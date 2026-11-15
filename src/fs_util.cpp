#include "fs_util.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <stdexcept>
#include <system_error>

namespace fs = std::filesystem;

namespace {

[[noreturn]] void throw_errno(const std::string& what, int err) {
    throw std::runtime_error(what + ": " + std::strerror(err));
}

std::string random_suffix() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(rng()));
    return std::string(buf);
}

// An empty parent_path() means "the current directory".
fs::path dir_or_cwd(const fs::path& dir) {
    return dir.empty() ? fs::path(".") : dir;
}

// Removes a temp file on scope exit unless dismissed after a successful
// commit, so every early-exit path in write_file_atomically cleans up
// without repeating the cleanup code.
class TempFileGuard {
public:
    explicit TempFileGuard(fs::path path) : path_(std::move(path)) {}
    ~TempFileGuard() {
        if (!dismissed_) {
            std::error_code ec;
            fs::remove(path_, ec);
        }
    }
    void dismiss() { dismissed_ = true; }

    TempFileGuard(const TempFileGuard&) = delete;
    TempFileGuard& operator=(const TempFileGuard&) = delete;

private:
    fs::path path_;
    bool dismissed_ = false;
};

} // namespace

// --- UniqueFd ---------------------------------------------------------------

UniqueFd::~UniqueFd() {
    if (fd_ >= 0) ::close(fd_);
}

UniqueFd::UniqueFd(UniqueFd&& other) noexcept : fd_(other.fd_) {
    other.fd_ = -1;
}

UniqueFd& UniqueFd::operator=(UniqueFd&& other) noexcept {
    if (this != &other) {
        if (fd_ >= 0) ::close(fd_);
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

void UniqueFd::close_or_throw(const std::string& what) {
    int fd = fd_;
    fd_ = -1; // never retry close(): the fd may already be reused after a failed close
    if (fd >= 0 && ::close(fd) != 0) throw_errno(what + ": close failed", errno);
}

// --- primitives -------------------------------------------------------------

void write_all(int fd, const uint8_t* data, std::size_t len, const std::string& what) {
    while (len > 0) {
        ssize_t written = ::write(fd, data, len);
        if (written < 0) {
            if (errno == EINTR) continue;
            throw_errno(what, errno);
        }
        data += written;
        len -= static_cast<std::size_t>(written);
    }
}

void sync_file(int fd, const std::string& what) {
    if (::fsync(fd) != 0) throw_errno(what + ": fsync failed", errno);
}

void sync_barrier(int fd, const std::string& what) {
#ifdef F_FULLFSYNC
    if (::fcntl(fd, F_FULLFSYNC) == 0) return;
    int err = errno;
    // Only a filesystem/device that doesn't implement F_FULLFSYNC (some
    // network and FUSE mounts) falls back to fsync; a real I/O error is
    // reported, never masked.
    if (err != ENOTSUP && err != EINVAL && err != ENOTTY) throw_errno(what + ": F_FULLFSYNC failed", err);
#endif
    sync_file(fd, what);
}

namespace {

UniqueFd open_for_sync(const fs::path& path) {
    UniqueFd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (!fd.valid()) throw_errno("failed to open for sync: " + path.string(), errno);
    return fd;
}

} // namespace

void sync_dir(const fs::path& dir) {
    fs::path d = dir_or_cwd(dir);
    sync_file(open_for_sync(d).get(), "directory " + d.string());
}

void sync_barrier_path(const fs::path& path) {
    fs::path p = dir_or_cwd(path);
    sync_barrier(open_for_sync(p).get(), p.string());
}

void create_directories_durably(const fs::path& dir) {
    if (dir.empty()) return;
    std::error_code ec;
    if (fs::is_directory(dir, ec)) return;

    create_directories_durably(dir.parent_path());
    if (::mkdir(dir.c_str(), 0755) != 0 && errno != EEXIST) {
        throw_errno("failed to create directory: " + dir.string(), errno);
    }
    sync_dir(dir.parent_path());
}

// --- file-level helpers -----------------------------------------------------

std::vector<uint8_t> read_file(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("cannot open file: " + path.string());
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

void write_file(const fs::path& path, const uint8_t* data, std::size_t len) {
    UniqueFd fd(::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666));
    if (!fd.valid()) throw_errno("cannot open file for write: " + path.string(), errno);
    write_all(fd.get(), data, len, "failed to write " + path.string());
    fd.close_or_throw("failed to write " + path.string());
}

void write_file(const fs::path& path, const std::vector<uint8_t>& data) {
    write_file(path, data.data(), data.size());
}

void write_file_atomically(const fs::path& path, const uint8_t* data, std::size_t len, fs::perms mode) {
    fs::path dir = path.parent_path();
    create_directories_durably(dir);

    fs::path tmp_path = dir / ("." + path.filename().string() + ".tmp-" + random_suffix());
    UniqueFd fd(::open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, static_cast<mode_t>(mode)));
    if (!fd.valid()) throw_errno("failed to create temp file: " + tmp_path.string(), errno);
    TempFileGuard guard(tmp_path);

    write_all(fd.get(), data, len, "failed to write " + path.string());
    sync_file(fd.get(), path.string());
    fd.close_or_throw(path.string());

    if (::rename(tmp_path.c_str(), path.c_str()) != 0) {
        throw_errno("failed to commit " + path.string(), errno);
    }
    guard.dismiss();
    sync_dir(dir);
}

void write_file_atomically(const fs::path& path, const std::vector<uint8_t>& data) {
    write_file_atomically(path, data.data(), data.size());
}

uint64_t now_unix_seconds() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
}
