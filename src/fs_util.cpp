#include "fs_util.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <stdexcept>
#include <system_error>

namespace fs = std::filesystem;

std::vector<uint8_t> read_file(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("cannot open file: " + path.string());
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

void write_file(const fs::path& path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("cannot open file for write: " + path.string());
    }
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

namespace {

std::string random_suffix() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    uint64_t v = rng();
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(v));
    return std::string(buf);
}

} // namespace

void write_file_atomically(const fs::path& path, const std::vector<uint8_t>& data) {
    fs::path dir = path.parent_path();
    std::error_code ec;
    fs::create_directories(dir, ec);

    fs::path tmp_path = dir / ("." + path.filename().string() + ".tmp-" + random_suffix());

    int fd = ::open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0444);
    if (fd < 0) {
        throw std::runtime_error("failed to create temp file: " + tmp_path.string() + ": " + std::strerror(errno));
    }

    const uint8_t* ptr = data.data();
    std::size_t remaining = data.size();
    while (remaining > 0) {
        ssize_t written = ::write(fd, ptr, remaining);
        if (written < 0) {
            if (errno == EINTR) continue;
            int err = errno;
            ::close(fd);
            fs::remove(tmp_path, ec);
            throw std::runtime_error(std::string("failed to write file: ") + std::strerror(err));
        }
        ptr += written;
        remaining -= static_cast<std::size_t>(written);
    }

    if (::fsync(fd) != 0) {
        int err = errno;
        ::close(fd);
        fs::remove(tmp_path, ec);
        throw std::runtime_error(std::string("fsync failed: ") + std::strerror(err));
    }
    ::close(fd);

    fs::rename(tmp_path, path, ec);
    if (ec) {
        fs::remove(tmp_path, ec);
        throw std::runtime_error("failed to commit file: " + ec.message());
    }
}
