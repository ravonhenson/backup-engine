#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Durability model (used by every write path in the engine)
//
//   * Every file that must survive a crash is fsync'd, and so is the
//     directory that holds its name -- a rename or create isn't durable
//     until its parent directory is.
//   * On macOS, fsync only pushes data to the drive, not through the
//     drive's own write cache, so it does not order writes across a power
//     loss. sync_barrier() (F_FULLFSYNC) flushes the whole drive cache.
//     It's expensive (milliseconds), so it's used only at commit points --
//     right before and after the operations-log append that makes a
//     snapshot visible -- not per object. One barrier flushes everything
//     written before it, which is exactly the ordering the commit needs:
//     all chunks/manifest durable before the log entry referencing them.
//   * Elsewhere sync_barrier() is plain fsync, which already flushes the
//     device cache on Linux.
// ---------------------------------------------------------------------------

// Owns a POSIX file descriptor and closes it on destruction. Move-only.
// The destructor ignores close() errors (it can't throw); callers that
// haven't fsync'd and need to know a write actually succeeded -- some
// filesystems only report write errors at close -- call close_or_throw().
class UniqueFd {
public:
    UniqueFd() = default;
    explicit UniqueFd(int fd) : fd_(fd) {}
    ~UniqueFd();

    UniqueFd(UniqueFd&& other) noexcept;
    UniqueFd& operator=(UniqueFd&& other) noexcept;
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    int get() const { return fd_; }
    bool valid() const { return fd_ >= 0; }
    void close_or_throw(const std::string& what);

private:
    int fd_ = -1;
};

// Writes all `len` bytes, retrying on EINTR and partial writes. Throws
// std::runtime_error (prefixed with `what`) on failure.
void write_all(int fd, const uint8_t* data, std::size_t len, const std::string& what);

// fsync; throws on failure.
void sync_file(int fd, const std::string& what);

// F_FULLFSYNC on Apple (falling back to fsync only if the filesystem
// doesn't support it), fsync elsewhere. Throws on real I/O failure.
void sync_barrier(int fd, const std::string& what);

// fsyncs a directory, making creates/renames/unlinks inside it durable.
void sync_dir(const std::filesystem::path& dir);

// sync_barrier() through a descriptor opened on `path` (a file or a
// directory) -- for commit points that have no descriptor of their own.
void sync_barrier_path(const std::filesystem::path& path);

// Like create_directories, but fsyncs each newly created directory's
// parent so the new directory entries themselves survive a crash.
// No-op (and no syncing) if `dir` already exists.
void create_directories_durably(const std::filesystem::path& dir);

std::vector<uint8_t> read_file(const std::filesystem::path& path);

// Plain (non-fsync'd) write, for output files such as restored data or a
// proof file -- but every write and the final close are checked, so a
// failed or short write throws instead of leaving a silently truncated
// file behind.
void write_file(const std::filesystem::path& path, const uint8_t* data, std::size_t len);
void write_file(const std::filesystem::path& path, const std::vector<uint8_t>& data);

// Writes to a temp file in the same directory, fsyncs it, atomically
// renames it into place, then fsyncs the directory -- so the file is never
// observable half-written, and is durable once this returns. Creates the
// parent directory (durably) if needed. The temp file is removed on any
// failure. Used both for content-addressed objects and for small pieces of
// critical repo metadata like repo.conf.
void write_file_atomically(const std::filesystem::path& path, const uint8_t* data, std::size_t len,
                           std::filesystem::perms mode = std::filesystem::perms::owner_read |
                                                         std::filesystem::perms::group_read |
                                                         std::filesystem::perms::others_read);
void write_file_atomically(const std::filesystem::path& path, const std::vector<uint8_t>& data);

// The current time as whole seconds since the Unix epoch.
uint64_t now_unix_seconds();
