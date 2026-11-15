#pragma once

// Shared helpers for the unit tests. Header-only so it needs no CMake
// target of its own.

#include <cstdint>
#include <filesystem>
#include <random>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace test_util {

inline std::vector<uint8_t> to_bytes(std::string_view s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

// Deterministic for a given seed, so chunk boundaries in tests that use it
// are reproducible run to run.
inline std::vector<uint8_t> pseudo_random_bytes(std::size_t n, uint32_t seed) {
    std::vector<uint8_t> data(n);
    std::mt19937 rng(seed);
    for (auto& b : data) b = static_cast<uint8_t>(rng() % 256);
    return data;
}

// A uniquely named directory under the system temp dir, removed on
// destruction. Restores owner rwx on everything first: the engine
// deliberately produces read-only objects/logs and restores restrictive
// directory modes (e.g. 0500), and remove_all can't delete entries inside
// a directory it can't write to.
class TempDir {
public:
    explicit TempDir(const std::string& prefix = "backup_engine_test_") {
        std::mt19937_64 rng{std::random_device{}()};
        path_ = std::filesystem::temp_directory_path() / (prefix + std::to_string(rng()));
        std::filesystem::create_directories(path_);
    }

    ~TempDir() {
        namespace fs = std::filesystem;
        std::error_code ec;
        fs::permissions(path_, fs::perms::owner_all, fs::perm_options::add, ec);
        for (auto it = fs::recursive_directory_iterator(path_, ec); !ec && it != fs::recursive_directory_iterator();
             it.increment(ec)) {
            if (it->is_symlink(ec)) continue;
            fs::permissions(it->path(), fs::perms::owner_all, fs::perm_options::add, ec);
        }
        fs::remove_all(path_, ec);
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

} // namespace test_util
