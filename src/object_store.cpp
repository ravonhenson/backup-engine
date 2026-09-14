#include "object_store.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <stdexcept>
#include <system_error>

#include "hasher.h"

namespace fs = std::filesystem;

namespace {

std::string random_suffix() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    uint64_t v = rng();
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(v));
    return std::string(buf);
}

} // namespace

ObjectStore::ObjectStore(fs::path objects_root, HashAlgo write_algo)
    : objects_root_(std::move(objects_root)), write_algo_(write_algo) {
    std::error_code ec;
    fs::create_directories(objects_root_, ec);
}

fs::path ObjectStore::path_for(const Digest& digest) const {
    std::string hex = digest.to_hex();
    fs::path dir = objects_root_ / digest.algo_name() / hex.substr(0, 2);
    return dir / hex.substr(2);
}

PutResult ObjectStore::put(const std::vector<uint8_t>& data) const {
    auto hasher = make_hasher(write_algo_);
    hasher->update(data.data(), data.size());
    Digest digest = hasher->finalize();

    fs::path final_path = path_for(digest);
    if (fs::exists(final_path)) {
        return {digest, false}; // content-addressing: identical content, nothing to write
    }

    fs::path dir = final_path.parent_path();
    std::error_code ec;
    fs::create_directories(dir, ec);

    fs::path tmp_path = dir / ("." + final_path.filename().string() + ".tmp-" + random_suffix());

    int fd = ::open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0444);
    if (fd < 0) {
        throw std::runtime_error("failed to create temp file: " + tmp_path.string() + ": " + std::strerror(errno));
    }

    const uint8_t* ptr = data.data();
    size_t remaining = data.size();
    while (remaining > 0) {
        ssize_t written = ::write(fd, ptr, remaining);
        if (written < 0) {
            if (errno == EINTR) continue;
            int err = errno;
            ::close(fd);
            fs::remove(tmp_path, ec);
            throw std::runtime_error(std::string("failed to write object: ") + std::strerror(err));
        }
        ptr += written;
        remaining -= static_cast<size_t>(written);
    }

    if (::fsync(fd) != 0) {
        int err = errno;
        ::close(fd);
        fs::remove(tmp_path, ec);
        throw std::runtime_error(std::string("fsync failed: ") + std::strerror(err));
    }
    ::close(fd);

    fs::rename(tmp_path, final_path, ec);
    if (ec) {
        // Another writer may have raced us to the same content-addressed
        // path; if the object exists now, that's a successful outcome.
        if (!fs::exists(final_path)) {
            fs::remove(tmp_path, ec);
            throw std::runtime_error("failed to commit object: " + ec.message());
        }
        fs::remove(tmp_path, ec);
    }

    return {digest, true};
}

std::vector<uint8_t> ObjectStore::get(const Digest& digest) const {
    fs::path p = path_for(digest);
    std::ifstream f(p, std::ios::binary);
    if (!f) {
        throw std::runtime_error("object not found: " + digest.to_string());
    }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    auto hasher = make_hasher(digest.algo);
    hasher->update(data.data(), data.size());
    Digest recomputed = hasher->finalize();
    if (recomputed != digest) {
        throw std::runtime_error("integrity check failed for object: " + digest.to_string());
    }
    return data;
}

bool ObjectStore::exists(const Digest& digest) const {
    return fs::exists(path_for(digest));
}
