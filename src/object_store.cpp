#include "object_store.h"

#include <fstream>
#include <stdexcept>
#include <system_error>

#include "errors.h"
#include "fs_util.h"
#include "hasher.h"

namespace fs = std::filesystem;

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

PutResult ObjectStore::put(const uint8_t* data, std::size_t len) const {
    Digest digest = hash_bytes(write_algo_, data, len);

    fs::path final_path = path_for(digest);
    if (fs::exists(final_path)) {
        return {digest, false}; // content-addressing: identical content, nothing to write
    }

    // Temp file -> fsync -> rename -> fsync the shard directory (creating
    // it, and syncing its parent, if this is the shard's first object).
    try {
        write_file_atomically(final_path, data, len);
    } catch (const std::exception&) {
        // Another writer may have committed the same content-addressed
        // object concurrently. rename() is atomic, so if the path exists
        // now it holds a complete object with identical content.
        if (fs::exists(final_path)) return {digest, false};
        throw;
    }
    return {digest, true};
}

PutResult ObjectStore::put(const std::vector<uint8_t>& data) const {
    return put(data.data(), data.size());
}

std::vector<uint8_t> ObjectStore::get(const Digest& digest) const {
    fs::path p = path_for(digest);
    std::ifstream f(p, std::ios::binary);
    if (!f) {
        // Only report "not found" when that's actually what happened -- a
        // present-but-unreadable object (e.g. permissions) is a different
        // problem and shouldn't be misdiagnosed as missing.
        std::error_code ec;
        if (!fs::exists(p, ec)) throw ObjectNotFoundError("object not found: " + digest.to_string());
        throw std::runtime_error("cannot read object " + digest.to_string() + " at " + p.string());
    }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    // A short read also lands here: truncated data can't match the hash.
    if (hash_bytes(digest.algo, data) != digest) {
        throw IntegrityError("integrity check failed for object: " + digest.to_string());
    }
    return data;
}

bool ObjectStore::exists(const Digest& digest) const {
    return fs::exists(path_for(digest));
}
