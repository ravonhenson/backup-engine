#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <vector>

#include "digest.h"

// Result of a put(): the object's digest, and whether this call actually
// wrote new bytes or the content already existed (content-addressing
// makes a duplicate write a no-op). The latter is what lets a caller
// report dedup statistics without maintaining a separate index.
struct PutResult {
    Digest digest;
    bool newly_written;
};

// A content-addressable object store. Objects are namespaced by algorithm
// on disk (objects/<algo>/<xx>/<rest-hex>) so digests from different
// algorithms can never collide on the same path, and the path itself
// tells a reader which hasher to use to verify the object.
class ObjectStore {
public:
    // Creates objects_root (and the algorithm subdirectory) if missing.
    ObjectStore(std::filesystem::path objects_root, HashAlgo write_algo);

    // Hashes data with the store's write algorithm and stores it if not
    // already present. Durable once it returns: the object is fsync'd and
    // so is the directory entry naming it.
    PutResult put(const uint8_t* data, std::size_t len) const;
    PutResult put(const std::vector<uint8_t>& data) const;

    // Reads the object back and re-verifies its hash before returning,
    // so every read also acts as a corruption/bit-rot check. Throws
    // ObjectNotFoundError if it's missing, IntegrityError if it fails
    // verification (see errors.h), std::runtime_error if it can't be read.
    std::vector<uint8_t> get(const Digest& digest) const;

    bool exists(const Digest& digest) const;

    // Exposed because the on-disk layout is a documented part of the
    // format, not an implementation detail to hide.
    std::filesystem::path path_for(const Digest& digest) const;

private:
    std::filesystem::path objects_root_;
    HashAlgo write_algo_;
};
