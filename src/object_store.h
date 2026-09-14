#pragma once

#include <filesystem>
#include <vector>

#include "digest.h"

// A content-addressable object store. Objects are namespaced by algorithm
// on disk (objects/<algo>/<xx>/<rest-hex>) so digests from different
// algorithms can never collide on the same path, and the path itself
// tells a reader which hasher to use to verify the object.
class ObjectStore {
public:
    // Creates objects_root (and the algorithm subdirectory) if missing.
    ObjectStore(std::filesystem::path objects_root, HashAlgo write_algo);

    // Hashes data with the store's write algorithm and stores it if not
    // already present (content-addressing makes a duplicate write a no-op).
    Digest put(const std::vector<uint8_t>& data) const;

    // Reads the object back and re-verifies its hash before returning,
    // so every read also acts as a corruption/bit-rot check. Throws
    // std::runtime_error if the object is missing or fails verification.
    std::vector<uint8_t> get(const Digest& digest) const;

    bool exists(const Digest& digest) const;

    // Exposed because the on-disk layout is a documented part of the
    // format, not an implementation detail to hide.
    std::filesystem::path path_for(const Digest& digest) const;

private:
    std::filesystem::path objects_root_;
    HashAlgo write_algo_;
};
