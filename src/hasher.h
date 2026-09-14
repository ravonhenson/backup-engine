#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include "digest.h"

// Strategy interface: each concrete algorithm gets its own IHasher
// implementation, selected by HashAlgo so a second algorithm is a new
// subclass plus a registry entry, with no change to callers.
struct IHasher {
    virtual void update(const uint8_t* data, std::size_t len) = 0;
    virtual Digest finalize() = 0;
    virtual ~IHasher() = default;
};

std::unique_ptr<IHasher> make_hasher(HashAlgo algo);
