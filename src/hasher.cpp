#include "hasher.h"

#include <stdexcept>

#include "sha256_hasher.h"

std::unique_ptr<IHasher> make_hasher(HashAlgo algo) {
    switch (algo) {
        case HashAlgo::SHA256:
            return std::make_unique<SHA256Hasher>();
    }
    throw std::runtime_error("unknown hash algorithm");
}

Digest hash_bytes(HashAlgo algo, const uint8_t* data, std::size_t len) {
    auto hasher = make_hasher(algo);
    hasher->update(data, len);
    return hasher->finalize();
}

Digest hash_bytes(HashAlgo algo, const std::vector<uint8_t>& data) {
    return hash_bytes(algo, data.data(), data.size());
}
