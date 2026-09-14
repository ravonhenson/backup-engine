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
