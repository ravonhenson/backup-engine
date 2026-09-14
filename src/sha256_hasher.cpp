#include "sha256_hasher.h"

SHA256Hasher::SHA256Hasher() {
    sha256_init(&ctx_);
}

void SHA256Hasher::update(const uint8_t* data, std::size_t len) {
    sha256_update(&ctx_, data, len);
}

Digest SHA256Hasher::finalize() {
    Digest d;
    d.algo = HashAlgo::SHA256;
    d.length = SHA256_BLOCK_SIZE;
    sha256_final(&ctx_, d.bytes.data());
    return d;
}
