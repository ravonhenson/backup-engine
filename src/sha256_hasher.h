#pragma once

#include "hasher.h"
#include "sha256.h"

class SHA256Hasher : public IHasher {
public:
    SHA256Hasher();

    void update(const uint8_t* data, std::size_t len) override;
    Digest finalize() override;

private:
    SHA256_CTX ctx_{};
};
