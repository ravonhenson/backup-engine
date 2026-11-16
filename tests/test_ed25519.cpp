// Checks the vendored Monocypher Ed25519 implementation against the
// official RFC 8032 section 7.1 test vectors (TEST 1 and TEST 2), copied
// from https://www.rfc-editor.org/rfc/rfc8032.txt. Ed25519 signatures are
// deterministic, so a correct implementation must reproduce the exact
// public key and signature bytes.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "monocypher-ed25519.h"

namespace {

std::vector<uint8_t> unhex(const std::string& hex) {
    std::vector<uint8_t> out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

struct Vector {
    const char* name;
    const char* seed;       // RFC "SECRET KEY" (the 32-byte seed)
    const char* public_key;
    const char* message;
    const char* signature;
};

const Vector kVectors[] = {
    {"TEST 1",
     "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
    {"TEST 2",
     "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
     "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
};

} // namespace

TEST(Ed25519, MatchesRfc8032TestVectors) {
    for (const auto& v : kVectors) {
        SCOPED_TRACE(v.name);
        auto seed = unhex(v.seed);
        auto expected_public = unhex(v.public_key);
        auto message = unhex(v.message);
        auto expected_signature = unhex(v.signature);
        ASSERT_EQ(seed.size(), 32u);
        ASSERT_EQ(expected_signature.size(), 64u);

        std::array<uint8_t, 64> secret_key{};
        std::array<uint8_t, 32> public_key{};
        crypto_ed25519_key_pair(secret_key.data(), public_key.data(), seed.data()); // wipes `seed`
        EXPECT_EQ(std::vector<uint8_t>(public_key.begin(), public_key.end()), expected_public);

        std::array<uint8_t, 64> signature{};
        crypto_ed25519_sign(signature.data(), secret_key.data(), message.data(), message.size());
        EXPECT_EQ(std::vector<uint8_t>(signature.begin(), signature.end()), expected_signature);

        EXPECT_EQ(crypto_ed25519_check(expected_signature.data(), public_key.data(), message.data(), message.size()),
                  0);
    }
}

TEST(Ed25519, RejectsTamperedMessageOrSignature) {
    const auto& v = kVectors[1];
    auto public_key = unhex(v.public_key);
    auto message = unhex(v.message);
    auto signature = unhex(v.signature);

    auto bad_message = message;
    bad_message[0] ^= 0x01;
    EXPECT_NE(crypto_ed25519_check(signature.data(), public_key.data(), bad_message.data(), bad_message.size()), 0);

    auto bad_signature = signature;
    bad_signature[10] ^= 0x01;
    EXPECT_NE(crypto_ed25519_check(bad_signature.data(), public_key.data(), message.data(), message.size()), 0);

    auto wrong_key = unhex(kVectors[0].public_key);
    EXPECT_NE(crypto_ed25519_check(signature.data(), wrong_key.data(), message.data(), message.size()), 0);
}
