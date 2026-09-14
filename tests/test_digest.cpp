#include <gtest/gtest.h>

#include <vector>

#include "digest.h"
#include "hasher.h"

namespace {

Digest hash_bytes(const std::vector<uint8_t>& data) {
    auto hasher = make_hasher(HashAlgo::SHA256);
    hasher->update(data.data(), data.size());
    return hasher->finalize();
}

std::vector<uint8_t> to_bytes(std::string_view s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

} // namespace

TEST(Digest, KnownVectorEmptyString) {
    Digest d = hash_bytes({});
    EXPECT_EQ(d.to_hex(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Digest, KnownVectorAbc) {
    Digest d = hash_bytes(to_bytes("abc"));
    EXPECT_EQ(d.to_hex(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Digest, ToStringIncludesAlgoPrefix) {
    Digest d = hash_bytes(to_bytes("abc"));
    EXPECT_EQ(d.to_string(), "sha256:" + d.to_hex());
}

TEST(Digest, HexRoundTrip) {
    Digest original = hash_bytes(to_bytes("round trip me"));
    auto parsed = Digest::from_hex(HashAlgo::SHA256, original.to_hex());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, original);
}

TEST(Digest, ParseRoundTrip) {
    Digest original = hash_bytes(to_bytes("parse me"));
    auto parsed = Digest::parse(original.to_string());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, original);
}

TEST(Digest, ParseRejectsUnknownAlgo) {
    EXPECT_FALSE(Digest::parse("md5:deadbeef").has_value());
}

TEST(Digest, ParseRejectsMalformedHex) {
    EXPECT_FALSE(Digest::parse("sha256:not-hex").has_value());
}

TEST(Digest, DifferentContentProducesDifferentDigest) {
    Digest a = hash_bytes(to_bytes("hello"));
    Digest b = hash_bytes(to_bytes("hellp"));
    EXPECT_NE(a, b);
}
