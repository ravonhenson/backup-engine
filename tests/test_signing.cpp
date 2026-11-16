#include <gtest/gtest.h>

#include <filesystem>

#include "util/fs_util.h"
#include "crypto/signing.h"
#include "test_util.h"

namespace fs = std::filesystem;
using test_util::TempDir;

namespace {

// RFC 8032 section 7.1, TEST 2 (same vector as test_ed25519.cpp, here
// pushed through this project's wrapper and key-file format).
const std::string kSeedHex = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const std::string kPublicHex = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
const std::string kSignatureHex = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                                  "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

const std::string kSecretFile = "backup-engine ed25519 secret key v1\nseed=" + kSeedHex + "\n";
const std::string kPublicFile = "backup-engine ed25519 public key v1\npublic_key=" + kPublicHex + "\n";

std::string sig_hex(const Ed25519Signature& s) {
    std::string out;
    static const char* h = "0123456789abcdef";
    for (auto b : s) {
        out.push_back(h[b >> 4]);
        out.push_back(h[b & 0xF]);
    }
    return out;
}

} // namespace

TEST(Signing, KeyFilesAndSignatureMatchRfc8032) {
    auto secret = SecretKey::parse(kSecretFile);
    ASSERT_TRUE(secret);
    EXPECT_EQ(secret->serialize(), kSecretFile);

    PublicKey pub = secret->public_key();
    EXPECT_EQ(pub.serialize(), kPublicFile);
    EXPECT_EQ(pub.key_id(), "ed25519:" + kPublicHex);

    Ed25519Signature sig = secret->sign(std::string(1, '\x72')); // TEST 2 message: one byte 0x72
    EXPECT_EQ(sig_hex(sig), kSignatureHex);
}

TEST(Signing, SignAndVerifyRoundTrip) {
    SecretKey secret = SecretKey::generate();
    PublicKey pub = secret.public_key();
    const std::string message = "backup-engine checkpoint v1\nlog_size=1\n";

    Ed25519Signature sig = secret.sign(message);
    EXPECT_TRUE(verify_signature(pub, message, sig));

    EXPECT_FALSE(verify_signature(pub, message + "x", sig));
    Ed25519Signature bad = sig;
    bad[0] ^= 0x01;
    EXPECT_FALSE(verify_signature(pub, message, bad));
    EXPECT_FALSE(verify_signature(SecretKey::generate().public_key(), message, sig));
}

TEST(Signing, GeneratedKeysAreDistinct) {
    EXPECT_NE(SecretKey::generate().public_key(), SecretKey::generate().public_key());
}

TEST(Signing, KeyIdRoundTrips) {
    PublicKey pub = SecretKey::generate().public_key();
    auto back = PublicKey::from_key_id(pub.key_id());
    ASSERT_TRUE(back);
    EXPECT_EQ(*back, pub);

    EXPECT_FALSE(PublicKey::from_key_id("ed25519:abcd"));
    EXPECT_FALSE(PublicKey::from_key_id("sha256:" + kPublicHex));
}

TEST(Signing, KeyFilesAcceptOnlyCanonicalForm) {
    std::string upper = kPublicHex;
    for (auto& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    const std::string bad_public[] = {
        "",
        kPublicFile.substr(0, kPublicFile.size() - 1),                        // no trailing newline
        kPublicFile + "\n",                                                   // extra line
        "backup-engine ed25519 public key v1\npublic_key=" + upper + "\n",    // uppercase hex
        "backup-engine ed25519 public key v1\npublic_key=" + kPublicHex.substr(2) + "\n", // short
        "backup-engine ed25519 secret key v1\npublic_key=" + kPublicHex + "\n",           // wrong header
    };
    for (const auto& text : bad_public) EXPECT_FALSE(PublicKey::parse(text)) << text;

    // A secret key file is not a public key file, and vice versa.
    EXPECT_FALSE(PublicKey::parse(kSecretFile));
    EXPECT_FALSE(SecretKey::parse(kPublicFile));
}

TEST(Signing, WriteKeyPairUsesSafePermissionsAndRefusesOverwrite) {
    TempDir tmp;
    fs::path secret_path = tmp.path() / "signing.key";
    fs::path public_path = tmp.path() / "signing.pub";
    SecretKey secret = SecretKey::generate();

    write_key_pair(secret, secret_path, public_path);
    EXPECT_EQ(fs::status(secret_path).permissions() & fs::perms::all, fs::perms::owner_read);
    EXPECT_EQ(fs::status(public_path).permissions() & fs::perms::all,
              fs::perms::owner_read | fs::perms::group_read | fs::perms::others_read);

    auto read_back = read_file(secret_path);
    auto parsed = SecretKey::parse(std::string(read_back.begin(), read_back.end()));
    ASSERT_TRUE(parsed);
    EXPECT_EQ(parsed->public_key(), secret.public_key());

    auto pub_bytes = read_file(public_path);
    auto pub = PublicKey::parse(std::string(pub_bytes.begin(), pub_bytes.end()));
    ASSERT_TRUE(pub);
    EXPECT_EQ(*pub, secret.public_key());

    SecretKey other = SecretKey::generate();
    EXPECT_THROW(write_key_pair(other, secret_path, tmp.path() / "new.pub"), std::runtime_error);
    EXPECT_THROW(write_key_pair(other, tmp.path() / "new.key", public_path), std::runtime_error);
    EXPECT_FALSE(fs::exists(tmp.path() / "new.key"));
}
