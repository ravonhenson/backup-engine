#pragma once

// Ed25519 (RFC 8032) keys and signatures, via the vendored Monocypher
// (third_party/monocypher). Used to sign checkpoint statements with a key
// that is kept off the repo host.

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

using Ed25519Signature = std::array<uint8_t, 64>;

struct PublicKey {
    std::array<uint8_t, 32> bytes{};

    // "ed25519:<64 lowercase hex>". The key itself, not a hash of it: at 32
    // bytes it's short enough, and it needs no extra hashing step to check.
    std::string key_id() const;
    static std::optional<PublicKey> from_key_id(std::string_view key_id);

    // Public key file:
    //   backup-engine ed25519 public key v1
    //   public_key=<64 lowercase hex>
    std::string serialize() const;
    static std::optional<PublicKey> parse(std::string_view text); // canonical form only

    bool operator==(const PublicKey& other) const { return bytes == other.bytes; }
    bool operator!=(const PublicKey& other) const { return !(*this == other); }
};

// Holds the 32-byte seed (RFC 8032's "secret key"); the 64-byte signing
// key is derived from it on each use and wiped immediately after. The
// seed is wiped on destruction.
//
// Limitation: serialize()/parse() pass the seed through std::string,
// which isn't wiped. Fine for a short-lived CLI process; a long-running
// signer would want a more careful buffer.
class SecretKey {
public:
    // A new random key from the OS's cryptographic RNG (getentropy).
    static SecretKey generate();

    // Secret key file:
    //   backup-engine ed25519 secret key v1
    //   seed=<64 lowercase hex>
    std::string serialize() const;
    static std::optional<SecretKey> parse(std::string_view text); // canonical form only

    PublicKey public_key() const;
    Ed25519Signature sign(std::string_view message) const;

    SecretKey(const SecretKey&) = default;
    SecretKey& operator=(const SecretKey&) = default;
    ~SecretKey();

private:
    SecretKey() = default;
    std::array<uint8_t, 32> seed_{};
};

// True only if `signature` is a valid Ed25519 signature of exactly
// `message` by `key`.
bool verify_signature(const PublicKey& key, std::string_view message, const Ed25519Signature& signature);

// Writes the key pair to two new files: the secret key read-only to its
// owner (0400), the public key world-readable (0444). Refuses to
// overwrite either file -- silently replacing a signing key would orphan
// every checkpoint it signed.
void write_key_pair(const SecretKey& secret, const std::filesystem::path& secret_path,
                    const std::filesystem::path& public_path);
