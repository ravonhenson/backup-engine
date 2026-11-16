#include "crypto/signing.h"

#include <unistd.h>
#ifdef __APPLE__
#include <sys/random.h> // getentropy
#endif

#include <cerrno>
#include <cstring>
#include <stdexcept>

#include "util/fs_util.h"
#include "monocypher-ed25519.h"
#include "monocypher.h"
#include "util/text_format.h"

namespace fs = std::filesystem;

namespace {

constexpr std::string_view kPublicHeader = "backup-engine ed25519 public key v1";
constexpr std::string_view kSecretHeader = "backup-engine ed25519 secret key v1";
constexpr std::string_view kKeyIdPrefix = "ed25519:";

// Parses "<header>\n<field>=<hex>\n" into exactly N bytes. Canonical form
// only: the caller re-serializes and compares.
template <std::size_t N>
std::optional<std::array<uint8_t, N>> parse_key_file(std::string_view text, std::string_view header,
                                                     std::string_view field) {
    auto nl = text.find('\n');
    if (nl == std::string_view::npos || text.substr(0, nl) != header) return std::nullopt;
    std::string_view rest = text.substr(nl + 1);
    if (rest.empty() || rest.back() != '\n') return std::nullopt;
    auto kv = split_key_value(rest.substr(0, rest.size() - 1));
    if (!kv || kv->first != field) return std::nullopt;
    auto bytes = from_hex(kv->second, N);
    if (!bytes) return std::nullopt;

    std::array<uint8_t, N> out{};
    std::copy(bytes->begin(), bytes->end(), out.begin());
    crypto_wipe(bytes->data(), bytes->size());
    return out;
}

} // namespace

// --- PublicKey ----------------------------------------------------------------

std::string PublicKey::key_id() const {
    return std::string(kKeyIdPrefix) + to_hex(bytes.data(), bytes.size());
}

std::optional<PublicKey> PublicKey::from_key_id(std::string_view key_id) {
    if (key_id.substr(0, kKeyIdPrefix.size()) != kKeyIdPrefix) return std::nullopt;
    auto raw = from_hex(key_id.substr(kKeyIdPrefix.size()), 32);
    if (!raw) return std::nullopt;
    PublicKey k;
    std::copy(raw->begin(), raw->end(), k.bytes.begin());
    return k;
}

std::string PublicKey::serialize() const {
    return std::string(kPublicHeader) + "\npublic_key=" + to_hex(bytes.data(), bytes.size()) + "\n";
}

std::optional<PublicKey> PublicKey::parse(std::string_view text) {
    auto raw = parse_key_file<32>(text, kPublicHeader, "public_key");
    if (!raw) return std::nullopt;
    PublicKey k;
    k.bytes = *raw;
    if (k.serialize() != text) return std::nullopt;
    return k;
}

// --- SecretKey ----------------------------------------------------------------

SecretKey::~SecretKey() {
    crypto_wipe(seed_.data(), seed_.size());
}

SecretKey SecretKey::generate() {
    SecretKey k;
    if (::getentropy(k.seed_.data(), k.seed_.size()) != 0) {
        throw std::runtime_error(std::string("getentropy failed: ") + std::strerror(errno));
    }
    return k;
}

std::string SecretKey::serialize() const {
    return std::string(kSecretHeader) + "\nseed=" + to_hex(seed_.data(), seed_.size()) + "\n";
}

std::optional<SecretKey> SecretKey::parse(std::string_view text) {
    auto raw = parse_key_file<32>(text, kSecretHeader, "seed");
    if (!raw) return std::nullopt;
    SecretKey k;
    k.seed_ = *raw;
    crypto_wipe(raw->data(), raw->size());
    if (k.serialize() != text) return std::nullopt;
    return k;
}

PublicKey SecretKey::public_key() const {
    std::array<uint8_t, 32> seed = seed_; // crypto_ed25519_key_pair wipes its seed argument
    std::array<uint8_t, 64> signing_key{};
    PublicKey pk;
    crypto_ed25519_key_pair(signing_key.data(), pk.bytes.data(), seed.data());
    crypto_wipe(signing_key.data(), signing_key.size());
    return pk;
}

Ed25519Signature SecretKey::sign(std::string_view message) const {
    std::array<uint8_t, 32> seed = seed_;
    std::array<uint8_t, 64> signing_key{};
    std::array<uint8_t, 32> unused_public{};
    crypto_ed25519_key_pair(signing_key.data(), unused_public.data(), seed.data());

    Ed25519Signature sig{};
    crypto_ed25519_sign(sig.data(), signing_key.data(), reinterpret_cast<const uint8_t*>(message.data()),
                        message.size());
    crypto_wipe(signing_key.data(), signing_key.size());
    return sig;
}

// --- free functions -----------------------------------------------------------

bool verify_signature(const PublicKey& key, std::string_view message, const Ed25519Signature& signature) {
    return crypto_ed25519_check(signature.data(), key.bytes.data(),
                                reinterpret_cast<const uint8_t*>(message.data()), message.size()) == 0;
}

void write_key_pair(const SecretKey& secret, const fs::path& secret_path, const fs::path& public_path) {
    std::error_code ec;
    if (fs::exists(secret_path, ec)) throw std::runtime_error("refusing to overwrite " + secret_path.string());
    if (fs::exists(public_path, ec)) throw std::runtime_error("refusing to overwrite " + public_path.string());

    // Secret first: never leave a public key whose secret was never saved.
    std::string secret_text = secret.serialize();
    write_file_atomically(secret_path, reinterpret_cast<const uint8_t*>(secret_text.data()), secret_text.size(),
                          fs::perms::owner_read);
    crypto_wipe(secret_text.data(), secret_text.size());

    std::string public_text = secret.public_key().serialize();
    write_file_atomically(public_path, reinterpret_cast<const uint8_t*>(public_text.data()), public_text.size());
}
