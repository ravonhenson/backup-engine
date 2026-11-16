#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

enum class HashAlgo : uint8_t {
    SHA256 = 1,
};

constexpr std::size_t kMaxDigestBytes = 32;

// A self-describing digest: the algorithm travels with the bytes, so a
// future second algorithm needs no change to how existing digests are
// stored, compared, or read back.
struct Digest {
    HashAlgo algo = HashAlgo::SHA256;
    uint8_t length = 0;
    std::array<uint8_t, kMaxDigestBytes> bytes{};

    std::string algo_name() const;
    std::string to_hex() const;
    std::string to_string() const; // "sha256:9f86d0..."

    static std::optional<HashAlgo> algo_from_name(std::string_view name);
    static std::optional<Digest> from_hex(HashAlgo algo, std::string_view hex);
    // Parses the "algo:hex" form produced by to_string().
    static std::optional<Digest> parse(std::string_view text);

    bool operator==(const Digest& other) const;
    bool operator!=(const Digest& other) const { return !(*this == other); }
};

namespace std {
template <>
struct hash<Digest> {
    std::size_t operator()(const Digest& d) const noexcept;
};
} // namespace std
