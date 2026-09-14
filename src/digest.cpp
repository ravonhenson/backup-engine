#include "digest.h"

#include <cstdio>

namespace {

int hex_digit_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

} // namespace

std::string Digest::algo_name() const {
    switch (algo) {
        case HashAlgo::SHA256:
            return "sha256";
    }
    return "unknown";
}

std::string Digest::to_hex() const {
    static const char* kHexChars = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(length) * 2);
    for (uint8_t i = 0; i < length; ++i) {
        out.push_back(kHexChars[(bytes[i] >> 4) & 0xF]);
        out.push_back(kHexChars[bytes[i] & 0xF]);
    }
    return out;
}

std::string Digest::to_string() const {
    return algo_name() + ":" + to_hex();
}

std::optional<HashAlgo> Digest::algo_from_name(std::string_view name) {
    if (name == "sha256") return HashAlgo::SHA256;
    return std::nullopt;
}

std::optional<Digest> Digest::from_hex(HashAlgo algo, std::string_view hex) {
    if (hex.size() % 2 != 0) return std::nullopt;
    std::size_t byte_len = hex.size() / 2;
    if (byte_len == 0 || byte_len > kMaxDigestBytes) return std::nullopt;

    Digest d;
    d.algo = algo;
    d.length = static_cast<uint8_t>(byte_len);
    for (std::size_t i = 0; i < byte_len; ++i) {
        int hi = hex_digit_value(hex[2 * i]);
        int lo = hex_digit_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        d.bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return d;
}

std::optional<Digest> Digest::parse(std::string_view text) {
    auto colon = text.find(':');
    if (colon == std::string_view::npos) return std::nullopt;
    auto algo = algo_from_name(text.substr(0, colon));
    if (!algo) return std::nullopt;
    return from_hex(*algo, text.substr(colon + 1));
}

bool Digest::operator==(const Digest& other) const {
    if (algo != other.algo || length != other.length) return false;
    for (uint8_t i = 0; i < length; ++i) {
        if (bytes[i] != other.bytes[i]) return false;
    }
    return true;
}

std::size_t std::hash<Digest>::operator()(const Digest& d) const noexcept {
    // FNV-1a over the algorithm tag and digest bytes actually in use.
    std::size_t h = 1469598103934665603ULL;
    auto mix = [&h](uint8_t byte) {
        h ^= byte;
        h *= 1099511628211ULL;
    };
    mix(static_cast<uint8_t>(d.algo));
    for (uint8_t i = 0; i < d.length; ++i) mix(d.bytes[i]);
    return h;
}
