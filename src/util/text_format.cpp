#include "util/text_format.h"

#include <charconv>

std::optional<std::pair<std::string_view, std::string_view>> split_key_value(std::string_view line) {
    auto eq = line.find('=');
    if (eq == std::string_view::npos) return std::nullopt;
    return std::make_pair(line.substr(0, eq), line.substr(eq + 1));
}

std::optional<uint64_t> parse_u64(std::string_view text, int base) {
    if (text.empty()) return std::nullopt;
    uint64_t value = 0;
    const char* end = text.data() + text.size();
    auto [ptr, ec] = std::from_chars(text.data(), end, value, base);
    if (ec != std::errc() || ptr != end) return std::nullopt;
    return value;
}

std::string to_hex(const uint8_t* data, std::size_t len) {
    static const char* kHexChars = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(kHexChars[data[i] >> 4]);
        out.push_back(kHexChars[data[i] & 0xF]);
    }
    return out;
}

std::optional<std::vector<uint8_t>> from_hex(std::string_view hex, std::size_t expected_len) {
    if (hex.size() != expected_len * 2) return std::nullopt;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1; // uppercase rejected: one canonical spelling per value
    };
    std::vector<uint8_t> out(expected_len);
    for (std::size_t i = 0; i < expected_len; ++i) {
        int hi = nibble(hex[2 * i]);
        int lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}
