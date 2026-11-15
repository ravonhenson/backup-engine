#include "text_format.h"

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
