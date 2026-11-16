#pragma once

// Tiny shared helpers for the engine's line-based text formats (manifest,
// chunk list, inclusion proof, repo.conf). Deliberately not a
// serialization framework: each format keeps its own dispatch logic;
// these only remove the repeated low-level parsing.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Splits "key=value" at the first '=' (the value may itself contain '=').
// Returns nullopt if the line has no '='. The views point into `line`.
std::optional<std::pair<std::string_view, std::string_view>> split_key_value(std::string_view line);

// Strict unsigned integer parse: the whole input must be digits in the
// given base -- no whitespace, sign, or trailing characters, and no
// overflow. Stricter than std::stoull (which accepts " +12abc" as 12, and
// "-1" as 2^64-1), which is safe because these formats only ever parse
// what this engine wrote.
std::optional<uint64_t> parse_u64(std::string_view text, int base = 10);

// Lowercase hex encoding of arbitrary bytes.
std::string to_hex(const uint8_t* data, std::size_t len);

// Strict inverse of to_hex: lowercase hex only, even length, exactly
// `expected_len` bytes. Anything else returns nullopt.
std::optional<std::vector<uint8_t>> from_hex(std::string_view hex, std::size_t expected_len);
