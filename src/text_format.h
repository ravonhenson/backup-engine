#pragma once

// Tiny shared helpers for the engine's line-based text formats (manifest,
// chunk list, inclusion proof, repo.conf). Deliberately not a
// serialization framework: each format keeps its own dispatch logic;
// these only remove the repeated low-level parsing.

#include <cstdint>
#include <optional>
#include <string_view>
#include <utility>

// Splits "key=value" at the first '=' (the value may itself contain '=').
// Returns nullopt if the line has no '='. The views point into `line`.
std::optional<std::pair<std::string_view, std::string_view>> split_key_value(std::string_view line);

// Strict unsigned integer parse: the whole input must be digits in the
// given base -- no whitespace, sign, or trailing characters, and no
// overflow. Stricter than std::stoull (which accepts " +12abc" as 12, and
// "-1" as 2^64-1), which is safe because these formats only ever parse
// what this engine wrote.
std::optional<uint64_t> parse_u64(std::string_view text, int base = 10);
