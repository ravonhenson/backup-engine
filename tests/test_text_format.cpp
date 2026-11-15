#include <gtest/gtest.h>

#include "text_format.h"

TEST(TextFormat, SplitKeyValueSplitsAtFirstEquals) {
    auto kv = split_key_value("source_root=/a=b/c");
    ASSERT_TRUE(kv);
    EXPECT_EQ(kv->first, "source_root");
    EXPECT_EQ(kv->second, "/a=b/c");

    EXPECT_FALSE(split_key_value("no equals sign"));

    auto empty_value = split_key_value("key=");
    ASSERT_TRUE(empty_value);
    EXPECT_EQ(empty_value->second, "");
}

TEST(TextFormat, ParseU64AcceptsPlainDecimalAndOctal) {
    EXPECT_EQ(parse_u64("0"), 0u);
    EXPECT_EQ(parse_u64("1700000000"), 1700000000u);
    EXPECT_EQ(parse_u64("18446744073709551615"), UINT64_MAX);
    EXPECT_EQ(parse_u64("755", 8), 0755u);
}

// Stricter than std::stoull on purpose: these inputs were silently
// accepted (and some silently misread) by the old parsers.
TEST(TextFormat, ParseU64RejectsAnythingButExactDigits) {
    EXPECT_FALSE(parse_u64(""));
    EXPECT_FALSE(parse_u64(" 12"));
    EXPECT_FALSE(parse_u64("+12"));
    EXPECT_FALSE(parse_u64("-1"));                   // stoull would give 2^64-1
    EXPECT_FALSE(parse_u64("12abc"));                // stoull would give 12
    EXPECT_FALSE(parse_u64("18446744073709551616")); // overflow
    EXPECT_FALSE(parse_u64("8", 8));
}
