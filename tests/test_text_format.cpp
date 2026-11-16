#include <gtest/gtest.h>

#include "util/text_format.h"

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

TEST(TextFormat, HexRoundTripsAndIsStrict) {
    const uint8_t bytes[] = {0x00, 0x7f, 0xab, 0xff};
    EXPECT_EQ(to_hex(bytes, 4), "007fabff");

    auto back = from_hex("007fabff", 4);
    ASSERT_TRUE(back);
    EXPECT_EQ(*back, std::vector<uint8_t>(bytes, bytes + 4));

    EXPECT_FALSE(from_hex("007FABFF", 4)); // uppercase
    EXPECT_FALSE(from_hex("007fab", 4));   // too short
    EXPECT_FALSE(from_hex("007fabff00", 4)); // too long
    EXPECT_FALSE(from_hex("007fabfg", 4)); // not hex
}
