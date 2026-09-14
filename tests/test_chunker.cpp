#include <gtest/gtest.h>

#include <algorithm>
#include <random>
#include <set>
#include <vector>

#include "chunker.h"
#include "hasher.h"

namespace {

std::vector<uint8_t> pseudo_random_bytes(std::size_t n, uint32_t seed) {
    std::vector<uint8_t> data(n);
    std::mt19937 rng(seed);
    for (auto& b : data) b = static_cast<uint8_t>(rng() % 256);
    return data;
}

std::string hash_hex(const uint8_t* data, std::size_t len) {
    auto hasher = make_hasher(HashAlgo::SHA256);
    hasher->update(data, len);
    return hasher->finalize().to_hex();
}

} // namespace

TEST(Chunker, CoversAllBytesWithNoGapsOrOverlaps) {
    auto data = pseudo_random_bytes(200 * 1024, 1);
    auto ranges = chunk_data(data.data(), data.size());

    ASSERT_FALSE(ranges.empty());
    std::size_t expected_offset = 0;
    for (const auto& r : ranges) {
        EXPECT_EQ(r.offset, expected_offset);
        EXPECT_GT(r.length, 0u);
        expected_offset += r.length;
    }
    EXPECT_EQ(expected_offset, data.size());
}

TEST(Chunker, NonFinalChunksRespectMinAndMaxBounds) {
    ChunkerConfig cfg;
    auto data = pseudo_random_bytes(500 * 1024, 2);
    auto ranges = chunk_data(data.data(), data.size(), cfg);

    ASSERT_GT(ranges.size(), 1u) << "test fixture should produce multiple chunks";
    for (std::size_t i = 0; i + 1 < ranges.size(); ++i) {
        EXPECT_GE(ranges[i].length, cfg.min_size);
        EXPECT_LE(ranges[i].length, cfg.max_size);
    }
    // The final chunk is whatever's left and may be shorter than min_size.
    EXPECT_LE(ranges.back().length, cfg.max_size);
}

TEST(Chunker, DeterministicForTheSameInput) {
    auto data = pseudo_random_bytes(100 * 1024, 3);
    auto a = chunk_data(data.data(), data.size());
    auto b = chunk_data(data.data(), data.size());

    ASSERT_EQ(a.size(), b.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        EXPECT_EQ(a[i].offset, b[i].offset);
        EXPECT_EQ(a[i].length, b[i].length);
    }
}

TEST(Chunker, SmallInputBecomesASingleChunk) {
    auto data = pseudo_random_bytes(100, 4);
    auto ranges = chunk_data(data.data(), data.size());

    ASSERT_EQ(ranges.size(), 1u);
    EXPECT_EQ(ranges[0].offset, 0u);
    EXPECT_EQ(ranges[0].length, data.size());
}

TEST(Chunker, EmptyInputProducesNoChunks) {
    std::vector<uint8_t> empty;
    auto ranges = chunk_data(empty.data(), empty.size());
    EXPECT_TRUE(ranges.empty());
}

// The actual point of content-defined chunking: editing the middle of a
// large blob should leave most chunks -- identified by their content hash,
// not their position -- unchanged, so they dedup against what was already
// stored.
TEST(Chunker, EditingTheMiddleOnlyPerturbsNearbyChunks) {
    auto original = pseudo_random_bytes(200 * 1024, 5);

    auto modified = original;
    std::vector<uint8_t> insertion = pseudo_random_bytes(37, 999);
    modified.insert(modified.begin() + static_cast<long>(modified.size() / 2), insertion.begin(), insertion.end());

    auto original_ranges = chunk_data(original.data(), original.size());
    auto modified_ranges = chunk_data(modified.data(), modified.size());

    std::set<std::string> original_hashes;
    for (const auto& r : original_ranges) {
        original_hashes.insert(hash_hex(original.data() + r.offset, r.length));
    }

    std::set<std::string> modified_hashes;
    for (const auto& r : modified_ranges) {
        modified_hashes.insert(hash_hex(modified.data() + r.offset, r.length));
    }

    std::size_t shared = 0;
    for (const auto& h : modified_hashes) {
        if (original_hashes.count(h)) ++shared;
    }

    ASSERT_GT(original_hashes.size(), 4u) << "test fixture should produce several chunks";
    EXPECT_GT(shared, original_hashes.size() / 2)
        << "most chunks should survive an edit to a small region of the content";
}
