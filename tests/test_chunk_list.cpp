#include <gtest/gtest.h>

#include "chunk_list.h"

namespace {

Digest make_digest(uint8_t fill_byte) {
    Digest d;
    d.algo = HashAlgo::SHA256;
    d.length = 32;
    d.bytes.fill(fill_byte);
    return d;
}

} // namespace

TEST(ChunkList, SerializeDeserializeRoundTrip) {
    ChunkList list;
    list.total_size = 100;
    list.chunks.push_back({make_digest(0x11), 40});
    list.chunks.push_back({make_digest(0x22), 60});

    auto parsed = ChunkList::deserialize(list.serialize());
    ASSERT_TRUE(parsed.has_value());

    EXPECT_EQ(parsed->total_size, 100u);
    ASSERT_EQ(parsed->chunks.size(), 2u);
    EXPECT_EQ(parsed->chunks[0].digest, list.chunks[0].digest);
    EXPECT_EQ(parsed->chunks[0].size, 40u);
    EXPECT_EQ(parsed->chunks[1].digest, list.chunks[1].digest);
    EXPECT_EQ(parsed->chunks[1].size, 60u);
}

TEST(ChunkList, EmptyChunkListRoundTrips) {
    ChunkList list;
    list.total_size = 0;
    auto parsed = ChunkList::deserialize(list.serialize());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->total_size, 0u);
    EXPECT_TRUE(parsed->chunks.empty());
}

TEST(ChunkList, DeserializeRejectsMissingFormatVersion) {
    std::string text = "total_size=1\n";
    std::vector<uint8_t> data(text.begin(), text.end());
    EXPECT_FALSE(ChunkList::deserialize(data).has_value());
}
