#include <gtest/gtest.h>

#include "manifest.h"

namespace {

Digest make_digest(uint8_t fill_byte) {
    Digest d;
    d.algo = HashAlgo::SHA256;
    d.length = 32;
    d.bytes.fill(fill_byte);
    return d;
}

} // namespace

TEST(Manifest, SerializeDeserializeRoundTrip) {
    Manifest m;
    m.created_at = 1700000000;
    m.source_root = "/tmp/example";
    m.merkle_root = make_digest(0xCD);

    ManifestEntry root;
    root.is_directory = true;
    root.mode = 0755;
    root.relative_path = ".";
    m.entries.push_back(root);

    ManifestEntry subdir;
    subdir.is_directory = true;
    subdir.mode = 0700;
    subdir.relative_path = "sub dir with spaces";
    m.entries.push_back(subdir);

    ManifestEntry file;
    file.is_directory = false;
    file.mode = 0644;
    file.size = 42;
    file.digest = make_digest(0xAB);
    file.relative_path = "sub dir with spaces/file.txt";
    m.entries.push_back(file);

    auto serialized = m.serialize();
    auto parsed = Manifest::deserialize(serialized);
    ASSERT_TRUE(parsed.has_value());

    EXPECT_EQ(parsed->created_at, m.created_at);
    EXPECT_EQ(parsed->source_root, m.source_root);
    EXPECT_EQ(parsed->merkle_root, m.merkle_root);
    ASSERT_EQ(parsed->entries.size(), 3u);

    EXPECT_TRUE(parsed->entries[0].is_directory);
    EXPECT_EQ(parsed->entries[0].mode, 0755u);
    EXPECT_EQ(parsed->entries[0].relative_path, ".");

    EXPECT_TRUE(parsed->entries[1].is_directory);
    EXPECT_EQ(parsed->entries[1].relative_path, "sub dir with spaces");

    EXPECT_FALSE(parsed->entries[2].is_directory);
    EXPECT_EQ(parsed->entries[2].mode, 0644u);
    EXPECT_EQ(parsed->entries[2].size, 42u);
    EXPECT_EQ(parsed->entries[2].digest, file.digest);
    EXPECT_EQ(parsed->entries[2].relative_path, "sub dir with spaces/file.txt");
}

TEST(Manifest, DeserializeRejectsMissingFormatVersion) {
    std::string text = "created_at=1\nsource_root=/x\n";
    std::vector<uint8_t> data(text.begin(), text.end());
    EXPECT_FALSE(Manifest::deserialize(data).has_value());
}

TEST(Manifest, DeserializeRejectsUnknownFormatVersion) {
    std::string text = "format_version=999\ncreated_at=1\nsource_root=/x\n";
    std::vector<uint8_t> data(text.begin(), text.end());
    EXPECT_FALSE(Manifest::deserialize(data).has_value());
}

TEST(Manifest, DeserializeRejectsMissingMerkleRoot) {
    std::string text = "format_version=2\ncreated_at=1\nsource_root=/x\n";
    std::vector<uint8_t> data(text.begin(), text.end());
    EXPECT_FALSE(Manifest::deserialize(data).has_value());
}

TEST(Manifest, EmptyManifestRoundTrips) {
    Manifest m;
    m.created_at = 5;
    m.source_root = "/empty";
    m.merkle_root = make_digest(0x00);
    auto parsed = Manifest::deserialize(m.serialize());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->created_at, 5u);
    EXPECT_EQ(parsed->merkle_root, m.merkle_root);
    EXPECT_TRUE(parsed->entries.empty());
}
