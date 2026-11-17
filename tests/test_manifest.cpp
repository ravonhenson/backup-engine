#include <gtest/gtest.h>

#include "crypto/merkle.h"
#include "snapshot/manifest.h"
#include "test_util.h"

using test_util::to_bytes;

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
    m.entries_root = manifest_entries_root(HashAlgo::SHA256, m.entries);

    auto serialized = m.serialize();
    auto parsed = Manifest::deserialize(serialized);
    ASSERT_TRUE(parsed.has_value());

    EXPECT_EQ(parsed->created_at, m.created_at);
    EXPECT_EQ(parsed->source_root, m.source_root);
    EXPECT_EQ(parsed->merkle_root, m.merkle_root);
    EXPECT_EQ(parsed->entries_root, m.entries_root);
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
    m.entries_root = manifest_entries_root(HashAlgo::SHA256, m.entries);
    auto parsed = Manifest::deserialize(m.serialize());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->created_at, 5u);
    EXPECT_EQ(parsed->merkle_root, m.merkle_root);
    EXPECT_TRUE(parsed->entries.empty());
}

// entries_root is required in v3 and not allowed in v2: a v2 manifest
// carrying one, or a v3 manifest missing one, is not something this
// engine ever wrote.
TEST(Manifest, EntriesRootPresenceMustMatchVersion) {
    const std::string root = "sha256:" + std::string(64, 'a');
    const std::string common = "created_at=1\nsource_root=/x\nmerkle_root=" + root + "\n";

    EXPECT_TRUE(Manifest::deserialize(to_bytes("format_version=2\n" + common)));
    EXPECT_TRUE(Manifest::deserialize(to_bytes("format_version=3\n" + common + "entries_root=" + root + "\n")));

    EXPECT_FALSE(Manifest::deserialize(to_bytes("format_version=3\n" + common)));
    EXPECT_FALSE(Manifest::deserialize(to_bytes("format_version=2\n" + common + "entries_root=" + root + "\n")));
    EXPECT_FALSE(Manifest::deserialize(to_bytes("format_version=4\n" + common + "entries_root=" + root + "\n")));
}

TEST(Manifest, SerializeRefusesUnsetRoots) {
    Manifest m;
    m.created_at = 1;
    m.source_root = "/x";
    EXPECT_THROW(m.serialize(), std::logic_error); // neither root set

    m.merkle_root = make_digest(0x01);
    EXPECT_THROW(m.serialize(), std::logic_error); // v3 without entries_root

    m.entries_root = manifest_entries_root(HashAlgo::SHA256, m.entries);
    EXPECT_NO_THROW(m.serialize());

    Manifest v2;
    v2.format_version = 2;
    v2.merkle_root = make_digest(0x01);
    EXPECT_NO_THROW(v2.serialize()); // v2 has no entries_root
}

// The intended use of entries_root: any single entry can be proven part of
// the manifest from its own line plus an O(log n) path, revealing no other
// entry.
TEST(Manifest, EveryEntryHasAnInclusionPathToEntriesRoot) {
    std::vector<ManifestEntry> entries;
    entries.push_back({true, 0755, 0, Digest{}, "."});
    for (int i = 0; i < 6; ++i) {
        entries.push_back({false, 0644, static_cast<uint64_t>(i), make_digest(static_cast<uint8_t>(i)),
                           "file " + std::to_string(i)});
    }
    Digest root = manifest_entries_root(HashAlgo::SHA256, entries);

    std::vector<Digest> leaves;
    for (const auto& e : entries) leaves.push_back(manifest_entry_leaf(HashAlgo::SHA256, e));
    for (std::size_t i = 0; i < entries.size(); ++i) {
        auto path = merkle_path(HashAlgo::SHA256, leaves, i);
        EXPECT_TRUE(merkle_verify_inclusion(HashAlgo::SHA256, leaves[i], i, entries.size(), path, root)) << i;
    }

    // A changed entry (here: a different size) no longer matches its slot.
    ManifestEntry altered = entries[3];
    altered.size += 1;
    EXPECT_FALSE(merkle_verify_inclusion(HashAlgo::SHA256, manifest_entry_leaf(HashAlgo::SHA256, altered), 3,
                                         entries.size(), merkle_path(HashAlgo::SHA256, leaves, 3), root));
}
