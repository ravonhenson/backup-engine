#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <random>

#include "chunk_list.h"
#include "fs_util.h"
#include "manifest.h"
#include "merkle.h"
#include "oplog.h"
#include "repo.h"
#include "snapshot.h"

namespace fs = std::filesystem;

namespace {

void write_text(const fs::path& p, const std::string& content) {
    fs::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary);
    f << content;
}

std::vector<uint8_t> to_bytes(std::string_view s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

} // namespace

class SnapshotTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::mt19937_64 rng{std::random_device{}()};
        root_ = fs::temp_directory_path() / ("backup_engine_snapshot_test_" + std::to_string(rng()));
        fs::create_directories(root_);
        repo_path_ = root_ / "repo";
        src_path_ = root_ / "src";
        dest_path_ = root_ / "dest";
        Repo::init(repo_path_);
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(root_, ec);
    }

    fs::path root_;
    fs::path repo_path_;
    fs::path src_path_;
    fs::path dest_path_;
};

TEST_F(SnapshotTest, BackupAndRestoreRoundTrip) {
    write_text(src_path_ / "hello.txt", "hello");
    write_text(src_path_ / "subdir" / "nested.txt", "nested content");
    fs::create_directories(src_path_ / "empty_dir");

    Repo repo = Repo::open(repo_path_);
    Digest snapshot = create_snapshot(repo, src_path_).digest;
    restore_snapshot(repo, snapshot, dest_path_);

    EXPECT_EQ(read_file(dest_path_ / "hello.txt"), to_bytes("hello"));
    EXPECT_EQ(read_file(dest_path_ / "subdir" / "nested.txt"), to_bytes("nested content"));
    EXPECT_TRUE(fs::is_directory(dest_path_ / "empty_dir"));
}

TEST_F(SnapshotTest, RestoredPermissionsMatchSource) {
    write_text(src_path_ / "file.txt", "content");
    fs::permissions(src_path_ / "file.txt", fs::perms::owner_read | fs::perms::owner_write,
                     fs::perm_options::replace);

    Repo repo = Repo::open(repo_path_);
    Digest snapshot = create_snapshot(repo, src_path_).digest;
    restore_snapshot(repo, snapshot, dest_path_);

    auto expected = fs::status(src_path_ / "file.txt").permissions();
    auto actual = fs::status(dest_path_ / "file.txt").permissions();
    EXPECT_EQ(expected, actual);
}

TEST_F(SnapshotTest, EmptySourceDirectoryRestoresAsEmptyDestination) {
    fs::create_directories(src_path_);

    Repo repo = Repo::open(repo_path_);
    Digest snapshot = create_snapshot(repo, src_path_).digest;
    restore_snapshot(repo, snapshot, dest_path_);

    EXPECT_TRUE(fs::is_directory(dest_path_));
    EXPECT_TRUE(fs::is_empty(dest_path_));
}

TEST_F(SnapshotTest, SymlinkIsRejectedRatherThanSilentlySkipped) {
    write_text(src_path_ / "real.txt", "real content");
    std::error_code ec;
    fs::create_symlink(src_path_ / "real.txt", src_path_ / "link.txt", ec);
    if (ec) GTEST_SKIP() << "symlinks not supported in this test environment";

    Repo repo = Repo::open(repo_path_);
    EXPECT_THROW(create_snapshot(repo, src_path_), std::runtime_error);
}

TEST_F(SnapshotTest, ListSnapshotsReturnsCreatedSnapshotsInOrder) {
    write_text(src_path_ / "a.txt", "a");
    Repo repo = Repo::open(repo_path_);
    Digest first = create_snapshot(repo, src_path_).digest;

    write_text(src_path_ / "b.txt", "b");
    Digest second = create_snapshot(repo, src_path_).digest;

    auto snapshots = list_snapshots(repo);
    ASSERT_EQ(snapshots.size(), 2u);
    EXPECT_EQ(snapshots[0].digest, first);
    EXPECT_EQ(snapshots[1].digest, second);
}

TEST_F(SnapshotTest, DuplicateFileContentIsDeduplicatedByExistence) {
    write_text(src_path_ / "a.txt", "same content");
    write_text(src_path_ / "b.txt", "same content");

    Repo repo = Repo::open(repo_path_);
    SnapshotResult result = create_snapshot(repo, src_path_);
    restore_snapshot(repo, result.digest, dest_path_);

    EXPECT_EQ(read_file(dest_path_ / "a.txt"), to_bytes("same content"));
    EXPECT_EQ(read_file(dest_path_ / "b.txt"), to_bytes("same content"));
    // Two files with identical content produce identical chunk lists, so
    // the second file's chunk (and its chunk-list object) should be pure
    // dedup: no new chunks written for it.
    EXPECT_LT(result.stats.new_chunks, result.stats.total_chunks);
}

TEST_F(SnapshotTest, EditingAFileDeduplicatesMostOfItAcrossSnapshots) {
    std::string base(50 * 1024, '\0');
    std::mt19937 rng(42);
    for (auto& c : base) c = static_cast<char>(rng() % 256);
    write_text(src_path_ / "big.bin", base);

    Repo repo = Repo::open(repo_path_);
    SnapshotResult first = create_snapshot(repo, src_path_);
    ASSERT_GT(first.stats.total_chunks, 1u) << "test fixture should produce multiple chunks";

    // Insert a few bytes in the middle -- everything before and (once the
    // rolling hash resyncs) after the edit should keep its old chunk
    // boundaries and therefore dedup against the first snapshot.
    std::string edited = base;
    edited.insert(base.size() / 2, "INSERTED BYTES HERE");
    write_text(src_path_ / "big.bin", edited);

    SnapshotResult second = create_snapshot(repo, src_path_);
    restore_snapshot(repo, second.digest, dest_path_);

    EXPECT_EQ(read_file(dest_path_ / "big.bin"), to_bytes(edited));
    EXPECT_LT(second.stats.new_chunks, second.stats.total_chunks / 2)
        << "most chunks should be deduplicated against the first snapshot";
}

TEST_F(SnapshotTest, OperationsLogVerifiesAfterNormalUse) {
    write_text(src_path_ / "a.txt", "a");
    Repo repo = Repo::open(repo_path_);
    create_snapshot(repo, src_path_);
    write_text(src_path_ / "b.txt", "b");
    create_snapshot(repo, src_path_);

    auto result = verify_operations_log(repo);
    EXPECT_TRUE(result.ok);
    EXPECT_EQ(result.entries_checked, 2u);
}

// Confirms the deliberate detection-only design: a tampered operations
// log is caught by an explicit verify_operations_log() check, but does
// not itself block list_snapshots()/restore_snapshot() from continuing
// to serve snapshots that are otherwise perfectly valid in the object
// store -- a single corrupted catalog entry shouldn't become a denial of
// recovery.
TEST_F(SnapshotTest, TamperedLogIsDetectedButDoesNotBlockRestoreOfAnUnaffectedSnapshot) {
    write_text(src_path_ / "a.txt", "a");
    Repo repo = Repo::open(repo_path_);
    Digest snapshot = create_snapshot(repo, src_path_).digest;

    fs::path log_path = repo_path_ / "operations.log";
    std::ifstream in(log_path);
    std::string line;
    std::getline(in, line);
    in.close();

    // Flip one hex character of the recorded digest, in place, without
    // recomputing entry_hash -- corrupts the entry (breaks the chain)
    // without turning it into a deletion of this same snapshot.
    auto pos = line.find("sha256:");
    ASSERT_NE(pos, std::string::npos);
    std::size_t hex_start = pos + 7;
    ASSERT_LT(hex_start, line.size());
    line[hex_start] = (line[hex_start] == 'a') ? 'b' : 'a';

    // The log is written read-only at rest (Layer 5); restore write
    // access before tampering with it directly.
    fs::permissions(log_path, fs::perms::owner_write, fs::perm_options::add);
    std::ofstream out(log_path, std::ios::trunc);
    out << line << "\n";
    out.close();

    EXPECT_FALSE(verify_operations_log(repo).ok);

    // The snapshot itself is untouched in the object store, and the
    // tampered entry no longer even refers to this digest, so restoring
    // it by its real digest still works despite the known-tampered log.
    restore_snapshot(repo, snapshot, dest_path_);
    EXPECT_EQ(read_file(dest_path_ / "a.txt"), to_bytes("a"));
}

// A real, narrow consequence of the detection-only design (Layer 2.5):
// restore_snapshot's tombstone check reads the raw, unverified log, so
// tampering that flips a snapshot's own creation event into a fake
// deletion event (without recomputing entry_hash) makes that snapshot
// refuse to restore *before* anyone runs verify-log, not just after.
// Detection still happens -- verify-log fails -- but detection-only
// doesn't mean tampering has zero effect until detected.
TEST_F(SnapshotTest, TamperingASnapshotIntoLookingDeletedBlocksItsOwnRestoreBeforeDetection) {
    write_text(src_path_ / "a.txt", "a");
    Repo repo = Repo::open(repo_path_);
    Digest snapshot = create_snapshot(repo, src_path_).digest;

    fs::path log_path = repo_path_ / "operations.log";
    std::ifstream in(log_path);
    std::string line;
    std::getline(in, line);
    in.close();

    auto pos = line.find("snapshot_created");
    ASSERT_NE(pos, std::string::npos);
    fs::permissions(log_path, fs::perms::owner_write, fs::perm_options::add);
    std::ofstream out(log_path, std::ios::trunc);
    out << line.substr(0, pos) << "snapshot_deleted" << line.substr(pos + std::string("snapshot_created").size())
        << "\n";
    out.close();

    EXPECT_FALSE(verify_operations_log(repo).ok);
    EXPECT_THROW(restore_snapshot(repo, snapshot, dest_path_), std::runtime_error);
}

TEST_F(SnapshotTest, DeletedSnapshotDisappearsFromListingButOtherSnapshotsRemain) {
    write_text(src_path_ / "a.txt", "a");
    Repo repo = Repo::open(repo_path_);
    Digest first = create_snapshot(repo, src_path_).digest;

    write_text(src_path_ / "b.txt", "b");
    Digest second = create_snapshot(repo, src_path_).digest;

    delete_snapshot(repo, first);

    auto snapshots = list_snapshots(repo);
    ASSERT_EQ(snapshots.size(), 1u);
    EXPECT_EQ(snapshots[0].digest, second);
}

TEST_F(SnapshotTest, RestoreRefusesADeletedSnapshot) {
    write_text(src_path_ / "a.txt", "a");
    Repo repo = Repo::open(repo_path_);
    Digest snapshot = create_snapshot(repo, src_path_).digest;

    delete_snapshot(repo, snapshot);

    EXPECT_THROW(restore_snapshot(repo, snapshot, dest_path_), std::runtime_error);
}

TEST_F(SnapshotTest, DeletingASnapshotDoesNotPhysicallyRemoveItsObjects) {
    write_text(src_path_ / "a.txt", "a");
    Repo repo = Repo::open(repo_path_);
    Digest snapshot = create_snapshot(repo, src_path_).digest;

    delete_snapshot(repo, snapshot);

    // Deletion is a catalog tombstone, not physical removal -- unsafe
    // without a reachability/GC pass given chunk-level dedup.
    EXPECT_TRUE(repo.objects().exists(snapshot));
}

TEST_F(SnapshotTest, DeletingAnUnknownSnapshotThrows) {
    Repo repo = Repo::open(repo_path_);
    auto bogus = Digest::from_hex(HashAlgo::SHA256, std::string(64, 'a'));
    ASSERT_TRUE(bogus.has_value());
    EXPECT_THROW(delete_snapshot(repo, *bogus), std::runtime_error);
}

TEST_F(SnapshotTest, DeletingAnAlreadyDeletedSnapshotThrows) {
    write_text(src_path_ / "a.txt", "a");
    Repo repo = Repo::open(repo_path_);
    Digest snapshot = create_snapshot(repo, src_path_).digest;

    delete_snapshot(repo, snapshot);
    EXPECT_THROW(delete_snapshot(repo, snapshot), std::runtime_error);
}

TEST_F(SnapshotTest, VerifyLogStaysIntactAcrossCreateAndDeleteEvents) {
    write_text(src_path_ / "a.txt", "a");
    Repo repo = Repo::open(repo_path_);
    Digest snapshot = create_snapshot(repo, src_path_).digest;
    delete_snapshot(repo, snapshot);

    auto result = verify_operations_log(repo);
    EXPECT_TRUE(result.ok);
    EXPECT_EQ(result.entries_checked, 2u);
}

TEST_F(SnapshotTest, VerifySnapshotSucceedsForAFreshlyCreatedSnapshot) {
    write_text(src_path_ / "a.txt", "a");
    write_text(src_path_ / "subdir" / "b.txt", "b");
    Repo repo = Repo::open(repo_path_);
    SnapshotResult result = create_snapshot(repo, src_path_);

    auto verify = verify_snapshot(repo, result.digest);
    EXPECT_TRUE(verify.ok);
    EXPECT_EQ(verify.chunks_checked, result.stats.total_chunks);
}

TEST_F(SnapshotTest, VerifySnapshotFailsIfAChunkIsCorrupted) {
    std::string base(50 * 1024, '\0');
    std::mt19937 rng(7);
    for (auto& c : base) c = static_cast<char>(rng() % 256);
    write_text(src_path_ / "big.bin", base);

    Repo repo = Repo::open(repo_path_);
    SnapshotResult result = create_snapshot(repo, src_path_);
    ASSERT_GT(result.stats.total_chunks, 0u);

    // Corrupt an arbitrary stored chunk object directly on disk.
    fs::path objects_dir = repo_path_ / "objects" / "sha256";
    bool corrupted = false;
    for (const auto& shard : fs::directory_iterator(objects_dir)) {
        for (const auto& obj : fs::directory_iterator(shard.path())) {
            fs::permissions(obj.path(), fs::perms::owner_write, fs::perm_options::add);
            std::fstream f(obj.path(), std::ios::binary | std::ios::in | std::ios::out);
            f.seekp(0);
            f.put(static_cast<char>(0x00));
            f.close();
            corrupted = true;
            break;
        }
        if (corrupted) break;
    }
    ASSERT_TRUE(corrupted);

    auto verify = verify_snapshot(repo, result.digest);
    EXPECT_FALSE(verify.ok);
}

TEST_F(SnapshotTest, ProveAndVerifyChunkInclusionRoundTrip) {
    std::string base(50 * 1024, '\0');
    std::mt19937 rng(9);
    for (auto& c : base) c = static_cast<char>(rng() % 256);
    write_text(src_path_ / "big.bin", base);

    Repo repo = Repo::open(repo_path_);
    SnapshotResult result = create_snapshot(repo, src_path_);
    ASSERT_GT(result.stats.total_chunks, 1u) << "test fixture should produce multiple chunks";

    // Find a real chunk digest to prove inclusion of: read the manifest
    // and one file's chunk list directly via the object store.
    auto manifest = Manifest::deserialize(repo.objects().get(result.digest));
    ASSERT_TRUE(manifest.has_value());
    Digest file_chunk_list_digest;
    for (const auto& e : manifest->entries) {
        if (!e.is_directory) {
            file_chunk_list_digest = e.digest;
            break;
        }
    }
    auto chunk_list = ChunkList::deserialize(repo.objects().get(file_chunk_list_digest));
    ASSERT_TRUE(chunk_list.has_value());
    ASSERT_FALSE(chunk_list->chunks.empty());
    Digest target_chunk = chunk_list->chunks[0].digest;

    auto proof = prove_chunk_inclusion(repo, result.digest, target_chunk);
    ASSERT_TRUE(proof.has_value());
    EXPECT_EQ(proof->root, manifest->merkle_root);
    EXPECT_EQ(proof->leaf, target_chunk);

    // The whole point: this verification needs nothing but the proof
    // itself -- no Repo, no other chunk, no manifest re-fetch.
    EXPECT_TRUE(merkle_verify_inclusion(*proof));

    // And it round-trips through serialization, as it would if written
    // to a file and handed to someone else.
    auto reparsed = MerkleInclusionProof::deserialize(proof->serialize());
    ASSERT_TRUE(reparsed.has_value());
    EXPECT_TRUE(merkle_verify_inclusion(*reparsed));
}

TEST_F(SnapshotTest, ProveChunkInclusionReturnsNulloptForAnUnrelatedChunk) {
    write_text(src_path_ / "a.txt", "a");
    Repo repo = Repo::open(repo_path_);
    SnapshotResult result = create_snapshot(repo, src_path_);

    auto unrelated = Digest::from_hex(HashAlgo::SHA256, std::string(64, 'f'));
    ASSERT_TRUE(unrelated.has_value());
    auto proof = prove_chunk_inclusion(repo, result.digest, *unrelated);
    EXPECT_FALSE(proof.has_value());
}

// A tampered manifest is caught earlier than the Merkle root check: the
// manifest object's own content-addressing means get() throws on a
// corrupted manifest before verify_snapshot ever reaches the
// recompute-and-compare step. The root check only ever fires for a
// genuine internal inconsistency between creation-time and verify-time
// leaf gathering, not for on-disk tampering -- tampering is already
// Layer 1's job.
TEST_F(SnapshotTest, TamperingTheManifestIsCaughtByObjectStoreNotByTheRootCheck) {
    write_text(src_path_ / "a.txt", "a");
    Repo repo = Repo::open(repo_path_);
    SnapshotResult result = create_snapshot(repo, src_path_);

    fs::path manifest_path = repo.objects().path_for(result.digest);
    fs::permissions(manifest_path, fs::perms::owner_write, fs::perm_options::add);
    std::fstream f(manifest_path, std::ios::binary | std::ios::in | std::ios::out);
    f.seekp(0);
    f.put(static_cast<char>(0x00));
    f.close();

    auto verify = verify_snapshot(repo, result.digest);
    EXPECT_FALSE(verify.ok);
    EXPECT_EQ(verify.chunks_checked, 0u);
    EXPECT_NE(verify.message.find("failed to fetch manifest"), std::string::npos) << verify.message;
}
