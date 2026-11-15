// Characterization tests: these pin down *existing* behavior -- exact
// on-disk byte formats, hash outputs, and catalog semantics -- so that
// internal refactors can't silently change them. If one of these fails,
// either the refactor has a bug or it's an intentional format change that
// needs to be made deliberately (and will invalidate existing repos'
// digests).
//
// Expected hash values were computed independently with Python's hashlib,
// not by running this codebase, so they also check the hashing itself.

#include <gtest/gtest.h>

#include <signal.h>
#include <sys/resource.h>

#include <fstream>
#include <string>

#include "chunk_list.h"
#include "fs_util.h"
#include "hasher.h"
#include "manifest.h"
#include "merkle.h"
#include "oplog.h"
#include "repo.h"
#include "snapshot.h"
#include "test_util.h"

namespace fs = std::filesystem;
using test_util::TempDir;
using test_util::to_bytes;

namespace {

Digest digest_of_repeated(const std::string& byte_hex) {
    std::string hex;
    for (int i = 0; i < 32; ++i) hex += byte_hex;
    return *Digest::from_hex(HashAlgo::SHA256, hex);
}

std::string as_string(const std::vector<uint8_t>& v) {
    return std::string(v.begin(), v.end());
}

const std::string kZero = "sha256:" + std::string(64, '0');
const std::string kAB = "sha256:" + [] { std::string s; for (int i = 0; i < 32; ++i) s += "ab"; return s; }();
const std::string kCD = "sha256:" + [] { std::string s; for (int i = 0; i < 32; ++i) s += "cd"; return s; }();
const std::string kEF = "sha256:" + [] { std::string s; for (int i = 0; i < 32; ++i) s += "ef"; return s; }();

} // namespace

TEST(Characterization, ManifestSerializationIsByteStable) {
    Manifest m;
    m.created_at = 1700000000;
    m.source_root = "/src root";
    m.merkle_root = digest_of_repeated("ab");
    m.entries.push_back({true, 0755, 0, Digest{}, "."});
    m.entries.push_back({false, 0644, 5, digest_of_repeated("cd"), "dir/a file.txt"});
    m.entries.push_back({true, 0700, 0, Digest{}, "dir"});

    const std::string expected = "format_version=2\n"
                                 "created_at=1700000000\n"
                                 "source_root=/src root\n"
                                 "merkle_root=" + kAB + "\n"
                                 "D 755 .\n"
                                 "F 644 5 " + kCD + " dir/a file.txt\n"
                                 "D 700 dir\n";
    EXPECT_EQ(as_string(m.serialize()), expected);

    auto parsed = Manifest::deserialize(to_bytes(expected));
    ASSERT_TRUE(parsed);
    EXPECT_EQ(as_string(parsed->serialize()), expected);
}

TEST(Characterization, ChunkListSerializationIsByteStable) {
    ChunkList list;
    list.total_size = 10;
    list.chunks.push_back({digest_of_repeated("cd"), 4});
    list.chunks.push_back({digest_of_repeated("ef"), 6});

    const std::string expected = "format_version=1\n"
                                 "total_size=10\n"
                                 "chunk " + kCD + " 4\n"
                                 "chunk " + kEF + " 6\n";
    EXPECT_EQ(as_string(list.serialize()), expected);

    auto parsed = ChunkList::deserialize(to_bytes(expected));
    ASSERT_TRUE(parsed);
    EXPECT_EQ(as_string(parsed->serialize()), expected);
}

TEST(Characterization, ProofSerializationIsByteStable) {
    MerkleInclusionProof proof;
    proof.root = digest_of_repeated("ab");
    proof.leaf = digest_of_repeated("cd");
    proof.leaf_index = 2;
    proof.leaf_count = 5;
    proof.path = {digest_of_repeated("ef")};

    const std::string expected = "format_version=1\n"
                                 "root=" + kAB + "\n"
                                 "leaf=" + kCD + "\n"
                                 "leaf_index=2\n"
                                 "leaf_count=5\n"
                                 "path " + kEF + "\n";
    EXPECT_EQ(as_string(proof.serialize()), expected);

    auto parsed = MerkleInclusionProof::deserialize(to_bytes(expected));
    ASSERT_TRUE(parsed);
    EXPECT_EQ(as_string(parsed->serialize()), expected);
}

// RFC 6962 roots over leaves sha256("a"), sha256("b"), ... for every
// count 0..5, covering the empty tree, a single leaf, powers of two, and
// non-powers of two.
TEST(Characterization, MerkleRootsMatchIndependentImplementation) {
    const char* expected_roots[] = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "a23bd5b06da9048238a65b3f1d9d0b9e15fae3dde262688e6489aa4c763d1820",
        "ad5ca6cddc0b27c6a83e332bf28011769236e6c6a1f786ebf7b5267b37a5bd22",
        "cac3d448d4e20a2ad5eae1f500e63c2a7f9217cd14572ba7fd22e26dc1ec2648",
        "3baac34fdbf4f2297a37c0613822d0c48efdcd6602ca7a4f48ceb31339ffb3d5",
        "4dc1abc938a0141a3c7cd1fed88948c35c4452e7e8aff9b1503eb5100a2c77b3",
    };
    const std::string letters = "abcde";

    std::vector<Digest> leaves;
    for (std::size_t n = 0; n <= letters.size(); ++n) {
        EXPECT_EQ(merkle_root(HashAlgo::SHA256, leaves).to_hex(), expected_roots[n]) << "n=" << n;
        for (std::size_t i = 0; i < leaves.size(); ++i) {
            auto path = merkle_path(HashAlgo::SHA256, leaves, i);
            EXPECT_TRUE(merkle_verify_inclusion(HashAlgo::SHA256, leaves[i], i, leaves.size(), path,
                                                merkle_root(HashAlgo::SHA256, leaves)))
                << "n=" << n << " i=" << i;
        }
        if (n < letters.size()) {
            auto hasher = make_hasher(HashAlgo::SHA256);
            auto c = static_cast<uint8_t>(letters[n]);
            hasher->update(&c, 1);
            leaves.push_back(hasher->finalize());
        }
    }
}

// A hand-written log whose entry hashes were computed independently: pins
// both the canonical hashing input and the on-disk line format.
TEST(Characterization, OperationsLogHashesAreStable) {
    TempDir tmp;
    Repo repo = Repo::init(tmp.path() / "repo");

    const std::string e0 = "sha256:dbb0d567013f00420c7dd25695a75e491c69f8640418c21384e1ce7480a99186";
    const std::string e1 = "sha256:cfbfb64693e1c777a9da454eee3fef96ae0bfd76c0e8e0ad631e8734cacff7a0";
    {
        std::ofstream log(repo.root() / "operations.log", std::ios::binary);
        log << "0 1700000000 snapshot_created " << kAB << " " << kZero << " " << e0 << "\n";
        log << "1 1700000001 snapshot_deleted " << kAB << " " << e0 << " " << e1 << "\n";
    }

    VerifyLogResult result = verify_operations_log(repo);
    EXPECT_TRUE(result.ok) << result.message;
    EXPECT_EQ(result.entries_checked, 2u);

    // And the next real append chains onto the hand-written head.
    OperationEntry next = append_operation(repo, "snapshot_created", kCD);
    EXPECT_EQ(next.seq, 2u);
    EXPECT_EQ(next.prev_hash.to_string(), e1);
    EXPECT_TRUE(verify_operations_log(repo).ok);
}

// Deletion is permanent: a digest that was tombstoned stays deleted even
// if a later snapshot_created event for the same digest appears (possible
// when identical content is backed up again within the same second, since
// created_at has one-second resolution).
TEST(Characterization, DeletionIsPermanentEvenIfDigestIsRecreated) {
    TempDir tmp;
    fs::path src = tmp.path() / "src";
    fs::create_directories(src);
    std::ofstream(src / "f.txt") << "content";

    Repo repo = Repo::init(tmp.path() / "repo");
    Digest snap = create_snapshot(repo, src).digest;
    delete_snapshot(repo, snap);
    append_operation(repo, "snapshot_created", snap.to_string());

    EXPECT_TRUE(list_snapshots(repo).empty());
    EXPECT_THROW(restore_snapshot(repo, snap, tmp.path() / "dest"), std::runtime_error);
    EXPECT_THROW(delete_snapshot(repo, snap), std::runtime_error);
}

// write_file must report a failed/short write rather than silently
// leaving a truncated file (restore uses it for every restored file).
// RLIMIT_FSIZE with SIGXFSZ ignored makes writes past the limit fail with
// EFBIG, portably on macOS and Linux.
TEST(Characterization, WriteFileReportsShortWrite) {
    TempDir tmp;

    struct rlimit old_limit{};
    ASSERT_EQ(getrlimit(RLIMIT_FSIZE, &old_limit), 0);
    auto old_handler = signal(SIGXFSZ, SIG_IGN);

    struct rlimit small_limit = old_limit;
    small_limit.rlim_cur = 4096;
    ASSERT_EQ(setrlimit(RLIMIT_FSIZE, &small_limit), 0);

    bool threw = false;
    try {
        write_file(tmp.path() / "big.bin", std::vector<uint8_t>(64 * 1024, 0x5a));
    } catch (const std::runtime_error&) {
        threw = true;
    }

    setrlimit(RLIMIT_FSIZE, &old_limit);
    signal(SIGXFSZ, old_handler);

    EXPECT_TRUE(threw);
}
