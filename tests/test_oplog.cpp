#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include "log/oplog.h"
#include "storage/repo.h"
#include "test_util.h"

namespace fs = std::filesystem;

class OpLogTest : public ::testing::Test {
protected:
    void SetUp() override {
        root_ = tmp_.path();
        repo_path_ = root_ / "repo";
        Repo::init(repo_path_);
    }

    test_util::TempDir tmp_; // declared first: outlives every path below
    fs::path root_;
    fs::path repo_path_;
};

TEST_F(OpLogTest, EmptyLogVerifiesOk) {
    Repo repo = Repo::open(repo_path_);
    auto result = verify_operations_log(repo);
    EXPECT_TRUE(result.ok);
    EXPECT_EQ(result.entries_checked, 0u);
}

TEST_F(OpLogTest, AppendedEntriesHaveIncreasingSeqAndChainedHashes) {
    Repo repo = Repo::open(repo_path_);
    auto first = append_operation(repo, "test_event", "a");
    auto second = append_operation(repo, "test_event", "b");

    EXPECT_EQ(first.seq, 0u);
    EXPECT_EQ(second.seq, 1u);
    EXPECT_EQ(second.prev_hash, first.entry_hash);
    EXPECT_NE(first.entry_hash, second.entry_hash);
}

TEST_F(OpLogTest, ReadOperationsReturnsWhatWasAppended) {
    Repo repo = Repo::open(repo_path_);
    append_operation(repo, "snapshot_created", "sha256:aaaa");
    append_operation(repo, "snapshot_created", "sha256:bbbb");

    auto entries = read_operations(repo);
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(entries[0].event_data, "sha256:aaaa");
    EXPECT_EQ(entries[1].event_data, "sha256:bbbb");
}

TEST_F(OpLogTest, VerifyPassesForAnUntamperedChain) {
    Repo repo = Repo::open(repo_path_);
    for (int i = 0; i < 5; ++i) {
        append_operation(repo, "test_event", "value" + std::to_string(i));
    }

    auto result = verify_operations_log(repo);
    EXPECT_TRUE(result.ok);
    EXPECT_EQ(result.entries_checked, 5u);
    EXPECT_FALSE(result.first_bad_seq.has_value());
}

// The realistic threat model: an attacker (or a ransomware operator's
// tooling) edits an old entry through the normal file format but doesn't
// know to -- or can't easily -- regenerate every entry_hash after it.
TEST_F(OpLogTest, VerifyDetectsAnEditedOldEntry) {
    Repo repo = Repo::open(repo_path_);
    for (int i = 0; i < 4; ++i) {
        append_operation(repo, "snapshot_created", "sha256:" + std::string(64, static_cast<char>('a' + i)));
    }

    fs::path log_path = repo_path_ / "operations.log";
    std::ifstream in(log_path);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) lines.push_back(line);
    in.close();

    ASSERT_GE(lines.size(), 2u);
    // Tamper with entry 0's event_data in place, leaving its stored
    // entry_hash (and everything after it) untouched -- exactly what
    // hand-editing the file without recomputing the chain looks like.
    auto pos = lines[0].find("sha256:");
    ASSERT_NE(pos, std::string::npos);
    lines[0].replace(pos, 71, "sha256:" + std::string(64, 'f')); // "sha256:" + 64 hex chars = 71

    // The log is written read-only at rest (Layer 5); restore write
    // access before tampering with it directly, same as append_operation
    // does internally.
    fs::permissions(log_path, fs::perms::owner_write, fs::perm_options::add);
    std::ofstream out(log_path, std::ios::trunc);
    for (const auto& l : lines) out << l << "\n";
    out.close();

    auto result = verify_operations_log(repo);
    EXPECT_FALSE(result.ok);
    ASSERT_TRUE(result.first_bad_seq.has_value());
    EXPECT_EQ(*result.first_bad_seq, 0u);
}

TEST_F(OpLogTest, VerifyDetectsAReorderedEntry) {
    Repo repo = Repo::open(repo_path_);
    append_operation(repo, "test_event", "a");
    append_operation(repo, "test_event", "b");
    append_operation(repo, "test_event", "c");

    fs::path log_path = repo_path_ / "operations.log";
    std::ifstream in(log_path);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) lines.push_back(line);
    in.close();

    ASSERT_EQ(lines.size(), 3u);
    std::swap(lines[1], lines[2]);

    fs::permissions(log_path, fs::perms::owner_write, fs::perm_options::add);
    std::ofstream out(log_path, std::ios::trunc);
    for (const auto& l : lines) out << l << "\n";
    out.close();

    auto result = verify_operations_log(repo);
    EXPECT_FALSE(result.ok);
    // The entry now in the second position is the original seq=2 entry
    // (its own stored seq field is unchanged by the swap); its prev_hash
    // no longer matches the actual preceding entry's hash.
    ASSERT_TRUE(result.first_bad_seq.has_value());
    EXPECT_EQ(*result.first_bad_seq, 2u);
}

// Each field is stored as one space-separated token, so anything that
// can't round-trip through that format must be rejected up front --
// and rejected without writing anything to the log.
TEST_F(OpLogTest, RejectsFieldsThatCannotRoundTrip) {
    Repo repo = Repo::open(repo_path_);
    append_operation(repo, "test_event", "ok");

    const std::string bad_values[] = {"", "has space", "has\nnewline", "has\ttab", std::string("nul\0x", 5)};
    for (const auto& bad : bad_values) {
        EXPECT_THROW(append_operation(repo, "test_event", bad), std::invalid_argument);
        EXPECT_THROW(append_operation(repo, bad, "ok"), std::invalid_argument);
    }

    auto entries = read_operations(repo);
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_TRUE(verify_operations_log(repo).ok);
}

// The kind of structured value future events (retention policy,
// checkpoints) will use: a single token that round-trips exactly.
TEST_F(OpLogTest, StructuredTokenDataRoundTrips) {
    Repo repo = Repo::open(repo_path_);
    const std::string data = "min_age_days=2555,scope=all";
    append_operation(repo, "test_event", data);

    auto entries = read_operations(repo);
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].event_data, data);
}
