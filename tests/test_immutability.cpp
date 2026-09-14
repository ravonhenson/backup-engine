#include <gtest/gtest.h>

#include <filesystem>
#include <random>

#include "oplog.h"
#include "repo.h"

namespace fs = std::filesystem;

namespace {

bool is_read_only(const fs::path& path) {
    auto perms = fs::status(path).permissions();
    return (perms & fs::perms::owner_write) == fs::perms::none;
}

} // namespace

class ImmutabilityTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::mt19937_64 rng{std::random_device{}()};
        root_ = fs::temp_directory_path() / ("backup_engine_immutability_test_" + std::to_string(rng()));
        repo_path_ = root_ / "repo";
        Repo::init(repo_path_);
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(root_, ec);
    }

    fs::path root_;
    fs::path repo_path_;
};

TEST_F(ImmutabilityTest, RepoConfigIsReadOnlyAfterInit) {
    EXPECT_TRUE(is_read_only(repo_path_ / "repo.conf"));
}

TEST_F(ImmutabilityTest, OperationsLogIsReadOnlyAtRestBetweenAppends) {
    Repo repo = Repo::open(repo_path_);

    append_operation(repo, "test_event", "a");
    EXPECT_TRUE(is_read_only(repo_path_ / "operations.log"));

    // A second append must still succeed -- the append path has to
    // temporarily restore write access rather than being permanently
    // locked out by the previous append's chmod.
    append_operation(repo, "test_event", "b");
    EXPECT_TRUE(is_read_only(repo_path_ / "operations.log"));

    auto entries = read_operations(repo);
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(entries[1].prev_hash, entries[0].entry_hash);
}
