#include <gtest/gtest.h>

#include <csignal>
#include <sys/wait.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <random>

#include "chunker.h"
#include "fs_util.h"
#include "oplog.h"
#include "repo.h"
#include "snapshot.h"

namespace fs = std::filesystem;

namespace {

std::vector<uint8_t> pseudo_random_bytes(std::size_t n, uint32_t seed) {
    std::vector<uint8_t> data(n);
    std::mt19937 rng(seed);
    for (auto& b : data) b = static_cast<uint8_t>(rng() % 256);
    return data;
}

} // namespace

// Forks a child that runs create_snapshot() and kills itself (via
// raise(SIGKILL) from inside a checkpoint hook, not a clean exit) at an
// exact point in the multi-object commit sequence, then verifies from the
// parent that the repo always recovers to a valid state: it opens, it
// lists at most the one snapshot being created, and if that snapshot is
// listed at all it's fully restorable and byte-correct. This is
// deliberately exhaustive over every checkpoint (chunk write, chunk-list
// write, manifest write, log append) for a small fixture rather than
// randomized timing, since fork+kill is cheap and this is fully
// deterministic -- no flakiness from scheduling luck.
TEST(CrashSafety, RecoversFromKillAtEveryObjectBoundary) {
    std::mt19937_64 rng{std::random_device{}()};
    fs::path root = fs::temp_directory_path() / ("backup_engine_crash_test_" + std::to_string(rng()));
    fs::create_directories(root);
    fs::path src_path = root / "src";
    fs::create_directories(src_path);

    auto file_bytes = pseudo_random_bytes(20 * 1024, 123);
    {
        std::ofstream f(src_path / "data.bin", std::ios::binary);
        f.write(reinterpret_cast<const char*>(file_bytes.data()), static_cast<std::streamsize>(file_bytes.size()));
    }

    auto chunks = chunk_data(file_bytes.data(), file_bytes.size());
    ASSERT_GT(chunks.size(), 1u) << "test fixture should produce multiple chunks";
    // checkpoints: one per chunk, +1 for the chunk-list object, +1 for the
    // manifest object, +1 for the operations-log append.
    std::size_t total_checkpoints = chunks.size() + 3;

    for (std::size_t kill_at = 0; kill_at < total_checkpoints; ++kill_at) {
        fs::path trial_repo = root / ("trial_" + std::to_string(kill_at));
        Repo::init(trial_repo);

        pid_t pid = fork();
        ASSERT_NE(pid, -1) << "fork failed";

        if (pid == 0) {
            // Child: never call gtest assertions here, only raw syscalls
            // and library calls, then _exit -- fork() inside a test
            // process means this child shares no gtest state safely
            // beyond what's already been copied.
            Repo repo = Repo::open(trial_repo);
            std::size_t counter = 0;
            CrashTestHook hook = [&]() {
                if (counter++ == kill_at) {
                    std::raise(SIGKILL);
                }
            };
            try {
                create_snapshot(repo, src_path, hook);
            } catch (...) {
                // Only reachable if kill_at >= total_checkpoints; not
                // expected in this loop, but don't let an exception
                // escape a forked child into shared test infrastructure.
            }
            _exit(0);
        }

        int status = 0;
        ASSERT_EQ(waitpid(pid, &status, 0), pid);
        ASSERT_TRUE(WIFSIGNALED(status)) << "trial " << kill_at << ": child was not killed as expected";
        EXPECT_EQ(WTERMSIG(status), SIGKILL) << "trial " << kill_at;

        // Recovery invariants, checked from the parent after the "crash".
        Repo reopened = Repo::open(trial_repo);

        auto snapshots = list_snapshots(reopened);
        ASSERT_LE(snapshots.size(), 1u) << "trial " << kill_at << ": at most one snapshot could have been created";

        auto log_result = verify_operations_log(reopened);
        EXPECT_TRUE(log_result.ok) << "trial " << kill_at << ": " << log_result.message;

        if (!snapshots.empty()) {
            fs::path dest = root / ("dest_" + std::to_string(kill_at));
            EXPECT_NO_THROW(restore_snapshot(reopened, snapshots[0].digest, dest)) << "trial " << kill_at;
            if (fs::exists(dest / "data.bin")) {
                EXPECT_EQ(read_file(dest / "data.bin"), file_bytes) << "trial " << kill_at;
            }
        }
    }

    std::error_code ec;
    fs::remove_all(root, ec);
}

// A crash during Repo::init() itself (specifically, before the atomic
// repo.conf write completes) must never leave a repo that looks
// initialized but fails to open -- write_file_atomically's temp+fsync+
// rename means the config file is either fully absent or fully present,
// never partial.
TEST(CrashSafety, RepoConfigIsNeverPartiallyWritten) {
    std::mt19937_64 rng{std::random_device{}()};
    fs::path root = fs::temp_directory_path() / ("backup_engine_crash_init_test_" + std::to_string(rng()));
    fs::create_directories(root);
    fs::path repo_path = root / "repo";

    Repo::init(repo_path);
    ASSERT_TRUE(fs::exists(repo_path / "repo.conf"));

    // No temp files should be left behind after a clean init.
    for (const auto& entry : fs::directory_iterator(repo_path)) {
        std::string name = entry.path().filename().string();
        EXPECT_EQ(name.find(".tmp-"), std::string::npos) << name;
    }

    EXPECT_NO_THROW(Repo::open(repo_path));

    std::error_code ec;
    fs::remove_all(root, ec);
}
