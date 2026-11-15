#include <gtest/gtest.h>

#include <fcntl.h>
#include <unistd.h>

#include <filesystem>

#include "fs_util.h"
#include "test_util.h"

namespace fs = std::filesystem;
using test_util::TempDir;
using test_util::to_bytes;

namespace {

std::size_t count_entries(const fs::path& dir) {
    std::size_t n = 0;
    for ([[maybe_unused]] const auto& e : fs::directory_iterator(dir)) ++n;
    return n;
}

} // namespace

TEST(FsUtil, WriteFileAtomicallyCreatesReadOnlyFileAndParents) {
    TempDir tmp;
    fs::path target = tmp.path() / "a" / "b" / "file";
    write_file_atomically(target, to_bytes("payload"));

    EXPECT_EQ(read_file(target), to_bytes("payload"));
    auto perms = fs::status(target).permissions();
    EXPECT_EQ(perms & fs::perms::all, fs::perms::owner_read | fs::perms::group_read | fs::perms::others_read);
    EXPECT_EQ(count_entries(target.parent_path()), 1u); // no temp file left behind
}

// A failed commit (here: rename onto a non-empty directory) must throw
// and must not leave the temp file behind.
TEST(FsUtil, WriteFileAtomicallyCleansUpTempFileOnFailedCommit) {
    TempDir tmp;
    fs::path target = tmp.path() / "occupied";
    fs::create_directories(target / "child");

    EXPECT_THROW(write_file_atomically(target, to_bytes("payload")), std::runtime_error);
    EXPECT_EQ(count_entries(tmp.path()), 1u); // only "occupied" itself
    EXPECT_TRUE(fs::is_directory(target / "child"));
}

TEST(FsUtil, CreateDirectoriesDurablyIsIdempotent) {
    TempDir tmp;
    fs::path nested = tmp.path() / "x" / "y" / "z";
    create_directories_durably(nested);
    EXPECT_TRUE(fs::is_directory(nested));
    EXPECT_NO_THROW(create_directories_durably(nested));
}

TEST(FsUtil, WriteFileOverwritesAndRoundTrips) {
    TempDir tmp;
    fs::path p = tmp.path() / "out.bin";
    write_file(p, to_bytes("first, longer content"));
    write_file(p, to_bytes("second"));
    EXPECT_EQ(read_file(p), to_bytes("second"));
}

TEST(FsUtil, UniqueFdClosesOnDestructionAndTransfersOnMove) {
    TempDir tmp;
    fs::path p = tmp.path() / "f";
    int raw = ::open(p.c_str(), O_WRONLY | O_CREAT, 0644);
    ASSERT_GE(raw, 0);
    {
        UniqueFd a(raw);
        UniqueFd b(std::move(a));
        EXPECT_FALSE(a.valid());
        EXPECT_EQ(b.get(), raw);
    }
    EXPECT_EQ(::fcntl(raw, F_GETFD), -1); // closed exactly once, by b
}

TEST(FsUtil, CloseOrThrowLeavesFdInvalid) {
    TempDir tmp;
    UniqueFd fd(::open((tmp.path() / "g").c_str(), O_WRONLY | O_CREAT, 0644));
    ASSERT_TRUE(fd.valid());
    fd.close_or_throw("test");
    EXPECT_FALSE(fd.valid());
}
