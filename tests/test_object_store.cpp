#include <gtest/gtest.h>

#include <fcntl.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <vector>

#include "util/errors.h"
#include "storage/object_store.h"
#include "test_util.h"

namespace fs = std::filesystem;
using test_util::to_bytes;

namespace {

std::size_t count_regular_files(const fs::path& root) {
    std::size_t n = 0;
    for (const auto& entry : fs::recursive_directory_iterator(root)) {
        if (entry.is_regular_file()) ++n;
    }
    return n;
}

} // namespace

class ObjectStoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        root_ = tmp_.path();
        fs::create_directories(root_);
    }

    test_util::TempDir tmp_; // declared first: outlives every path below
    fs::path root_;
};

TEST_F(ObjectStoreTest, PutGetRoundTrip) {
    ObjectStore store(root_ / "objects", HashAlgo::SHA256);
    auto data = to_bytes("hello world");

    Digest digest = store.put(data).digest;
    auto got = store.get(digest);

    EXPECT_EQ(got, data);
}

TEST_F(ObjectStoreTest, PuttingSameContentTwiceIsIdempotent) {
    ObjectStore store(root_ / "objects", HashAlgo::SHA256);
    auto data = to_bytes("duplicate me");

    PutResult first = store.put(data);
    std::size_t files_after_first = count_regular_files(root_ / "objects");

    PutResult second = store.put(data);
    std::size_t files_after_second = count_regular_files(root_ / "objects");

    EXPECT_EQ(first.digest, second.digest);
    EXPECT_TRUE(first.newly_written);
    EXPECT_FALSE(second.newly_written);
    EXPECT_EQ(files_after_first, files_after_second);
}

TEST_F(ObjectStoreTest, ExistsReflectsStoredObjects) {
    ObjectStore store(root_ / "objects", HashAlgo::SHA256);
    auto data = to_bytes("check existence");
    Digest digest = store.put(data).digest;

    EXPECT_TRUE(store.exists(digest));

    auto other = Digest::from_hex(HashAlgo::SHA256, std::string(64, '0'));
    ASSERT_TRUE(other.has_value());
    EXPECT_FALSE(store.exists(*other));
}

TEST_F(ObjectStoreTest, GetOnMissingObjectThrows) {
    ObjectStore store(root_ / "objects", HashAlgo::SHA256);
    auto missing = Digest::from_hex(HashAlgo::SHA256, std::string(64, 'a'));
    ASSERT_TRUE(missing.has_value());

    EXPECT_THROW(store.get(*missing), ObjectNotFoundError);
}

TEST_F(ObjectStoreTest, CorruptedObjectFailsVerificationOnRead) {
    ObjectStore store(root_ / "objects", HashAlgo::SHA256);
    auto data = to_bytes("do not corrupt me");
    Digest digest = store.put(data).digest;

    fs::path on_disk = store.path_for(digest);
    // Objects are written read-only; restore write permission to simulate
    // bit rot / tampering, then flip a byte.
    fs::permissions(on_disk, fs::perms::owner_write, fs::perm_options::add);
    {
        std::fstream f(on_disk, std::ios::binary | std::ios::in | std::ios::out);
        ASSERT_TRUE(f);
        f.seekp(0);
        f.put(static_cast<char>(0x00));
    }

    EXPECT_THROW(store.get(digest), IntegrityError);
}

TEST_F(ObjectStoreTest, SurvivesReopeningTheStore) {
    fs::path objects_dir = root_ / "objects";
    Digest digest;
    {
        ObjectStore store(objects_dir, HashAlgo::SHA256);
        digest = store.put(to_bytes("still here after restart")).digest;
    }
    {
        ObjectStore reopened(objects_dir, HashAlgo::SHA256);
        auto got = reopened.get(digest);
        EXPECT_EQ(got, to_bytes("still here after restart"));
    }
}
