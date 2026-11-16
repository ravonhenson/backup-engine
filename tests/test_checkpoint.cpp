#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>

#include "log/checkpoint.h"
#include "crypto/signing.h"
#include "log/oplog.h"
#include "storage/repo.h"
#include "test_util.h"

namespace fs = std::filesystem;
using test_util::TempDir;

namespace {

const std::string kHead = "sha256:30ac37e790bb9b2411b1bc5977517b1b360517340ed2a596ab5e9fe9946fc7f9";

const std::string kCanonical = "backup-engine checkpoint v1\n"
                               "log_size=51\n"
                               "head_hash=" + kHead + "\n"
                               "timestamp=1794762676\n";

} // namespace

TEST(CheckpointStatement, SerializesToExactFormat) {
    CheckpointStatement s;
    s.log_size = 51;
    s.head_hash = *Digest::parse(kHead);
    s.timestamp = 1794762676;
    EXPECT_EQ(s.serialize(), kCanonical);
}

TEST(CheckpointStatement, ParsesCanonicalForm) {
    auto s = CheckpointStatement::parse(kCanonical);
    ASSERT_TRUE(s);
    EXPECT_EQ(s->log_size, 51u);
    EXPECT_EQ(s->head_hash.to_string(), kHead);
    EXPECT_EQ(s->timestamp, 1794762676u);
}

// Each of these says the same thing as kCanonical (or almost), but isn't
// byte-identical to it -- and a signature covers exact bytes, so all of
// them must be refused rather than "normalized".
TEST(CheckpointStatement, RejectsAnyNonCanonicalEncoding) {
    auto replace = [](std::string text, const std::string& from, const std::string& to) {
        auto pos = text.find(from);
        EXPECT_NE(pos, std::string::npos) << from;
        return text.replace(pos, from.size(), to);
    };
    std::string upper_hash = kHead;
    for (auto& c : upper_hash) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    upper_hash.replace(0, 6, "sha256");

    const std::string bad[] = {
        "",
        kCanonical.substr(0, kCanonical.size() - 1),                      // no trailing newline
        kCanonical + "\n",                                                // extra blank line
        kCanonical + "extra=1\n",                                         // extra field
        replace(kCanonical, "checkpoint v1", "checkpoint v2"),            // unknown version
        replace(kCanonical, "log_size=51", "log_size= 51"),               // whitespace
        replace(kCanonical, "log_size=51", "log_size=051"),               // leading zero
        replace(kCanonical, kHead, upper_hash),                           // uppercase hex
        replace(kCanonical, "\n", "\r\n"),                                // CRLF
        "backup-engine checkpoint v1\n"                                   // reordered fields
        "head_hash=" + kHead + "\nlog_size=51\ntimestamp=1794762676\n",
    };
    for (const auto& text : bad) {
        EXPECT_FALSE(CheckpointStatement::parse(text)) << text;
    }
}

class CheckpointRepoTest : public ::testing::Test {
protected:
    TempDir tmp_;
    Repo repo_ = Repo::init(tmp_.path() / "repo");
};

TEST_F(CheckpointRepoTest, DescribesTheCurrentLogHead) {
    append_operation(repo_, "test_event", "a");
    OperationEntry last = append_operation(repo_, "test_event", "b");

    CheckpointStatement s = current_checkpoint_statement(repo_);
    EXPECT_EQ(s.log_size, 2u);
    EXPECT_EQ(s.head_hash, last.entry_hash);
    EXPECT_GT(s.timestamp, 0u);

    // And what it prints parses back to the same statement.
    auto reparsed = CheckpointStatement::parse(s.serialize());
    ASSERT_TRUE(reparsed);
    EXPECT_EQ(reparsed->serialize(), s.serialize());
}

TEST_F(CheckpointRepoTest, RefusesAnEmptyLog) {
    EXPECT_THROW(current_checkpoint_statement(repo_), std::runtime_error);
}

// A checkpoint of a tampered log would certify the tampering.
TEST_F(CheckpointRepoTest, RefusesALogThatFailsVerification) {
    append_operation(repo_, "test_event", "original");
    append_operation(repo_, "test_event", "second");

    fs::path log_path = repo_.root() / "operations.log";
    std::stringstream contents;
    contents << std::ifstream(log_path).rdbuf();
    std::string text = contents.str();
    text.replace(text.find("original"), 8, "modified");

    fs::permissions(log_path, fs::perms::owner_write, fs::perm_options::add);
    std::ofstream(log_path, std::ios::trunc) << text;

    EXPECT_THROW(current_checkpoint_statement(repo_), std::runtime_error);
}

// --- signed checkpoints ---------------------------------------------------

namespace {

CheckpointStatement sample_statement() {
    return *CheckpointStatement::parse(kCanonical);
}

} // namespace

TEST(SignedCheckpoint, SignatureCoversTheExactStatementBytes) {
    SecretKey key = SecretKey::generate();
    SignedCheckpoint c = sign_checkpoint(sample_statement(), key);

    EXPECT_EQ(c.signer, key.public_key());
    EXPECT_TRUE(verify_signature(key.public_key(), kCanonical, c.signature));

    std::string text = c.serialize();
    EXPECT_EQ(text.substr(0, kCanonical.size()), kCanonical); // statement unchanged, two lines appended
    EXPECT_NE(text.find("\nkey_id=" + key.public_key().key_id() + "\nsignature="), std::string::npos);
}

TEST(SignedCheckpoint, ParseRoundTrips) {
    SignedCheckpoint c = sign_checkpoint(sample_statement(), SecretKey::generate());
    auto parsed = SignedCheckpoint::parse(c.serialize());
    ASSERT_TRUE(parsed);
    EXPECT_EQ(parsed->serialize(), c.serialize());
    EXPECT_EQ(parsed->signer, c.signer);
    EXPECT_EQ(parsed->signature, c.signature);
}

TEST(SignedCheckpoint, ParseRejectsNonCanonicalOrIncomplete) {
    std::string good = sign_checkpoint(sample_statement(), SecretKey::generate()).serialize();
    auto sig_pos = good.find("signature=");

    const std::string bad[] = {
        kCanonical,                                    // unsigned statement
        good + "extra=1\n",                            // trailing content
        good.substr(0, good.size() - 1),               // no trailing newline
        good.substr(0, sig_pos) + "signature=00\n",    // short signature
        "x" + good,                                    // statement part not canonical
    };
    for (const auto& text : bad) EXPECT_FALSE(SignedCheckpoint::parse(text)) << text;
}

// --- verify_checkpoint ------------------------------------------------------

namespace {

std::string read_text(const fs::path& p) {
    std::stringstream ss;
    ss << std::ifstream(p, std::ios::binary).rdbuf();
    return ss.str();
}

void overwrite_log(const Repo& repo, const std::string& text) {
    fs::path log_path = repo.root() / "operations.log";
    fs::permissions(log_path, fs::perms::owner_write, fs::perm_options::add);
    std::ofstream(log_path, std::ios::binary | std::ios::trunc) << text;
}

} // namespace

class VerifyCheckpointTest : public ::testing::Test {
protected:
    void SetUp() override {
        for (const char* v : {"a", "b", "c"}) append_operation(repo_, "test_event", v);
        checkpoint_ = sign_checkpoint(current_checkpoint_statement(repo_), key_);
    }

    TempDir tmp_;
    Repo repo_ = Repo::init(tmp_.path() / "repo");
    SecretKey key_ = SecretKey::generate();
    SignedCheckpoint checkpoint_;
};

TEST_F(VerifyCheckpointTest, PassesForTheUnchangedLog) {
    auto r = verify_checkpoint(repo_, checkpoint_, key_.public_key());
    EXPECT_TRUE(r.ok) << r.message;
}

TEST_F(VerifyCheckpointTest, PassesAfterNewEntriesAreAppended) {
    append_operation(repo_, "test_event", "d");
    auto r = verify_checkpoint(repo_, checkpoint_, key_.public_key());
    EXPECT_TRUE(r.ok) << r.message;
}

TEST_F(VerifyCheckpointTest, FailsForAKeyOtherThanTheTrustedOne) {
    auto r = verify_checkpoint(repo_, checkpoint_, SecretKey::generate().public_key());
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.message.find("not the trusted key"), std::string::npos) << r.message;
}

// Someone edits the signed file (here: claims fewer entries) but can't
// re-sign it.
TEST_F(VerifyCheckpointTest, FailsIfTheStatementWasEdited) {
    SignedCheckpoint edited = checkpoint_;
    edited.statement.log_size = 2;
    auto r = verify_checkpoint(repo_, edited, key_.public_key());
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.message.find("invalid signature"), std::string::npos) << r.message;
}

// Dropping the last entry leaves a self-consistent chain that verify-log
// accepts -- the gap documented in oplog.h. The checkpoint catches it.
TEST_F(VerifyCheckpointTest, DetectsTailTruncation) {
    std::string log = read_text(repo_.root() / "operations.log");
    log.erase(log.rfind('\n', log.size() - 2) + 1); // drop the last line
    overwrite_log(repo_, log);
    ASSERT_TRUE(verify_operations_log(repo_).ok); // invisible to verify-log alone

    auto r = verify_checkpoint(repo_, checkpoint_, key_.public_key());
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.message.find("truncated"), std::string::npos) << r.message;
}

// A full rewrite with every hash recomputed: a log from a different repo,
// same length, internally valid. verify-log passes; the checkpoint doesn't.
TEST_F(VerifyCheckpointTest, DetectsHistoryRewrittenWithRecomputedHashes) {
    Repo forged = Repo::init(tmp_.path() / "forged");
    for (const char* v : {"a", "FORGED", "c"}) append_operation(forged, "test_event", v);
    overwrite_log(repo_, read_text(forged.root() / "operations.log"));
    ASSERT_TRUE(verify_operations_log(repo_).ok);

    auto r = verify_checkpoint(repo_, checkpoint_, key_.public_key());
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.message.find("rewritten"), std::string::npos) << r.message;
}

TEST_F(VerifyCheckpointTest, FailsIfTheLogChainIsBroken) {
    std::string log = read_text(repo_.root() / "operations.log");
    log.replace(log.find(" b "), 3, " B ");
    overwrite_log(repo_, log);

    auto r = verify_checkpoint(repo_, checkpoint_, key_.public_key());
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.message.find("fails verification"), std::string::npos) << r.message;
}

// current_checkpoint_statement never produces log_size=0, but a signer
// could be handed one; it must fail cleanly, not index entry -1.
TEST_F(VerifyCheckpointTest, RejectsACheckpointCoveringNoEntries) {
    CheckpointStatement empty = checkpoint_.statement;
    empty.log_size = 0;
    auto r = verify_checkpoint(repo_, sign_checkpoint(empty, key_), key_.public_key());
    EXPECT_FALSE(r.ok);
}
