#include "log/checkpoint.h"

#include <sstream>
#include <stdexcept>

#include "util/fs_util.h"
#include "log/oplog.h"
#include "util/text_format.h"

namespace {

constexpr std::string_view kHeader = "backup-engine checkpoint v1";

// Reads one '\n'-terminated line starting at `pos`, advancing `pos` past
// the newline. Returns nullopt if there is no complete line left.
std::optional<std::string_view> next_line(std::string_view text, std::size_t& pos) {
    auto nl = text.find('\n', pos);
    if (nl == std::string_view::npos) return std::nullopt;
    auto line = text.substr(pos, nl - pos);
    pos = nl + 1;
    return line;
}

// Reads the next line and requires it to be "<key>=<value>"; returns the value.
std::optional<std::string_view> expect_field(std::string_view text, std::size_t& pos, std::string_view key) {
    auto line = next_line(text, pos);
    if (!line) return std::nullopt;
    auto kv = split_key_value(*line);
    if (!kv || kv->first != key) return std::nullopt;
    return kv->second;
}

} // namespace

std::string CheckpointStatement::serialize() const {
    std::ostringstream out;
    out << kHeader << "\n";
    out << "log_size=" << log_size << "\n";
    out << "head_hash=" << head_hash.to_string() << "\n";
    out << "timestamp=" << timestamp << "\n";
    return out.str();
}

std::optional<CheckpointStatement> CheckpointStatement::parse(std::string_view text) {
    std::size_t pos = 0;
    auto header = next_line(text, pos);
    if (!header || *header != kHeader) return std::nullopt;

    auto log_size = expect_field(text, pos, "log_size");
    auto head_hash = expect_field(text, pos, "head_hash");
    auto timestamp = expect_field(text, pos, "timestamp");
    if (!log_size || !head_hash || !timestamp) return std::nullopt;

    CheckpointStatement s;
    auto size = parse_u64(*log_size);
    auto head = Digest::parse(*head_hash);
    auto time = parse_u64(*timestamp);
    if (!size || !head || !time) return std::nullopt;
    s.log_size = *size;
    s.head_hash = *head;
    s.timestamp = *time;

    // Canonical-form check: the line-by-line parse above already rejects
    // reordering, extra keys and missing lines; this also rejects trailing
    // content and anything the field parsers would tolerate but not
    // reproduce (e.g. uppercase hex in head_hash).
    if (s.serialize() != text) return std::nullopt;
    return s;
}

std::string SignedCheckpoint::serialize() const {
    return statement.serialize() + "key_id=" + signer.key_id() + "\n" +
           "signature=" + to_hex(signature.data(), signature.size()) + "\n";
}

std::optional<SignedCheckpoint> SignedCheckpoint::parse(std::string_view text) {
    // The statement is exactly the first four lines.
    std::size_t pos = 0;
    for (int i = 0; i < 4; ++i) {
        if (!next_line(text, pos)) return std::nullopt;
    }
    auto statement = CheckpointStatement::parse(text.substr(0, pos));
    if (!statement) return std::nullopt;

    auto key_id = expect_field(text, pos, "key_id");
    auto sig_hex = expect_field(text, pos, "signature");
    if (!key_id || !sig_hex) return std::nullopt;
    auto signer = PublicKey::from_key_id(*key_id);
    auto sig_bytes = from_hex(*sig_hex, 64);
    if (!signer || !sig_bytes) return std::nullopt;

    SignedCheckpoint c;
    c.statement = *statement;
    c.signer = *signer;
    std::copy(sig_bytes->begin(), sig_bytes->end(), c.signature.begin());

    if (c.serialize() != text) return std::nullopt; // rejects trailing content
    return c;
}

SignedCheckpoint sign_checkpoint(const CheckpointStatement& statement, const SecretKey& key) {
    SignedCheckpoint c;
    c.statement = statement;
    c.signer = key.public_key();
    c.signature = key.sign(statement.serialize());
    return c;
}

VerifyCheckpointResult verify_checkpoint(const Repo& repo, const SignedCheckpoint& checkpoint,
                                         const PublicKey& trusted) {
    const CheckpointStatement& s = checkpoint.statement;

    if (checkpoint.signer != trusted) {
        return {false, "signed by " + checkpoint.signer.key_id() + ", not the trusted key " + trusted.key_id()};
    }
    if (!verify_signature(trusted, s.serialize(), checkpoint.signature)) {
        return {false, "invalid signature: the statement was altered or the signature is corrupt"};
    }
    if (s.log_size == 0) {
        return {false, "checkpoint covers no log entries"}; // never produced by current_checkpoint_statement
    }

    VerifyLogResult log_check = verify_operations_log(repo);
    if (!log_check.ok) {
        std::string at = log_check.first_bad_seq ? " at seq " + std::to_string(*log_check.first_bad_seq) : "";
        return {false, "operations log fails verification" + at + ": " + log_check.message};
    }

    auto entries = read_operations(repo);
    if (entries.size() < s.log_size) {
        return {false, "log has " + std::to_string(entries.size()) + " entries but the checkpoint covers " +
                           std::to_string(s.log_size) + ": entries were removed (truncated)"};
    }
    const OperationEntry& covered_head = entries[s.log_size - 1];
    if (covered_head.entry_hash != s.head_hash) {
        return {false, "entry at seq " + std::to_string(s.log_size - 1) + " has hash " +
                           covered_head.entry_hash.to_string() + ", checkpoint says " + s.head_hash.to_string() +
                           ": history was rewritten"};
    }

    return {true, "log matches checkpoint at seq " + std::to_string(s.log_size - 1) + " (" +
                      std::to_string(entries.size() - s.log_size) + " entries appended since)"};
}

CheckpointStatement current_checkpoint_statement(const Repo& repo) {
    VerifyLogResult check = verify_operations_log(repo);
    if (!check.ok) {
        throw std::runtime_error("refusing to checkpoint a log that fails verification: " + check.message);
    }

    auto entries = read_operations(repo);
    if (entries.empty()) {
        throw std::runtime_error("operations log is empty; nothing to checkpoint");
    }

    // verify_operations_log guarantees seq numbers run 0..size-1, so
    // log_size really means "entries 0 through log_size-1".
    CheckpointStatement s;
    s.log_size = entries.size();
    s.head_hash = entries.back().entry_hash;
    s.timestamp = now_unix_seconds();
    return s;
}
