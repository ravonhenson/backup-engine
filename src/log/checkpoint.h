#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "crypto/digest.h"
#include "storage/repo.h"
#include "crypto/signing.h"

// A checkpoint statement: "at `timestamp`, this repo's operations log had
// `log_size` entries, and the last one's entry_hash was `head_hash`."
//
// Because every entry's hash covers the entry before it, head_hash stands
// for the entire log up to that point. Once a statement is signed with a
// key kept off the repo host and stored somewhere else, the log can no
// longer be rewritten or truncated below log_size without detection.
//
// This is the same shape as a Certificate Transparency signed tree head
// (size + head + time), so it keeps working if the log later becomes a
// Merkle log: head_hash would then be the tree root.
struct CheckpointStatement {
    uint64_t log_size = 0;
    Digest head_hash;
    uint64_t timestamp = 0;

    // The exact bytes that get signed:
    //
    //   backup-engine checkpoint v1
    //   log_size=<decimal>
    //   head_hash=<algo:hex>
    //   timestamp=<unix seconds>
    //
    // Every line ends with '\n', including the last.
    std::string serialize() const;

    // Accepts only the canonical form serialize() produces -- same line
    // order, no extra whitespace or lines, lowercase hex, trailing newline.
    // Anything else returns nullopt. A signature covers exact bytes, so
    // there must be exactly one valid encoding of any statement.
    static std::optional<CheckpointStatement> parse(std::string_view text);
};

// A statement describing the repo's operations log as it is right now.
// Verifies the whole chain first and throws if it's broken (a checkpoint
// would otherwise certify the tampered state), and throws if the log is
// empty (there is nothing to checkpoint yet).
CheckpointStatement current_checkpoint_statement(const Repo& repo);

// A statement plus an Ed25519 signature over its exact serialize() bytes:
//
//   <the four statement lines, unchanged>
//   key_id=ed25519:<64 hex>
//   signature=<128 hex>
//
// key_id names the signer, but is never trusted on its own: verification
// takes the verifier's own trusted public key and requires a match.
struct SignedCheckpoint {
    CheckpointStatement statement;
    PublicKey signer;
    Ed25519Signature signature{};

    std::string serialize() const;

    // Canonical form only, like CheckpointStatement::parse. Parsing does
    // NOT check the signature -- that's verify_checkpoint's job.
    static std::optional<SignedCheckpoint> parse(std::string_view text);
};

// Signs a statement. Touches no repo, so it can run on a separate machine
// that holds the key.
SignedCheckpoint sign_checkpoint(const CheckpointStatement& statement, const SecretKey& key);

struct VerifyCheckpointResult {
    bool ok = false;
    std::string message;
};

// Checks a signed checkpoint against the repo's current log, in order,
// stopping at the first failure:
//   1. it was signed by `trusted` (the verifier's own key, never the
//      key_id embedded in the checkpoint)
//   2. the signature is valid for the exact statement bytes
//   3. the whole log passes verify_operations_log
//   4. the log still has at least log_size entries     -> else truncated
//   5. entry log_size-1 still has entry_hash head_hash -> else rewritten
// Entries appended after the checkpoint are fine: the log only grows.
// Returns a verdict rather than throwing on failure, like the other
// verify_* functions.
VerifyCheckpointResult verify_checkpoint(const Repo& repo, const SignedCheckpoint& checkpoint,
                                         const PublicKey& trusted);
