#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "crypto/digest.h"
#include "storage/repo.h"

// One entry in the repo's tamper-evident operations log. Each entry
// commits to the previous entry's hash (prev_hash) as well as its own
// fields, forming a hash chain: altering any past entry without also
// recomputing every entry after it makes the chain fail to verify.
//
// What the chain alone detects: editing an old entry without regenerating
// the whole suffix, and reordering or deleting an entry from the middle.
//
// What it can't detect alone: an attacker with write access who either
// truncates the *tail* (a shorter chain is still internally consistent --
// nothing inside the log records how long it used to be) or rewrites
// history and recomputes every hash after the edit.
//
// Signed checkpoints (checkpoint.h) close both gaps for everything up to
// the most recent checkpoint: a statement of (log_size, head_hash), signed
// with a key kept off the repo host and stored elsewhere. verify_checkpoint
// then fails if the log is now shorter than log_size, or if the entry at
// log_size-1 no longer has that hash. Entries appended after the latest
// checkpoint remain covered only by the chain until the next checkpoint.
struct OperationEntry {
    uint64_t seq = 0;
    uint64_t timestamp = 0;
    std::string event_type;
    std::string event_data;
    Digest prev_hash;
    Digest entry_hash;
};

struct VerifyLogResult {
    bool ok = false;
    uint64_t entries_checked = 0;
    std::optional<uint64_t> first_bad_seq;
    std::string message;
};

// Appends a new event to the log, chained to the current head, and
// fsyncs before returning -- so a crash right after this call can never
// leave a fully-valid object in the store without the catalog knowing it
// exists. General-purpose: create_snapshot calls this with
// "snapshot_created", and a future event kind (deletion, retention
// change) is just another call site, not a format change.
//
// event_type and event_data must each be a single non-empty token with
// no whitespace or control characters (the on-disk line is
// space-separated); anything else throws std::invalid_argument without
// writing. Structured data should use a token-safe form such as
// "key=value,key=value".
OperationEntry append_operation(Repo& repo, const std::string& event_type, const std::string& event_data);

std::vector<OperationEntry> read_operations(const Repo& repo);

// Walks the whole chain from genesis, recomputing each entry's hash and
// checking it against both the stored value and the next entry's
// prev_hash. This is deliberately a separate, explicit check rather than
// something list_snapshots()/restore_snapshot() run automatically on
// every call: re-verifying a long chain on every read would be slow at
// scale, and -- more importantly -- a single corrupted old entry
// shouldn't make every snapshot after it inaccessible. Detection belongs
// in an explicit audit step (this function / the `verify-log` CLI
// command), not as a gate on normal recovery operations.
VerifyLogResult verify_operations_log(const Repo& repo);
