#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "digest.h"
#include "repo.h"

// One entry in the repo's tamper-evident operations log. Each entry
// commits to the previous entry's hash (prev_hash) as well as its own
// fields, forming a hash chain: altering any past entry without also
// recomputing every entry after it makes the chain fail to verify.
//
// Honest limitation: this detects the realistic threat (someone edits an
// old entry through the normal file format without regenerating the
// whole suffix), and it detects reordering or deletion of an entry from
// the middle. It does NOT by itself detect an attacker with full
// filesystem access truncating the *tail* of the log (deleting the most
// recent entries) -- a shorter chain that ends earlier is still
// internally consistent, because nothing inside the log records how long
// it used to be. Closing that gap needs an externally-held checkpoint of
// a past head (the classic problem Certificate Transparency solves with
// independent gossiping monitors); this layer surfaces the head hash on
// every append specifically so an operator has something to cross-check
// against an independent record later, but doesn't implement that
// external anchoring itself.
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
