#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "digest.h"
#include "merkle.h"
#include "oplog.h"
#include "repo.h"

// "What snapshots exist" is sourced from the tamper-evident operations
// log (oplog.h) -- "snapshot_created" events with no later matching
// "snapshot_deleted" event for the same digest.
struct SnapshotListEntry {
    uint64_t created_at = 0;
    Digest digest;
};

// Chunk-level dedup counters for one create_snapshot() call, so a caller
// can report how much of a backup was actually new versus already
// present -- the concrete, demonstrable payoff of content-defined
// chunking.
struct SnapshotStats {
    std::size_t total_files = 0;
    std::size_t total_chunks = 0;
    std::size_t new_chunks = 0;
};

struct SnapshotResult {
    Digest digest;
    SnapshotStats stats;
    // The operations-log entry recording this snapshot's creation, so a
    // caller can surface the resulting chain head (e.g. for an operator
    // to cross-check against an independently held record later).
    OperationEntry operation;
};

// Invoked after each durable write during snapshot creation (each chunk,
// each file's chunk-list, the manifest, and the final catalog append).
// Exists purely so tests can inject a crash (e.g. raise(SIGKILL)) at an
// exact point in the multi-step commit sequence to verify the repo
// recovers cleanly regardless of where it was interrupted; production
// callers should never need to pass one.
using CrashTestHook = std::function<void()>;

// Walks source_root, splitting each regular file into content-defined
// chunks (see chunker.h) and storing them in the repo's object store, then
// recording a manifest of (path, chunk-list digest, mode, size) entries.
// Throws if it encounters anything other than a regular file or a
// directory (symlinks, devices, etc. are not yet supported) rather than
// silently omitting data from the backup.
SnapshotResult create_snapshot(Repo& repo, const std::filesystem::path& source_root,
                                const CrashTestHook& checkpoint = {});

// Reconstructs a previously created snapshot under dest_root. Every
// object fetched from the store is already hash-verified by
// ObjectStore::get() before it's written out. Throws if the snapshot has
// been deleted (see delete_snapshot) -- deletion is a real access-control
// boundary, not just a listing filter.
void restore_snapshot(Repo& repo, const Digest& snapshot_digest, const std::filesystem::path& dest_root);

std::vector<SnapshotListEntry> list_snapshots(const Repo& repo);

// Tombstones a snapshot: appends a "snapshot_deleted" event so it drops
// out of list_snapshots() and restore_snapshot() refuses it, WITHOUT
// physically removing any underlying object. Dedup means a chunk from
// this snapshot may still be referenced by another one, so selective
// physical deletion would need a full reachability/garbage-collection
// pass -- out of scope here. Throws if the digest was never created, or
// was already deleted.
void delete_snapshot(Repo& repo, const Digest& snapshot_digest);

// Result of a full verification of a snapshot: every chunk is fetched
// (and therefore hash-verified by ObjectStore::get()) and the recomputed
// Merkle root is checked against the one recorded in the manifest at
// creation time. Be precise about what this buys over restore_snapshot:
// it's still O(total snapshot size) -- reading is reading, with or
// without a Merkle tree -- the saving is skipping the destination-write
// phase (no directory tree, no permissions, nothing written to disk),
// not a "milliseconds regardless of size" guarantee. That sublinear
// property belongs to prove_chunk_inclusion below, not to this.
struct VerifySnapshotResult {
    bool ok = false;
    std::size_t chunks_checked = 0;
    std::string message;
};

VerifySnapshotResult verify_snapshot(Repo& repo, const Digest& snapshot_digest);

// Generates a self-contained Merkle inclusion proof that chunk_digest is
// part of snapshot_digest's content. Be precise about where the
// sublinearity actually lives: *generating* a proof still needs the full
// ordered leaf list to know the tree shape, so it's O(number of chunks)
// in chunk-list metadata -- but never touches actual chunk content, so
// it's far cheaper than verify_snapshot for a large snapshot. The
// genuinely sublinear, zero-repo-access step is *verifying* an
// already-generated proof (merkle_verify_inclusion / the MerkleInclusionProof
// overload), which is O(log n) and needs nothing but the proof itself.
// Returns nullopt if the snapshot has no such chunk. If the chunk occurs
// more than once (deduplicated within the same snapshot), proves
// whichever occurrence is encountered first while walking the manifest
// in order.
std::optional<MerkleInclusionProof> prove_chunk_inclusion(Repo& repo, const Digest& snapshot_digest,
                                                           const Digest& chunk_digest);
