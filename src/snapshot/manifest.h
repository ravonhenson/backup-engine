#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "crypto/digest.h"

// A directory entry backed up as part of a snapshot. Only regular files
// and directories are represented today; symlinks and other special
// files are explicitly out of scope for this layer (see snapshot.cpp).
struct ManifestEntry {
    bool is_directory = false;
    uint32_t mode = 0;         // POSIX permission bits (fs::perms, masked to 12 bits)
    uint64_t size = 0;         // 0 for directories
    Digest digest;             // meaningful only when !is_directory
    std::string relative_path; // POSIX-style, "." for the backed-up root itself
};

// The exact manifest line for an entry, without the trailing newline:
//   "F <octal mode> <size> <chunk-list digest> <path>"  or  "D <octal mode> <path>"
// Used both to serialize the manifest and as the entry's Merkle leaf data,
// so the line an auditor is shown and the leaf that was committed to can
// never disagree.
std::string manifest_entry_line(const ManifestEntry& e);

// The Merkle leaf data for an entry: H(manifest_entry_line(e)).
Digest manifest_entry_leaf(HashAlgo algo, const ManifestEntry& e);

// RFC 6962 root (merkle.h) over manifest_entry_leaf of every entry, in
// manifest order. Lets a single entry be proven part of a snapshot with an
// O(log n) path, without revealing any other entry.
Digest manifest_entries_root(HashAlgo algo, const std::vector<ManifestEntry>& entries);

// Version 2: header + entries. Version 3 adds entries_root. Both are read;
// new snapshots are written as version 3.
constexpr uint32_t kManifestVersion = 3;

// The full listing for one snapshot. This object is itself content-
// addressed like everything else in the repo: its own digest becomes the
// snapshot's ID, so "restore snapshot X" just means "fetch and parse the
// object named X."
struct Manifest {
    // Kept so a version-2 manifest re-serializes to exactly its original
    // bytes -- those bytes' hash is its snapshot ID.
    uint32_t format_version = kManifestVersion;
    uint64_t created_at = 0; // unix timestamp
    std::string source_root; // absolute path that was backed up
    std::vector<ManifestEntry> entries;
    // Merkle root (see merkle.h) over every chunk digest in this snapshot,
    // in the order they're gathered by walking `entries`. Storing it here
    // rather than in a separate object means it's protected "for free" by
    // this object's own content-addressing: if it were tampered with, the
    // manifest's own digest (the snapshot ID) would no longer match on
    // the next hash-verified read.
    Digest merkle_root;
    // Version 3 only: manifest_entries_root(entries). Protected by
    // content-addressing in the same way as merkle_root.
    Digest entries_root;

    std::vector<uint8_t> serialize() const;
    static std::optional<Manifest> deserialize(const std::vector<uint8_t>& data);
};
