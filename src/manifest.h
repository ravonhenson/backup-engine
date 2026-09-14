#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "digest.h"

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

// The full listing for one snapshot. This object is itself content-
// addressed like everything else in the repo: its own digest becomes the
// snapshot's ID, so "restore snapshot X" just means "fetch and parse the
// object named X."
struct Manifest {
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

    std::vector<uint8_t> serialize() const;
    static std::optional<Manifest> deserialize(const std::vector<uint8_t>& data);
};
