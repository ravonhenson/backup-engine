#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "digest.h"

// One file's content, as an ordered sequence of chunk digests. This
// object is itself content-addressed and stored like any other object;
// a manifest's file entry references a ChunkList's digest rather than
// embedding the chunk list inline, so the manifest format from Layer 2
// doesn't need to change shape at all. Two files with identical content
// produce an identical chunk sequence and therefore an identical
// ChunkList digest -- whole-file dedup falls out of chunk-level dedup for
// free.
struct ChunkRef {
    Digest digest;
    uint64_t size;
};

struct ChunkList {
    uint64_t total_size = 0;
    std::vector<ChunkRef> chunks;

    std::vector<uint8_t> serialize() const;
    static std::optional<ChunkList> deserialize(const std::vector<uint8_t>& data);
};
