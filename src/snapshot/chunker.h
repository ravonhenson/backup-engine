#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

// Content-defined chunking parameters. These bounds and the target
// average are part of the repo's effective format: rechunking the same
// bytes must always produce the same boundaries, forever, or dedup and
// restore both silently break. Keep this in mind before ever changing the
// defaults on an existing repo.
struct ChunkerConfig {
    std::size_t min_size = 2 * 1024;
    std::size_t avg_size = 8 * 1024;
    std::size_t max_size = 32 * 1024;
};

struct ChunkRange {
    std::size_t offset;
    std::size_t length;
};

// Splits [data, data+len) into content-defined chunks (FastCDC-style Gear
// hash with two-level normalization around avg_size), covering every byte
// exactly once with no gaps or overlaps. Because boundaries are
// determined by nearby content rather than fixed offsets, inserting or
// removing bytes only perturbs the chunk(s) near the edit -- everything
// else keeps its original boundaries and therefore its original digest.
std::vector<ChunkRange> chunk_data(const uint8_t* data, std::size_t len, const ChunkerConfig& config = {});
