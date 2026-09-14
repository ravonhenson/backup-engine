#include "chunker.h"

#include <algorithm>
#include <array>

namespace {

// A fixed table of 256 pseudo-random 64-bit constants, one per byte
// value, used by the Gear hash below. The values don't need to be
// cryptographically strong -- just fixed and reasonably well-mixed -- but
// they DO need to never change: two repos chunking the same bytes with
// different tables would disagree about chunk boundaries, silently
// breaking dedup and cross-repo digest comparisons. Generated once with
// splitmix64 from a fixed seed rather than hand-typing 256 constants.
std::array<uint64_t, 256> make_gear_table() {
    std::array<uint64_t, 256> table{};
    uint64_t state = 0x9E3779B97F4A7C15ULL;
    for (auto& v : table) {
        state += 0x9E3779B97F4A7C15ULL;
        uint64_t z = state;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        z = z ^ (z >> 31);
        v = z;
    }
    return table;
}

const std::array<uint64_t, 256> kGearTable = make_gear_table();

// Number of low bits whose all-zero probability is ~= 1/avg_size.
unsigned mask_bits_for(std::size_t avg_size) {
    unsigned bits = 0;
    while ((std::size_t(1) << (bits + 1)) <= avg_size) ++bits;
    return bits;
}

uint64_t mask_with_bits(unsigned bits) {
    if (bits == 0) return 0;
    if (bits >= 64) return ~uint64_t(0);
    return (uint64_t(1) << bits) - 1;
}

} // namespace

std::vector<ChunkRange> chunk_data(const uint8_t* data, std::size_t len, const ChunkerConfig& cfg) {
    std::vector<ChunkRange> result;
    if (len == 0) return result;

    unsigned base_bits = mask_bits_for(cfg.avg_size);
    // Stricter mask (more bits, lower match probability) before the
    // average size, looser mask (fewer bits) after it -- this is FastCDC's
    // normalization, which pulls the chunk-size distribution tighter
    // around avg_size instead of the exponential tail plain CDC produces.
    uint64_t mask_small = mask_with_bits(base_bits + 2);
    uint64_t mask_large = mask_with_bits(base_bits > 2 ? base_bits - 2 : base_bits);

    std::size_t pos = 0;
    while (pos < len) {
        std::size_t remaining = len - pos;
        if (remaining <= cfg.min_size) {
            result.push_back({pos, remaining});
            break;
        }

        std::size_t limit = std::min(pos + cfg.max_size, len);
        std::size_t avg_point = std::min(pos + cfg.avg_size, limit);
        std::size_t test_start = std::min(pos + cfg.min_size, limit);

        uint64_t hash = 0;
        std::size_t i = pos;
        for (; i < test_start; ++i) {
            hash = (hash << 1) + kGearTable[data[i]];
        }

        std::size_t cut = limit; // forced cut if no boundary is found
        bool found = false;

        for (; i < avg_point; ++i) {
            hash = (hash << 1) + kGearTable[data[i]];
            if ((hash & mask_small) == 0) {
                cut = i + 1;
                found = true;
                break;
            }
        }
        if (!found) {
            for (; i < limit; ++i) {
                hash = (hash << 1) + kGearTable[data[i]];
                if ((hash & mask_large) == 0) {
                    cut = i + 1;
                    break;
                }
            }
        }

        result.push_back({pos, cut - pos});
        pos = cut;
    }

    return result;
}
