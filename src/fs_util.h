#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

std::vector<uint8_t> read_file(const std::filesystem::path& path);
void write_file(const std::filesystem::path& path, const std::vector<uint8_t>& data);

// Writes to a temp file in the same directory, fsyncs it, then atomically
// renames it into place -- the same durability pattern ObjectStore uses
// for content-addressed objects, applied here to small pieces of critical
// repo metadata (like repo.conf) that must never be observed half-written
// after a crash, and must survive a crash that happens right after this
// call returns. The resulting file is written read-only (0444), matching
// the immutable-by-construction property CAS objects already have.
void write_file_atomically(const std::filesystem::path& path, const std::vector<uint8_t>& data);
