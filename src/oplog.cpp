#include "oplog.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include "hasher.h"

namespace fs = std::filesystem;

namespace {

constexpr const char* kOpLogFileName = "operations.log";

Digest genesis_digest(HashAlgo algo) {
    Digest d;
    d.algo = algo;
    d.length = 32;
    d.bytes.fill(0);
    return d;
}

uint64_t now_unix_seconds() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

Digest compute_entry_hash(HashAlgo algo, const OperationEntry& e) {
    std::ostringstream canonical;
    canonical << e.seq << '\n' << e.timestamp << '\n' << e.event_type << '\n' << e.event_data << '\n'
              << e.prev_hash.to_string() << '\n';
    std::string s = canonical.str();

    auto hasher = make_hasher(algo);
    hasher->update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    return hasher->finalize();
}

std::string serialize_entry(const OperationEntry& e) {
    std::ostringstream line;
    line << e.seq << ' ' << e.timestamp << ' ' << e.event_type << ' ' << e.event_data << ' '
         << e.prev_hash.to_string() << ' ' << e.entry_hash.to_string() << '\n';
    return line.str();
}

// A single O_APPEND write plus fsync is the right durability primitive
// here, unlike ObjectStore's temp-file-then-rename dance: that pattern
// exists because CAS objects are created fresh and must never be
// observed half-written, whereas this file is grown in place and
// POSIX guarantees a single O_APPEND write() lands atomically relative
// to other writers.
//
// The file is left read-only (0444) between appends, matching the
// immutable-by-construction property CAS objects already have -- a
// casual overwrite or accidental open-for-write requires an explicit
// permission change first. This is a speed bump, not a hard security
// boundary: anyone with the same OS user account can chmod it back, the
// same honest limitation already documented for the hash chain itself.
void append_line_durably(const fs::path& path, const std::string& line) {
    std::error_code ec;
    if (fs::exists(path)) {
        fs::permissions(path, fs::perms::owner_write, fs::perm_options::add, ec);
    }

    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        throw std::runtime_error("failed to open operations log: " + path.string() + ": " + std::strerror(errno));
    }

    const char* ptr = line.data();
    std::size_t remaining = line.size();
    while (remaining > 0) {
        ssize_t written = ::write(fd, ptr, remaining);
        if (written < 0) {
            if (errno == EINTR) continue;
            int err = errno;
            ::close(fd);
            throw std::runtime_error(std::string("failed to append to operations log: ") + std::strerror(err));
        }
        ptr += written;
        remaining -= static_cast<std::size_t>(written);
    }

    if (::fsync(fd) != 0) {
        int err = errno;
        ::close(fd);
        throw std::runtime_error(std::string("fsync failed for operations log: ") + std::strerror(err));
    }
    ::close(fd);

    fs::permissions(path, fs::perms::owner_write, fs::perm_options::remove, ec);
}

} // namespace

OperationEntry append_operation(Repo& repo, const std::string& event_type, const std::string& event_data) {
    auto existing = read_operations(repo);

    OperationEntry entry;
    entry.seq = existing.empty() ? 0 : existing.back().seq + 1;
    entry.timestamp = now_unix_seconds();
    entry.event_type = event_type;
    entry.event_data = event_data;
    entry.prev_hash = existing.empty() ? genesis_digest(repo.default_algo()) : existing.back().entry_hash;
    entry.entry_hash = compute_entry_hash(repo.default_algo(), entry);

    append_line_durably(repo.root() / kOpLogFileName, serialize_entry(entry));

    return entry;
}

std::vector<OperationEntry> read_operations(const Repo& repo) {
    std::vector<OperationEntry> result;
    std::ifstream log(repo.root() / kOpLogFileName);
    if (!log) return result;

    std::string line;
    while (std::getline(log, line)) {
        if (line.empty()) continue;

        std::istringstream fields(line);
        OperationEntry e;
        std::string prev_hash_text, entry_hash_text;
        if (!(fields >> e.seq >> e.timestamp >> e.event_type >> e.event_data >> prev_hash_text >> entry_hash_text)) {
            continue; // skip a malformed line rather than fail the whole read
        }

        auto prev_hash = Digest::parse(prev_hash_text);
        auto entry_hash = Digest::parse(entry_hash_text);
        if (!prev_hash || !entry_hash) continue;

        e.prev_hash = *prev_hash;
        e.entry_hash = *entry_hash;
        result.push_back(std::move(e));
    }
    return result;
}

VerifyLogResult verify_operations_log(const Repo& repo) {
    auto entries = read_operations(repo);
    Digest expected_prev = genesis_digest(repo.default_algo());

    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto& e = entries[i];

        if (e.prev_hash != expected_prev) {
            return {false, i, e.seq, "prev_hash does not match the preceding entry's hash"};
        }

        Digest recomputed = compute_entry_hash(repo.default_algo(), e);
        if (recomputed != e.entry_hash) {
            return {false, i, e.seq, "entry_hash does not match a recomputed hash of the entry's own fields"};
        }

        expected_prev = e.entry_hash;
    }

    return {true, entries.size(), std::nullopt, "chain intact"};
}
