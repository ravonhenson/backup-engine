#include "oplog.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include "fs_util.h"
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

// A log line is space-separated fields read back with `>>`, so each of
// event_type/event_data must be exactly one non-empty token: a space
// would shift every later field, a newline would split the entry in two,
// and an empty field would make `>>` read the next field in its place.
// Rejects all whitespace and ASCII control characters.
bool is_log_token(const std::string& s) {
    if (s.empty()) return false;
    for (unsigned char c : s) {
        if (c <= 0x20 || c == 0x7f) return false;
    }
    return true;
}

Digest compute_entry_hash(HashAlgo algo, const OperationEntry& e) {
    std::ostringstream canonical;
    canonical << e.seq << '\n' << e.timestamp << '\n' << e.event_type << '\n' << e.event_data << '\n'
              << e.prev_hash.to_string() << '\n';
    std::string s = canonical.str();
    return hash_bytes(algo, reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

std::string serialize_entry(const OperationEntry& e) {
    std::ostringstream line;
    line << e.seq << ' ' << e.timestamp << ' ' << e.event_type << ' ' << e.event_data << ' '
         << e.prev_hash.to_string() << ' ' << e.entry_hash.to_string() << '\n';
    return line.str();
}

// Removes owner write permission from `path` on scope exit -- including
// when an append throws, so a failed append can't leave the log writable.
class ReadOnlyOnExit {
public:
    explicit ReadOnlyOnExit(const fs::path& path) : path_(path) {}
    ~ReadOnlyOnExit() {
        std::error_code ec;
        fs::permissions(path_, fs::perms::owner_write, fs::perm_options::remove, ec);
    }
    ReadOnlyOnExit(const ReadOnlyOnExit&) = delete;
    ReadOnlyOnExit& operator=(const ReadOnlyOnExit&) = delete;

private:
    const fs::path& path_;
};

// A single O_APPEND write plus a sync is the right durability primitive
// here, unlike ObjectStore's temp-file-then-rename dance: that pattern
// exists because CAS objects are created fresh and must never be
// observed half-written, whereas this file is grown in place.
//
// This append is the commit point that makes a snapshot visible, so it
// is bracketed by storage barriers (see the durability model in
// fs_util.h): the first guarantees every object the new entry refers to
// is durable *before* the entry can be; the second makes the entry itself
// durable before returning.
//
// The file is left read-only (0444) between appends, matching the
// immutable-by-construction property CAS objects already have -- a
// casual overwrite or accidental open-for-write requires an explicit
// permission change first. This is a speed bump, not a hard security
// boundary: anyone with the same OS user account can chmod it back, the
// same honest limitation already documented for the hash chain itself.
void append_line_durably(const fs::path& path, const std::string& line) {
    std::error_code ec;
    const bool existed = fs::exists(path, ec);
    if (existed) {
        fs::permissions(path, fs::perms::owner_write, fs::perm_options::add, ec);
    }
    ReadOnlyOnExit read_only_again(path); // declared before fd: runs after fd is closed

    UniqueFd fd(::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644));
    if (!fd.valid()) {
        throw std::runtime_error("failed to open operations log: " + path.string() + ": " + std::strerror(errno));
    }

    sync_barrier(fd.get(), "operations log (pre-append barrier)");
    write_all(fd.get(), reinterpret_cast<const uint8_t*>(line.data()), line.size(),
              "failed to append to operations log");
    sync_barrier(fd.get(), "operations log");

    if (!existed) sync_dir(path.parent_path()); // first append created the file
}

} // namespace

OperationEntry append_operation(Repo& repo, const std::string& event_type, const std::string& event_data) {
    // Checked before any I/O, so a rejected event never touches the log.
    if (!is_log_token(event_type)) {
        throw std::invalid_argument("invalid operations-log event_type: \"" + event_type + "\"");
    }
    if (!is_log_token(event_data)) {
        throw std::invalid_argument("invalid operations-log event_data: \"" + event_data + "\"");
    }

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
