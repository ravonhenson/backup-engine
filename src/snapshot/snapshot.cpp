#include "snapshot/snapshot.h"

#include <algorithm>
#include <functional>
#include <stdexcept>
#include <unordered_set>

#include "snapshot/chunk_list.h"
#include "snapshot/chunker.h"
#include "util/fs_util.h"
#include "snapshot/manifest.h"
#include "crypto/merkle.h"

namespace fs = std::filesystem;

namespace {

uint32_t mode_bits(const fs::path& p) {
    return static_cast<uint32_t>(fs::status(p).permissions()) & 0xFFF;
}

// Splits a file's bytes into content-defined chunks, stores each one
// (deduplicating for free via ObjectStore::put's existence check), and
// stores the resulting ordered chunk list as its own object. Returns that
// chunk-list object's digest, which is what the manifest's file entry
// points to -- not the file's raw content digest.
Digest store_file_as_chunks(Repo& repo, const std::vector<uint8_t>& data, SnapshotStats& stats,
                             const CrashTestHook& checkpoint) {
    ChunkList chunk_list;
    chunk_list.total_size = data.size();

    for (const auto& range : chunk_data(data.data(), data.size())) {
        PutResult result = repo.objects().put(data.data() + range.offset, range.length);
        chunk_list.chunks.push_back({result.digest, static_cast<uint64_t>(range.length)});

        stats.total_chunks += 1;
        if (result.newly_written) stats.new_chunks += 1;
        if (checkpoint) checkpoint();
    }

    Digest digest = repo.objects().put(chunk_list.serialize()).digest;
    if (checkpoint) checkpoint();
    return digest;
}

// THE walk over a snapshot's content: every file entry in manifest order,
// with its ChunkList (fetched hash-verified, then parsed). Every consumer
// -- Merkle root at creation, verify, prove, restore -- goes through this
// one function, so the order that defines the Merkle leaf sequence is
// specified in exactly one place and can't drift between creation and
// verification. Throws if a chunk list is missing, corrupt, or unparseable.
void for_each_file_chunk_list(const Repo& repo, const Manifest& manifest,
                              const std::function<void(const ManifestEntry&, const ChunkList&)>& visit) {
    for (const auto& e : manifest.entries) {
        if (e.is_directory) continue;
        auto chunk_list = ChunkList::deserialize(repo.objects().get(e.digest));
        if (!chunk_list) {
            throw std::runtime_error("failed to parse chunk list for: " + e.relative_path);
        }
        visit(e, *chunk_list);
    }
}

// The Merkle leaf list for a whole snapshot: every chunk digest, in
// for_each_file_chunk_list order. Touches only chunk-list metadata, never
// chunk content.
std::vector<Digest> gather_snapshot_chunk_digests(const Repo& repo, const Manifest& manifest) {
    std::vector<Digest> leaves;
    for_each_file_chunk_list(repo, manifest, [&](const ManifestEntry&, const ChunkList& list) {
        for (const auto& c : list.chunks) leaves.push_back(c.digest);
    });
    return leaves;
}

} // namespace

SnapshotResult create_snapshot(Repo& repo, const fs::path& source_root, const CrashTestHook& checkpoint) {
    if (!fs::exists(source_root) || !fs::is_directory(source_root)) {
        throw std::runtime_error("source is not a directory: " + source_root.string());
    }

    Manifest manifest;
    manifest.created_at = now_unix_seconds();
    manifest.source_root = fs::absolute(source_root).string();

    SnapshotStats stats;

    ManifestEntry root_entry;
    root_entry.is_directory = true;
    root_entry.mode = mode_bits(source_root);
    root_entry.relative_path = ".";
    manifest.entries.push_back(root_entry);

    for (const auto& dirent : fs::recursive_directory_iterator(source_root)) {
        std::string rel_str = fs::relative(dirent.path(), source_root).generic_string();

        if (dirent.is_symlink()) {
            // is_directory()/is_regular_file() below resolve through a
            // symlink to its target's type, so this check must come
            // first or a symlink would be silently backed up as a copy
            // of whatever it points to.
            throw std::runtime_error(
                "unsupported filesystem entry (symlinks are not yet supported): " + dirent.path().string());
        } else if (dirent.is_directory()) {
            ManifestEntry e;
            e.is_directory = true;
            e.mode = mode_bits(dirent.path());
            e.relative_path = rel_str;
            manifest.entries.push_back(std::move(e));
        } else if (dirent.is_regular_file()) {
            auto data = read_file(dirent.path());
            Digest chunk_list_digest = store_file_as_chunks(repo, data, stats, checkpoint);
            stats.total_files += 1;

            ManifestEntry e;
            e.is_directory = false;
            e.mode = mode_bits(dirent.path());
            e.size = data.size();
            e.digest = chunk_list_digest;
            e.relative_path = rel_str;
            manifest.entries.push_back(std::move(e));
        } else {
            throw std::runtime_error(
                "unsupported filesystem entry (symlinks and special files are not yet "
                "supported): " + dirent.path().string());
        }
    }

    // Re-fetches the chunk lists just written (cheap -- these are small
    // metadata objects, not chunk content) rather than accumulating the
    // leaf list inline during the loop above, so creation and later
    // verification/proof generation compute the root via the exact same
    // code path and can never silently diverge.
    manifest.merkle_root = merkle_root(repo.default_algo(), gather_snapshot_chunk_digests(repo, manifest));
    manifest.entries_root = manifest_entries_root(repo.default_algo(), manifest.entries);

    Digest snapshot_digest = repo.objects().put(manifest.serialize()).digest;
    if (checkpoint) checkpoint();

    OperationEntry operation = append_operation(repo, snapshot_events::kCreated, snapshot_digest.to_string());
    if (checkpoint) checkpoint();

    return {snapshot_digest, stats, operation};
}

namespace {

// Which snapshots exist, derived from the operations log in one pass.
// Every catalog question (list, restore's tombstone check, delete's
// validity checks) is answered from this one derivation, so they can't
// disagree with each other.
//
// Semantics, deliberately:
//   * Deletion is permanent. A tombstoned digest stays deleted even if a
//     later snapshot_created event for the same digest appears (identical
//     content backed up again within the same second yields the same
//     manifest digest).
//   * A digest created more than once is listed once, at its first
//     creation.
//   * Events whose data isn't a parseable digest are ignored.
struct SnapshotCatalog {
    std::vector<SnapshotListEntry> live; // log order
    std::unordered_set<Digest> created;
    std::unordered_set<Digest> deleted;

    static SnapshotCatalog from_log(const std::vector<OperationEntry>& ops) {
        SnapshotCatalog catalog;
        for (const auto& op : ops) {
            if (op.event_type != snapshot_events::kDeleted) continue;
            if (auto d = Digest::parse(op.event_data)) catalog.deleted.insert(*d);
        }
        for (const auto& op : ops) {
            if (op.event_type != snapshot_events::kCreated) continue;
            auto d = Digest::parse(op.event_data);
            if (!d) continue;
            bool first_creation = catalog.created.insert(*d).second;
            if (first_creation && !catalog.deleted.count(*d)) catalog.live.push_back({op.timestamp, *d});
        }
        return catalog;
    }
};

} // namespace

void restore_snapshot(const Repo& repo, const Digest& snapshot_digest, const fs::path& dest_root) {
    if (SnapshotCatalog::from_log(read_operations(repo)).deleted.count(snapshot_digest)) {
        throw std::runtime_error("cannot restore a deleted snapshot: " + snapshot_digest.to_string());
    }

    auto manifest = Manifest::deserialize(repo.objects().get(snapshot_digest));
    if (!manifest) {
        throw std::runtime_error("failed to parse snapshot manifest: " + snapshot_digest.to_string());
    }

    // Create every directory before writing any file, so a file nested
    // several levels deep always has somewhere to land regardless of
    // manifest entry order.
    for (const auto& e : manifest->entries) {
        if (!e.is_directory) continue;
        std::error_code ec;
        fs::create_directories(dest_root / e.relative_path, ec);
        if (ec) {
            throw std::runtime_error("failed to create directory: " + (dest_root / e.relative_path).string());
        }
    }

    for_each_file_chunk_list(repo, *manifest, [&](const ManifestEntry& e, const ChunkList& chunk_list) {
        fs::path target = dest_root / e.relative_path;
        fs::create_directories(target.parent_path());

        std::vector<uint8_t> file_data;
        file_data.reserve(chunk_list.total_size);
        for (const auto& chunk : chunk_list.chunks) {
            auto chunk_bytes = repo.objects().get(chunk.digest); // re-verified against its own hash
            file_data.insert(file_data.end(), chunk_bytes.begin(), chunk_bytes.end());
        }

        write_file(target, file_data);
    });

    // Permissions are applied last: setting a restrictive directory mode
    // before its files are written would block writing into it.
    for (const auto& e : manifest->entries) {
        fs::permissions(dest_root / e.relative_path, static_cast<fs::perms>(e.mode), fs::perm_options::replace);
    }
}

std::vector<SnapshotListEntry> list_snapshots(const Repo& repo) {
    return SnapshotCatalog::from_log(read_operations(repo)).live;
}

void delete_snapshot(Repo& repo, const Digest& snapshot_digest) {
    auto catalog = SnapshotCatalog::from_log(read_operations(repo));
    std::string text = snapshot_digest.to_string();

    if (!catalog.created.count(snapshot_digest)) {
        throw std::runtime_error("no such snapshot: " + text);
    }
    if (catalog.deleted.count(snapshot_digest)) {
        throw std::runtime_error("snapshot already deleted: " + text);
    }

    append_operation(repo, snapshot_events::kDeleted, text);
}

VerifySnapshotResult verify_snapshot(const Repo& repo, const Digest& snapshot_digest) {
    Manifest manifest;
    try {
        auto parsed = Manifest::deserialize(repo.objects().get(snapshot_digest));
        if (!parsed) {
            return {false, 0, "failed to parse snapshot manifest"};
        }
        manifest = *parsed;
    } catch (const std::exception& e) {
        return {false, 0, std::string("failed to fetch manifest: ") + e.what()};
    }

    // Same walk (and therefore same leaf order) as creation, plus a fetch
    // of every chunk's actual content -- that fetch is what makes this a
    // real verification rather than a metadata check.
    std::vector<Digest> leaves;
    std::size_t chunks_checked = 0;
    try {
        for_each_file_chunk_list(repo, manifest, [&](const ManifestEntry&, const ChunkList& list) {
            for (const auto& c : list.chunks) {
                repo.objects().get(c.digest); // throws on missing/corrupt; bytes discarded, only the check matters
                leaves.push_back(c.digest);
                ++chunks_checked;
            }
        });
    } catch (const std::exception& e) {
        return {false, chunks_checked, std::string("object verification failed: ") + e.what()};
    }

    Digest recomputed = merkle_root(repo.default_algo(), leaves);
    if (recomputed != manifest.merkle_root) {
        return {false, chunks_checked, "recomputed merkle root does not match the manifest's recorded root"};
    }
    if (manifest.format_version >= 3 &&
        manifest_entries_root(repo.default_algo(), manifest.entries) != manifest.entries_root) {
        return {false, chunks_checked, "recomputed entries root does not match the manifest's recorded root"};
    }

    return {true, chunks_checked, "ok"};
}

std::optional<MerkleInclusionProof> prove_chunk_inclusion(const Repo& repo, const Digest& snapshot_digest,
                                                           const Digest& chunk_digest) {
    auto manifest = Manifest::deserialize(repo.objects().get(snapshot_digest));
    if (!manifest) {
        throw std::runtime_error("failed to parse snapshot manifest: " + snapshot_digest.to_string());
    }

    auto leaves = gather_snapshot_chunk_digests(repo, *manifest);
    auto it = std::find(leaves.begin(), leaves.end(), chunk_digest);
    if (it == leaves.end()) {
        return std::nullopt;
    }
    std::size_t index = static_cast<std::size_t>(it - leaves.begin());

    MerkleInclusionProof proof;
    proof.root = manifest->merkle_root;
    proof.leaf = chunk_digest;
    proof.leaf_index = index;
    proof.leaf_count = leaves.size();
    proof.path = merkle_path(repo.default_algo(), leaves, index);
    return proof;
}
