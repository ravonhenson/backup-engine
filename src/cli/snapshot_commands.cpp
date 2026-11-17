#include <iostream>

#include "cli/command.h"
#include "snapshot/snapshot.h"

namespace {

int cmd_backup(const Invocation& in) {
    SnapshotResult result = create_snapshot(in.repo(), in.arg(0));
    const auto& s = result.stats;
    std::cerr << s.total_files << " files, " << s.total_chunks << " chunks, " << s.new_chunks << " new, "
              << (s.total_chunks - s.new_chunks) << " deduplicated\n";
    std::cerr << "operations log head: " << result.operation.entry_hash.to_string() << " at seq "
              << result.operation.seq << "\n";
    std::cout << result.digest.to_string() << "\n";
    return 0;
}

int cmd_restore(const Invocation& in) {
    restore_snapshot(in.repo(), parse_digest_arg(in.arg(0)), in.arg(1));
    return 0;
}

int cmd_snapshots(const Invocation& in) {
    for (const auto& entry : list_snapshots(in.repo())) {
        std::cout << entry.created_at << " " << entry.digest.to_string() << "\n";
    }
    return 0;
}

int cmd_delete(const Invocation& in) {
    Digest snapshot = parse_digest_arg(in.arg(0));
    delete_snapshot(in.repo(), snapshot);
    std::cout << "deleted " << snapshot.to_string() << "\n";
    return 0;
}

int cmd_verify_snapshot(const Invocation& in) {
    VerifySnapshotResult result = verify_snapshot(in.repo(), parse_digest_arg(in.arg(0)));
    if (result.ok) {
        std::cout << "OK (" << result.chunks_checked << " chunks checked)\n";
        return 0;
    }
    std::cout << "FAILED after " << result.chunks_checked << " chunks: " << result.message << "\n";
    return 1;
}

} // namespace

CommandGroup snapshot_commands() {
    return {"snapshots",
            {
                {"backup", true, {"<source-dir>"}, "Snapshot a directory; prints the snapshot ID and the log head",
                 cmd_backup},
                {"restore", true, {"<snapshot-digest>", "<dest-dir>"}, "Restore a snapshot into a new directory",
                 cmd_restore},
                {"snapshots", true, {}, "List live snapshots", cmd_snapshots},
                {"delete", true, {"<snapshot-digest>"}, "Tombstone a snapshot (no data is removed)", cmd_delete},
                {"verify-snapshot", true, {"<snapshot-digest>"},
                 "Re-hash every chunk and recompute the Merkle root, without restoring", cmd_verify_snapshot},
            }};
}
