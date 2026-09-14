#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "fs_util.h"
#include "merkle.h"
#include "oplog.h"
#include "repo.h"
#include "snapshot.h"

namespace {

void print_usage() {
    std::cerr << "usage:\n"
              << "  backup_engine init <repo>\n"
              << "  backup_engine put <repo> <file>\n"
              << "  backup_engine get <repo> <digest> <output-file>\n"
              << "  backup_engine verify <repo> <digest>\n"
              << "  backup_engine backup <repo> <source-dir>\n"
              << "  backup_engine restore <repo> <snapshot-digest> <dest-dir>\n"
              << "  backup_engine snapshots <repo>\n"
              << "  backup_engine verify-log <repo>\n"
              << "  backup_engine delete <repo> <snapshot-digest>\n"
              << "  backup_engine verify-snapshot <repo> <snapshot-digest>\n"
              << "  backup_engine prove <repo> <snapshot-digest> <chunk-digest> <proof-output-file>\n"
              << "  backup_engine verify-proof <proof-file>   (no repo needed)\n";
}

Digest parse_digest_arg(const std::string& text) {
    auto digest = Digest::parse(text);
    if (!digest) {
        throw std::runtime_error("invalid digest (expected \"algo:hex\", e.g. sha256:...): " + text);
    }
    return *digest;
}

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);

    try {
        if (args.empty()) {
            print_usage();
            return 1;
        }

        const std::string& cmd = args[0];

        if (cmd == "init" && args.size() == 2) {
            Repo::init(args[1]);
            std::cout << "initialized repo at " << args[1] << "\n";
            return 0;
        }

        if (cmd == "put" && args.size() == 3) {
            Repo repo = Repo::open(args[1]);
            auto data = read_file(args[2]);
            PutResult result = repo.objects().put(data);
            std::cout << result.digest.to_string() << "\n";
            return 0;
        }

        if (cmd == "get" && args.size() == 4) {
            Repo repo = Repo::open(args[1]);
            Digest digest = parse_digest_arg(args[2]);
            auto data = repo.objects().get(digest);
            write_file(args[3], data);
            return 0;
        }

        if (cmd == "verify" && args.size() == 3) {
            Repo repo = Repo::open(args[1]);
            Digest digest = parse_digest_arg(args[2]);
            try {
                repo.objects().get(digest);
                std::cout << "OK\n";
                return 0;
            } catch (const std::exception&) {
                std::cout << "FAILED\n";
                return 1;
            }
        }

        if (cmd == "backup" && args.size() == 3) {
            Repo repo = Repo::open(args[1]);
            SnapshotResult result = create_snapshot(repo, args[2]);
            std::cerr << result.stats.total_files << " files, " << result.stats.total_chunks << " chunks, "
                      << result.stats.new_chunks << " new, "
                      << (result.stats.total_chunks - result.stats.new_chunks) << " deduplicated\n";
            std::cerr << "operations log head: " << result.operation.entry_hash.to_string() << " at seq "
                      << result.operation.seq << "\n";
            std::cout << result.digest.to_string() << "\n";
            return 0;
        }

        if (cmd == "restore" && args.size() == 4) {
            Repo repo = Repo::open(args[1]);
            Digest snapshot_digest = parse_digest_arg(args[2]);
            restore_snapshot(repo, snapshot_digest, args[3]);
            return 0;
        }

        if (cmd == "snapshots" && args.size() == 2) {
            Repo repo = Repo::open(args[1]);
            for (const auto& entry : list_snapshots(repo)) {
                std::cout << entry.created_at << " " << entry.digest.to_string() << "\n";
            }
            return 0;
        }

        if (cmd == "delete" && args.size() == 3) {
            Repo repo = Repo::open(args[1]);
            Digest snapshot_digest = parse_digest_arg(args[2]);
            delete_snapshot(repo, snapshot_digest);
            std::cout << "deleted " << snapshot_digest.to_string() << "\n";
            return 0;
        }

        if (cmd == "verify-log" && args.size() == 2) {
            Repo repo = Repo::open(args[1]);
            VerifyLogResult result = verify_operations_log(repo);
            if (result.ok) {
                std::cout << "OK (" << result.entries_checked << " entries)\n";
                return 0;
            }
            std::cout << "FAILED at seq " << (result.first_bad_seq ? std::to_string(*result.first_bad_seq) : "?")
                       << ": " << result.message << "\n";
            return 1;
        }

        if (cmd == "verify-snapshot" && args.size() == 3) {
            Repo repo = Repo::open(args[1]);
            Digest snapshot_digest = parse_digest_arg(args[2]);
            VerifySnapshotResult result = verify_snapshot(repo, snapshot_digest);
            if (result.ok) {
                std::cout << "OK (" << result.chunks_checked << " chunks checked)\n";
                return 0;
            }
            std::cout << "FAILED after " << result.chunks_checked << " chunks: " << result.message << "\n";
            return 1;
        }

        if (cmd == "prove" && args.size() == 5) {
            Repo repo = Repo::open(args[1]);
            Digest snapshot_digest = parse_digest_arg(args[2]);
            Digest chunk_digest = parse_digest_arg(args[3]);
            auto proof = prove_chunk_inclusion(repo, snapshot_digest, chunk_digest);
            if (!proof) {
                std::cerr << "error: chunk is not part of that snapshot\n";
                return 1;
            }
            write_file(args[4], proof->serialize());
            std::cout << "wrote proof to " << args[4] << " (" << proof->path.size() << " path elements)\n";
            return 0;
        }

        if (cmd == "verify-proof" && args.size() == 2) {
            auto data = read_file(args[1]);
            auto proof = MerkleInclusionProof::deserialize(data);
            if (!proof) {
                std::cout << "FAILED (could not parse proof file)\n";
                return 1;
            }
            if (merkle_verify_inclusion(*proof)) {
                std::cout << "OK (chunk " << proof->leaf.to_string() << " included in root "
                          << proof->root.to_string() << ")\n";
                return 0;
            }
            std::cout << "FAILED\n";
            return 1;
        }

        print_usage();
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
