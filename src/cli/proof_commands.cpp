#include <iostream>

#include "cli/command.h"
#include "crypto/merkle.h"
#include "snapshot/snapshot.h"
#include "util/fs_util.h"

namespace {

int cmd_prove(const Invocation& in) {
    auto proof = prove_chunk_inclusion(in.repo(), parse_digest_arg(in.arg(0)), parse_digest_arg(in.arg(1)));
    if (!proof) {
        std::cerr << "error: chunk is not part of that snapshot\n";
        return 1;
    }
    write_file(in.arg(2), proof->serialize());
    std::cout << "wrote proof to " << in.arg(2) << " (" << proof->path.size() << " path elements)\n";
    return 0;
}

int cmd_verify_proof(const Invocation& in) {
    auto proof = MerkleInclusionProof::deserialize(read_file(in.arg(0)));
    if (!proof) {
        std::cout << "FAILED (could not parse proof file)\n";
        return 1;
    }
    if (!merkle_verify_inclusion(*proof)) {
        std::cout << "FAILED\n";
        return 1;
    }
    std::cout << "OK (chunk " << proof->leaf.to_string() << " included in root " << proof->root.to_string()
              << ")\n";
    return 0;
}

} // namespace

CommandGroup proof_commands() {
    return {"proofs",
            {
                {"prove", true, {"<snapshot-digest>", "<chunk-digest>", "<proof-output-file>"},
                 "Write a Merkle inclusion proof for one chunk of a snapshot", cmd_prove},
                {"verify-proof", false, {"<proof-file>"}, "Check a proof file (no repo needed)", cmd_verify_proof},
            }};
}
