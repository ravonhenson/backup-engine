#include <iostream>

#include "cli/command.h"
#include "crypto/signing.h"
#include "log/checkpoint.h"
#include "log/oplog.h"

namespace {

int cmd_verify_log(const Invocation& in) {
    VerifyLogResult result = verify_operations_log(in.repo());
    if (result.ok) {
        std::cout << "OK (" << result.entries_checked << " entries)\n";
        return 0;
    }
    std::cout << "FAILED at seq " << (result.first_bad_seq ? std::to_string(*result.first_bad_seq) : "?") << ": "
              << result.message << "\n";
    return 1;
}

int cmd_head(const Invocation& in) {
    std::cout << current_checkpoint_statement(in.repo()).serialize();
    return 0;
}

int cmd_keygen(const Invocation& in) {
    SecretKey secret = SecretKey::generate();
    write_key_pair(secret, in.arg(0), in.arg(1));
    std::cout << secret.public_key().key_id() << "\n";
    return 0;
}

int cmd_sign_checkpoint(const Invocation& in) {
    auto key = SecretKey::parse(read_text_file(in.arg(0)));
    if (!key) throw std::runtime_error("not a valid secret key file: " + in.arg(0));

    auto statement = CheckpointStatement::parse(read_text_file(in.arg(1)));
    if (!statement) {
        throw std::runtime_error("not a valid checkpoint statement (must be exactly what `head` printed): " +
                                 in.arg(1));
    }
    std::cout << sign_checkpoint(*statement, *key).serialize();
    return 0;
}

int cmd_verify_checkpoint(const Invocation& in) {
    auto checkpoint = SignedCheckpoint::parse(read_text_file(in.arg(0)));
    if (!checkpoint) {
        std::cout << "FAILED (could not parse signed checkpoint file)\n";
        return 1;
    }
    auto trusted = PublicKey::parse(read_text_file(in.arg(1)));
    if (!trusted) throw std::runtime_error("not a valid public key file: " + in.arg(1));

    VerifyCheckpointResult result = verify_checkpoint(in.repo(), *checkpoint, *trusted);
    std::cout << (result.ok ? "OK: " : "FAILED: ") << result.message << "\n";
    return result.ok ? 0 : 1;
}

} // namespace

CommandGroup log_commands() {
    return {"operations log and checkpoints",
            {
                {"verify-log", true, {}, "Check the whole operations log hash chain", cmd_verify_log},
                {"head", true, {}, "Print a checkpoint statement for the current log, ready to sign", cmd_head},
                {"keygen", false, {"<secret-key-file>", "<public-key-file>"},
                 "Generate an Ed25519 signing key pair (no repo needed)", cmd_keygen},
                {"sign-checkpoint", false, {"<secret-key-file>", "<statement-file>"},
                 "Sign a statement printed by 'head' (no repo needed)", cmd_sign_checkpoint},
                {"verify-checkpoint", true, {"<checkpoint-file>", "<public-key-file>"},
                 "Check the log against a signed checkpoint and a trusted public key", cmd_verify_checkpoint},
            }};
}
