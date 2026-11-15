#pragma once

#include <stdexcept>

// Error convention for the engine:
//   * Parsing our own on-disk formats returns std::optional.
//   * Audit/verification operations (verify_operations_log,
//     verify_snapshot, merkle_verify_inclusion) return a result, since
//     "it failed verification" is a normal answer, not an exception.
//   * Everything else throws. The two typed errors below exist so callers
//     can tell "missing" from "corrupt"; both derive from
//     std::runtime_error, so a generic catch still handles them.

// The requested object does not exist in the store.
struct ObjectNotFoundError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Data was read but does not match its expected hash -- corruption, bit
// rot, or tampering.
struct IntegrityError : std::runtime_error {
    using std::runtime_error::runtime_error;
};
