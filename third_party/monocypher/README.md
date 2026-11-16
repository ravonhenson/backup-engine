# Monocypher (vendored)

Used for Ed25519 signatures on operations-log checkpoints. Unmodified.

- **Version:** 4.0.2
- **Source:** https://monocypher.org/download/monocypher-4.0.2.tar.gz
- **Licence:** used under **CC-0** (public-domain dedication). Monocypher
  is dual-licensed CC-0 / 2-clause BSD and lets the user choose; this
  project chooses CC-0. `LICENCE.md` is kept unmodified for reference.

## Files

Copied flat from the release tarball (the library's own `#include`s use
bare filenames, so no edits were needed):

| File | From tarball | SHA-256 |
|---|---|---|
| `monocypher.c` | `src/` | `afe2b098c8569577a84488e0b98d276d1fba6506adea68bb9241a52111734c59` |
| `monocypher.h` | `src/` | `f78bb31255cfb7beba66afd2137f5194c8a025cf40488b6cc1e295234d43f374` |
| `monocypher-ed25519.c` | `src/optional/` | `7c9b16056cbd27521919e8a6f56a228808b9e718afc42e3d33f28c08e5abdee2` |
| `monocypher-ed25519.h` | `src/optional/` | `bd546edcd468d64e28caa3dbf4b1d6bfad7435c0ce994723fd81aae26405121b` |
| `LICENCE.md` | top level | `5f8360e4c06ddcc584bdb4b210c6af824c4bb301e6a9a521869b6d90795ca4b3` |

## Why `monocypher-ed25519` and not core Monocypher's signatures

Core Monocypher's `crypto_eddsa_*` functions use BLAKE2b internally, which
is *not* the standard Ed25519. The optional `crypto_ed25519_*` functions
implement RFC 8032 Ed25519 (with SHA-512), so signatures can be checked
by any standard tool (OpenSSL, libsodium, Python `cryptography`, ...).
`tests/test_ed25519.cpp` checks them against the RFC 8032 test vectors.

## Provenance check performed when vendoring

The same tag was also downloaded from GitHub
(`LoupVaillant/Monocypher/archive/refs/tags/4.0.2.tar.gz`) and compared.
The only differences: line 1 of each source file reads
`// Monocypher version __git__` in the GitHub archive versus
`// Monocypher version 4.0.2` in the release (the release script fills in
the version), and the GitHub `LICENCE.md` has an extra note about its
`tests/externals/` directory, which isn't part of the release. The code
is identical.

## Updating

Replace the five files from a new release tarball, update the table
above, and rerun the test suite.
