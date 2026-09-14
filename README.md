# Backup Engine

A content-addressed backup engine, built from scratch in C++. This is a portfolio
project aimed at cyber-resilience / data-protection companies (Rubrik, Eon, and
similar) — the goal is to demonstrate the specific engineering problems that
space actually cares about: deduplication, crash-safety, immutability, and
restores you can *prove* are correct, not just claim are correct.

It's snapshot-based (not continuous data protection), and it's built in
layers — each layer has to restore data correctly before the next one begins.

## Why this project is shaped the way it is

"Content-addressed, deduplicated, immutable, crash-safe" is table-stakes
marketing language for every vendor in this space today. To be worth more
than a skim, this project deliberately concentrates its depth into two
features that most vendors don't genuinely offer, rather than spreading
effort evenly across everything:

1. **Cryptographically verifiable restore proofs** — a Merkle tree over
   chunk digests lets the engine prove a snapshot is fully reconstructable
   *without doing a full restore*, using inclusion/consistency proofs (the
   same primitive Certificate Transparency logs use). Most vendors' "tested
   recoverability" claims amount to "we booted a VM and it powered on" —
   this is a mathematical guarantee instead.
2. **Tamper-evident, hash-chained operations log** — an append-only,
   Certificate-Transparency-style log of every repo event (snapshot
   created, snapshot deleted, retention changed). Ransomware operators
   specifically target backup consoles first, to disable recovery before
   detonating a payload. A hash-chained log makes that kind of history
   rewriting cryptographically detectable, independent of trusting the tool
   that wrote the log.

Everything *outside* those two features is deliberately kept simple and easy
to explain rather than maximally sophisticated — the goal is for the depth
budget to go where it's actually differentiating.

## Status

**Layer 1 (content-addressable object store) is done.** Everything else
below is roadmap, not yet built.

| Layer | What it adds | Status |
|---|---|---|
| 1 | Content-addressable object store (CAS) | ✅ Done |
| 2 | File-level snapshot manifests + restore | Planned |
| 2.5 | Tamper-evident hash-chained operations log (**differentiator #2**) | Planned |
| 3 | Content-defined chunking (FastCDC) + dedup | Planned |
| 4 | Crash-safety hardening (staged commits, crash-injection tests) | Planned |
| 5 | Immutability enforcement (tombstone deletes, read-only enforcement) | Planned |
| 6 | Verifiable restore proofs via Merkle tree (**differentiator #1**) | Planned |
| Later | Algorithm migration demo (BLAKE3), erasure-coded self-healing, deterministic crash-injection harness, cross-snapshot diff | Deferred |

## Layer 1: the content-addressable object store

Every object is identified by the hash of its own content, not by a path
someone chose. Store the same bytes twice and you get the same address —
that's the object store's dedup and immutability mechanism in one property.

- **Self-describing digests.** A `Digest` carries its algorithm tag
  alongside the hash bytes, so a second hash algorithm can be added later
  (behind the `IHasher` interface) without breaking anything already
  written. SHA-256 is the only algorithm implemented today — chosen over
  BLAKE3 deliberately, because it's universally recognized and
  independently verifiable with a command everyone already has
  (`shasum -a 256`), and the choice doesn't affect either differentiator
  above.
- **On-disk layout:** `objects/<algo>/<xx>/<rest-of-hex>`, namespaced by
  algorithm so digests from different algorithms can never collide on the
  same path.
- **Crash-safe writes:** every object is written to a temp file, `fsync`'d,
  then atomically `rename()`'d into place — a partial write can never be
  observed as a valid object.
- **Corruption detection on every read:** `get()` recomputes the hash of
  what it read and verifies it against the requested digest before
  returning anything. Silent bit rot fails loudly instead of returning bad
  data.
- **Immutable by construction:** objects are written read-only (`0444`) on
  disk, and writing content that already exists is a no-op rather than an
  overwrite.

### A note on the vendored SHA-256 implementation

`third_party/sha256/` is a small, self-contained SHA-256 implementation
(FIPS 180-4), written by hand rather than pulled from a package manager, to
keep the dependency story simple. It follows the structure of the
well-known public-domain reference implementation commonly attributed to
Brad Conte's `crypto-algorithms` — the same `SHA256_CTX` layout, macro
names, and round-constant table that's been reproduced across countless
open-source projects. The round constants and initial state values are
mandated byte-for-byte by the FIPS 180-4 spec regardless of implementation,
so that part is the algorithm, not a stylistic choice. Correctness is
checked against known SHA-256 test vectors in the unit tests, and manually
cross-verified against the system's own `shasum -a 256` output.

## Building and running

Requires CMake ≥ 3.20 and a C++17 compiler.

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

### CLI

```sh
./build/backup_engine init <repo>
./build/backup_engine put <repo> <file>              # prints a digest, e.g. sha256:9f86d0...
./build/backup_engine get <repo> <digest> <output>
./build/backup_engine verify <repo> <digest>          # OK or FAILED
```

Example:

```sh
./build/backup_engine init /tmp/repo
echo "hello" > /tmp/f.txt
DIGEST=$(./build/backup_engine put /tmp/repo /tmp/f.txt)
./build/backup_engine get /tmp/repo "$DIGEST" /tmp/out.txt
diff /tmp/f.txt /tmp/out.txt   # identical
shasum -a 256 /tmp/f.txt       # matches $DIGEST exactly
```
