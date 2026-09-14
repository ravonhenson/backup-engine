# Backup Engine

A content-addressed backup engine written from scratch in C++, with
deduplication, crash-safety, immutability, and cryptographically
verifiable restores. Snapshot-based (not continuous data protection).

## Features

- Content-addressable object store (SHA-256) with corruption detection on every read
- Snapshot backup/restore preserving directory structure and file permissions
- Content-defined chunking (FastCDC) for deduplication across file versions
- Tamper-evident, hash-chained operations log with an explicit audit command
- Crash-safe writes throughout the commit path
- Snapshot deletion (tombstone-based, underlying data never silently destroyed)
- Merkle-tree-based snapshot verification and offline-verifiable inclusion proofs

## Building and running

Requires CMake ≥ 3.20 and a C++17 compiler.

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## CLI

```sh
backup_engine init <repo>
backup_engine put <repo> <file>
backup_engine get <repo> <digest> <output-file>
backup_engine verify <repo> <digest>

backup_engine backup <repo> <source-dir>
backup_engine restore <repo> <snapshot-digest> <dest-dir>
backup_engine snapshots <repo>
backup_engine delete <repo> <snapshot-digest>

backup_engine verify-log <repo>
backup_engine verify-snapshot <repo> <snapshot-digest>
backup_engine prove <repo> <snapshot-digest> <chunk-digest> <proof-output-file>
backup_engine verify-proof <proof-file>
```

## Example

```sh
./build/backup_engine init /tmp/repo
mkdir -p /tmp/src
echo "hello" > /tmp/src/f.txt

SNAP=$(./build/backup_engine backup /tmp/repo /tmp/src)
./build/backup_engine restore /tmp/repo "$SNAP" /tmp/dest
diff -r /tmp/src /tmp/dest

./build/backup_engine snapshots /tmp/repo
./build/backup_engine verify-log /tmp/repo
./build/backup_engine verify-snapshot /tmp/repo "$SNAP"
```
