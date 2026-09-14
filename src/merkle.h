#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "digest.h"

// RFC 6962 (Certificate Transparency) style Merkle Tree Hash, with domain
// separation between leaf and internal-node hashing (a 0x00 vs 0x01
// prefix byte) so a crafted leaf can never be mistaken for an internal
// node -- the exact ambiguity attack domain separation exists to close.
//
// "Leaves" here are digests of already-known data (e.g. chunk digests
// from a ChunkList), not raw content -- these functions apply the
// leaf-hash transform themselves, so callers never pre-hash.
//
// The tree is built over a possibly non-power-of-two leaf count using
// RFC 6962's recursive split (always at the largest power of two less
// than the current count), which is why this isn't a simple "pad to the
// next power of two" scheme.
//
// Efficiency note: this recomputes overlapping subtree hashes on each
// call rather than building the tree once and caching node values, which
// is O(n log n) instead of O(n). Fine at the leaf counts a single
// snapshot produces here; a production version handling very large trees
// would cache level-by-level instead.

// The Merkle root over `leaves`. An empty leaf list yields the hash of
// the empty string (RFC 6962's defined MTH({})).
Digest merkle_root(HashAlgo algo, const std::vector<Digest>& leaves);

// The audit path for leaves[leaf_index]: an ordered list of sibling
// subtree hashes, leaf-adjacent first and root-adjacent last, sufficient
// to recompute the root from that one leaf's value alone.
std::vector<Digest> merkle_path(HashAlgo algo, const std::vector<Digest>& leaves, std::size_t leaf_index);

// Verifies an inclusion proof using only the leaf's own data digest, its
// claimed position (leaf_index of leaf_count), the audit path, and the
// root to check against -- no access to the rest of the tree is needed.
// Returns false (never throws or crashes) for a structurally malformed
// proof, e.g. the wrong number of path elements for the claimed position.
bool merkle_verify_inclusion(HashAlgo algo, const Digest& leaf_data, std::size_t leaf_index, std::size_t leaf_count,
                              const std::vector<Digest>& path, const Digest& expected_root);

// A self-contained, portable inclusion proof: everything needed to
// verify it independently, with no access to the repo, the rest of the
// tree, or any other chunk -- this is the sublinear, offline-verifiable
// capability a Merkle tree adds that per-object hash verification alone
// doesn't provide.
struct MerkleInclusionProof {
    Digest root;
    Digest leaf;
    std::size_t leaf_index = 0;
    std::size_t leaf_count = 0;
    std::vector<Digest> path;

    std::vector<uint8_t> serialize() const;
    static std::optional<MerkleInclusionProof> deserialize(const std::vector<uint8_t>& data);
};

// Verifies a proof against its own embedded root -- the hash algorithm is
// taken from the leaf/root digests themselves. Returns false (rather
// than throwing) if leaf.algo and root.algo disagree, since that alone
// makes the proof nonsensical.
bool merkle_verify_inclusion(const MerkleInclusionProof& proof);
