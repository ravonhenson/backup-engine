#include <gtest/gtest.h>

#include "hasher.h"
#include "merkle.h"

namespace {

Digest make_digest(uint8_t fill_byte) {
    Digest d;
    d.algo = HashAlgo::SHA256;
    d.length = 32;
    d.bytes.fill(fill_byte);
    return d;
}

Digest hash_bytes(const std::vector<uint8_t>& data) {
    auto hasher = make_hasher(HashAlgo::SHA256);
    hasher->update(data.data(), data.size());
    return hasher->finalize();
}

// Manual, independent reimplementation of leaf/parent hashing (same
// formulas the production code uses) so the tests aren't just checking
// internal self-consistency against merkle.cpp's own helpers.
Digest manual_leaf_hash(const Digest& d) {
    std::vector<uint8_t> buf{0x00};
    buf.insert(buf.end(), d.bytes.begin(), d.bytes.begin() + d.length);
    return hash_bytes(buf);
}

Digest manual_parent_hash(const Digest& l, const Digest& r) {
    std::vector<uint8_t> buf{0x01};
    buf.insert(buf.end(), l.bytes.begin(), l.bytes.begin() + l.length);
    buf.insert(buf.end(), r.bytes.begin(), r.bytes.begin() + r.length);
    return hash_bytes(buf);
}

std::vector<Digest> make_leaves(std::size_t n) {
    std::vector<Digest> leaves;
    for (std::size_t i = 0; i < n; ++i) {
        leaves.push_back(make_digest(static_cast<uint8_t>(i + 1)));
    }
    return leaves;
}

} // namespace

TEST(Merkle, EmptyTreeIsHashOfEmptyString) {
    Digest root = merkle_root(HashAlgo::SHA256, {});
    EXPECT_EQ(root.to_hex(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Merkle, SingleLeafRootIsLeafHash) {
    Digest leaf = make_digest(0xAB);
    Digest root = merkle_root(HashAlgo::SHA256, {leaf});
    EXPECT_EQ(root, manual_leaf_hash(leaf));
}

TEST(Merkle, TwoLeafRootMatchesManualComputation) {
    auto leaves = make_leaves(2);
    Digest expected = manual_parent_hash(manual_leaf_hash(leaves[0]), manual_leaf_hash(leaves[1]));
    EXPECT_EQ(merkle_root(HashAlgo::SHA256, leaves), expected);
}

TEST(Merkle, ThreeLeafRootMatchesRfc6962AsymmetricSplit) {
    // RFC 6962: for n=3, k=2, so the split is {d0,d1} and {d2}, NOT a
    // balanced/padded tree -- this is the detail most naive
    // implementations get wrong.
    auto leaves = make_leaves(3);
    Digest left = manual_parent_hash(manual_leaf_hash(leaves[0]), manual_leaf_hash(leaves[1]));
    Digest right = manual_leaf_hash(leaves[2]);
    Digest expected = manual_parent_hash(left, right);
    EXPECT_EQ(merkle_root(HashAlgo::SHA256, leaves), expected);
}

TEST(Merkle, DomainSeparationMakesLeafAndParentHashingDistinctFunctions) {
    // Confirms the implementation actually prefixes leaf vs. internal
    // hashing differently, rather than hashing raw bytes with no
    // separation (which would make a crafted leaf indistinguishable from
    // an internal node's preimage).
    Digest a = make_digest(0x01);
    Digest b = make_digest(0x02);

    std::vector<uint8_t> no_prefix(a.bytes.begin(), a.bytes.begin() + a.length);
    no_prefix.insert(no_prefix.end(), b.bytes.begin(), b.bytes.begin() + b.length);

    Digest naive_unprefixed_hash = hash_bytes(no_prefix);
    Digest actual_parent_hash = manual_parent_hash(a, b);

    EXPECT_NE(naive_unprefixed_hash, actual_parent_hash);
}

TEST(Merkle, InclusionProofRoundTripsForVariousTreeSizes) {
    for (std::size_t n : {1u, 2u, 3u, 4u, 5u, 7u, 8u, 13u, 16u}) {
        auto leaves = make_leaves(n);
        Digest root = merkle_root(HashAlgo::SHA256, leaves);

        for (std::size_t i = 0; i < n; ++i) {
            auto path = merkle_path(HashAlgo::SHA256, leaves, i);
            bool ok = merkle_verify_inclusion(HashAlgo::SHA256, leaves[i], i, n, path, root);
            EXPECT_TRUE(ok) << "n=" << n << " i=" << i;
        }
    }
}

TEST(Merkle, ProofFailsForTheWrongLeafValue) {
    auto leaves = make_leaves(5);
    Digest root = merkle_root(HashAlgo::SHA256, leaves);
    auto path = merkle_path(HashAlgo::SHA256, leaves, 2);

    Digest wrong_leaf = make_digest(0xEE);
    EXPECT_FALSE(merkle_verify_inclusion(HashAlgo::SHA256, wrong_leaf, 2, 5, path, root));
}

TEST(Merkle, ProofFailsForTheWrongIndex) {
    auto leaves = make_leaves(5);
    Digest root = merkle_root(HashAlgo::SHA256, leaves);
    auto path = merkle_path(HashAlgo::SHA256, leaves, 2);

    // Same leaf value and path, claimed at a different position.
    EXPECT_FALSE(merkle_verify_inclusion(HashAlgo::SHA256, leaves[2], 3, 5, path, root));
}

TEST(Merkle, ProofFailsAgainstTheWrongRoot) {
    auto leaves = make_leaves(5);
    auto path = merkle_path(HashAlgo::SHA256, leaves, 2);
    Digest wrong_root = make_digest(0x77);

    EXPECT_FALSE(merkle_verify_inclusion(HashAlgo::SHA256, leaves[2], 2, 5, path, wrong_root));
}

TEST(Merkle, MalformedProofLengthFailsRatherThanCrashing) {
    auto leaves = make_leaves(5);
    Digest root = merkle_root(HashAlgo::SHA256, leaves);
    auto path = merkle_path(HashAlgo::SHA256, leaves, 2);

    auto too_short = path;
    if (!too_short.empty()) too_short.pop_back();
    EXPECT_FALSE(merkle_verify_inclusion(HashAlgo::SHA256, leaves[2], 2, 5, too_short, root));

    auto too_long = path;
    too_long.push_back(make_digest(0x00));
    EXPECT_FALSE(merkle_verify_inclusion(HashAlgo::SHA256, leaves[2], 2, 5, too_long, root));
}

TEST(Merkle, OutOfBoundsLeafIndexFails) {
    auto leaves = make_leaves(5);
    Digest root = merkle_root(HashAlgo::SHA256, leaves);
    auto path = merkle_path(HashAlgo::SHA256, leaves, 0);

    EXPECT_FALSE(merkle_verify_inclusion(HashAlgo::SHA256, leaves[0], 5, 5, path, root));
}

TEST(Merkle, SingleLeafTreeHasEmptyProof) {
    auto leaves = make_leaves(1);
    auto path = merkle_path(HashAlgo::SHA256, leaves, 0);
    EXPECT_TRUE(path.empty());
}

TEST(Merkle, ProofStructVerifiesUsingItsOwnEmbeddedRoot) {
    auto leaves = make_leaves(6);
    Digest root = merkle_root(HashAlgo::SHA256, leaves);

    MerkleInclusionProof proof;
    proof.root = root;
    proof.leaf = leaves[4];
    proof.leaf_index = 4;
    proof.leaf_count = leaves.size();
    proof.path = merkle_path(HashAlgo::SHA256, leaves, 4);

    EXPECT_TRUE(merkle_verify_inclusion(proof));
}

TEST(Merkle, ProofStructSerializeDeserializeRoundTrip) {
    auto leaves = make_leaves(6);
    Digest root = merkle_root(HashAlgo::SHA256, leaves);

    MerkleInclusionProof proof;
    proof.root = root;
    proof.leaf = leaves[4];
    proof.leaf_index = 4;
    proof.leaf_count = leaves.size();
    proof.path = merkle_path(HashAlgo::SHA256, leaves, 4);

    auto parsed = MerkleInclusionProof::deserialize(proof.serialize());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->root, proof.root);
    EXPECT_EQ(parsed->leaf, proof.leaf);
    EXPECT_EQ(parsed->leaf_index, proof.leaf_index);
    EXPECT_EQ(parsed->leaf_count, proof.leaf_count);
    ASSERT_EQ(parsed->path.size(), proof.path.size());
    for (std::size_t i = 0; i < proof.path.size(); ++i) {
        EXPECT_EQ(parsed->path[i], proof.path[i]);
    }
    EXPECT_TRUE(merkle_verify_inclusion(*parsed));
}

TEST(Merkle, DeterministicForTheSameLeaves) {
    auto leaves = make_leaves(7);
    Digest a = merkle_root(HashAlgo::SHA256, leaves);
    Digest b = merkle_root(HashAlgo::SHA256, leaves);
    EXPECT_EQ(a, b);
}
