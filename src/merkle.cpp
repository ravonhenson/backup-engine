#include "merkle.h"

#include <optional>
#include <sstream>

#include "hasher.h"

namespace {

Digest merkle_leaf_hash(HashAlgo algo, const Digest& leaf_data) {
    auto hasher = make_hasher(algo);
    uint8_t prefix = 0x00;
    hasher->update(&prefix, 1);
    hasher->update(leaf_data.bytes.data(), leaf_data.length);
    return hasher->finalize();
}

Digest merkle_parent_hash(HashAlgo algo, const Digest& left, const Digest& right) {
    auto hasher = make_hasher(algo);
    uint8_t prefix = 0x01;
    hasher->update(&prefix, 1);
    hasher->update(left.bytes.data(), left.length);
    hasher->update(right.bytes.data(), right.length);
    return hasher->finalize();
}

Digest empty_tree_hash(HashAlgo algo) {
    return make_hasher(algo)->finalize(); // RFC 6962: MTH({}) = H()
}

// Largest power of two strictly less than n (n > 1).
std::size_t largest_pow2_less_than(std::size_t n) {
    std::size_t k = 1;
    while (k * 2 < n) k *= 2;
    return k;
}

// RFC 6962 MTH(D[begin:end)).
Digest mth(HashAlgo algo, const std::vector<Digest>& leaves, std::size_t begin, std::size_t end) {
    std::size_t n = end - begin;
    if (n == 0) return empty_tree_hash(algo);
    if (n == 1) return merkle_leaf_hash(algo, leaves[begin]);

    std::size_t k = largest_pow2_less_than(n);
    Digest left = mth(algo, leaves, begin, begin + k);
    Digest right = mth(algo, leaves, begin + k, end);
    return merkle_parent_hash(algo, left, right);
}

// RFC 6962 PATH(leaf_index, D[begin:end)), appended into `out`.
void path_recursive(HashAlgo algo, const std::vector<Digest>& leaves, std::size_t begin, std::size_t end,
                     std::size_t leaf_index, std::vector<Digest>& out) {
    std::size_t n = end - begin;
    if (n <= 1) return; // PATH(0, {d(0)}) = {}

    std::size_t k = largest_pow2_less_than(n);
    if (leaf_index < k) {
        path_recursive(algo, leaves, begin, begin + k, leaf_index, out);
        out.push_back(mth(algo, leaves, begin + k, end));
    } else {
        path_recursive(algo, leaves, begin + k, end, leaf_index - k, out);
        out.push_back(mth(algo, leaves, begin, begin + k));
    }
}

// Mirrors path_recursive's exact recursion so the same sibling consumed
// last during construction is consumed first during verification (the
// path is built inner-recursion-first, outer-sibling-appended-last, so
// reconstruction must consume from the end inward). Returns nullopt for
// a structurally malformed proof (wrong number of elements) rather than
// indexing out of bounds.
std::optional<Digest> recompute_root(HashAlgo algo, const Digest& leaf_hash, std::size_t m, std::size_t n,
                                      const std::vector<Digest>& path, std::size_t path_len) {
    if (n <= 1) {
        if (path_len != 0) return std::nullopt;
        return leaf_hash;
    }
    if (path_len == 0) return std::nullopt;

    std::size_t k = largest_pow2_less_than(n);
    const Digest& sibling = path[path_len - 1];

    if (m < k) {
        auto left = recompute_root(algo, leaf_hash, m, k, path, path_len - 1);
        if (!left) return std::nullopt;
        return merkle_parent_hash(algo, *left, sibling);
    }
    auto right = recompute_root(algo, leaf_hash, m - k, n - k, path, path_len - 1);
    if (!right) return std::nullopt;
    return merkle_parent_hash(algo, sibling, *right);
}

} // namespace

Digest merkle_root(HashAlgo algo, const std::vector<Digest>& leaves) {
    return mth(algo, leaves, 0, leaves.size());
}

std::vector<Digest> merkle_path(HashAlgo algo, const std::vector<Digest>& leaves, std::size_t leaf_index) {
    std::vector<Digest> out;
    path_recursive(algo, leaves, 0, leaves.size(), leaf_index, out);
    return out;
}

bool merkle_verify_inclusion(HashAlgo algo, const Digest& leaf_data, std::size_t leaf_index, std::size_t leaf_count,
                              const std::vector<Digest>& path, const Digest& expected_root) {
    if (leaf_index >= leaf_count) return false;

    Digest leaf_hash = merkle_leaf_hash(algo, leaf_data);
    auto recomputed = recompute_root(algo, leaf_hash, leaf_index, leaf_count, path, path.size());
    return recomputed.has_value() && *recomputed == expected_root;
}

bool merkle_verify_inclusion(const MerkleInclusionProof& proof) {
    if (proof.leaf.algo != proof.root.algo) return false;
    return merkle_verify_inclusion(proof.leaf.algo, proof.leaf, proof.leaf_index, proof.leaf_count, proof.path,
                                    proof.root);
}

std::vector<uint8_t> MerkleInclusionProof::serialize() const {
    std::ostringstream out;
    out << "format_version=1\n";
    out << "root=" << root.to_string() << "\n";
    out << "leaf=" << leaf.to_string() << "\n";
    out << "leaf_index=" << leaf_index << "\n";
    out << "leaf_count=" << leaf_count << "\n";
    for (const auto& step : path) {
        out << "path " << step.to_string() << "\n";
    }
    std::string s = out.str();
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::optional<MerkleInclusionProof> MerkleInclusionProof::deserialize(const std::vector<uint8_t>& data) {
    std::string text(data.begin(), data.end());
    std::istringstream in(text);
    std::string line;

    MerkleInclusionProof proof;
    bool have_version = false, have_root = false, have_leaf = false, have_index = false, have_count = false;

    while (std::getline(in, line)) {
        if (line.empty()) continue;

        if (line.rfind("path ", 0) == 0) {
            auto digest = Digest::parse(line.substr(5));
            if (!digest) return std::nullopt;
            proof.path.push_back(*digest);
            continue;
        }

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string value = line.substr(eq + 1);

        try {
            if (key == "format_version") {
                if (value != "1") return std::nullopt;
                have_version = true;
            } else if (key == "root") {
                auto digest = Digest::parse(value);
                if (!digest) return std::nullopt;
                proof.root = *digest;
                have_root = true;
            } else if (key == "leaf") {
                auto digest = Digest::parse(value);
                if (!digest) return std::nullopt;
                proof.leaf = *digest;
                have_leaf = true;
            } else if (key == "leaf_index") {
                proof.leaf_index = std::stoull(value);
                have_index = true;
            } else if (key == "leaf_count") {
                proof.leaf_count = std::stoull(value);
                have_count = true;
            }
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }

    if (!have_version || !have_root || !have_leaf || !have_index || !have_count) return std::nullopt;
    return proof;
}
