#pragma once

#include <filesystem>

#include "object_store.h"

// Owns a repo's on-disk root: the objects directory and a small config
// file declaring the format version and default write algorithm, so a
// future format change has somewhere to be declared instead of being
// silently assumed.
class Repo {
public:
    static Repo init(const std::filesystem::path& root);
    static Repo open(const std::filesystem::path& root);

    ObjectStore& objects() { return object_store_; }
    const ObjectStore& objects() const { return object_store_; }
    const std::filesystem::path& root() const { return root_; }
    HashAlgo default_algo() const { return default_algo_; }

private:
    Repo(std::filesystem::path root, HashAlgo default_algo);

    std::filesystem::path root_;
    HashAlgo default_algo_;
    ObjectStore object_store_;
};
