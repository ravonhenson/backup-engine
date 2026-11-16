#include "storage/repo.h"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

#include "util/fs_util.h"
#include "util/text_format.h"

namespace fs = std::filesystem;

namespace {

constexpr uint64_t kFormatVersion = 1;
constexpr const char* kConfigFileName = "repo.conf";

std::unordered_map<std::string, std::string> read_config(const fs::path& path) {
    std::ifstream f(path);
    if (!f) {
        throw std::runtime_error("cannot open repo config: " + path.string());
    }
    std::unordered_map<std::string, std::string> kv;
    std::string line;
    while (std::getline(f, line)) {
        if (auto pair = split_key_value(line)) kv[std::string(pair->first)] = std::string(pair->second);
    }
    return kv;
}

} // namespace

Repo::Repo(fs::path root, HashAlgo default_algo)
    : root_(std::move(root)),
      default_algo_(default_algo),
      object_store_(root_ / "objects", default_algo) {}

Repo Repo::init(const fs::path& root) {
    try {
        create_directories_durably(root / "objects");
    } catch (const std::exception& e) {
        throw std::runtime_error("failed to create repo at " + root.string() + ": " + e.what());
    }

    std::ostringstream conf;
    conf << "format_version=" << kFormatVersion << "\n";
    conf << "default_algo=sha256\n";
    std::string s = conf.str();
    // Atomic + fsync'd: a crash right after init() returns (or even a
    // clean process exit before the OS flushes an unsynced write) must
    // never leave a truncated repo.conf that Repo::open() can't parse --
    // that would permanently brick the repo before it's ever used.
    write_file_atomically(root / kConfigFileName, reinterpret_cast<const uint8_t*>(s.data()), s.size());
    // Init is a commit point: flush through the drive cache too (see the
    // durability model in fs_util.h).
    sync_barrier_path(root);

    return Repo(root, HashAlgo::SHA256);
}

Repo Repo::open(const fs::path& root) {
    auto kv = read_config(root / kConfigFileName);

    auto version_it = kv.find("format_version");
    if (version_it == kv.end()) {
        throw std::runtime_error("repo config missing format_version at " + root.string());
    }
    auto version = parse_u64(version_it->second);
    if (!version || *version != kFormatVersion) {
        throw std::runtime_error("unsupported repo format_version \"" + version_it->second + "\" at " +
                                 root.string());
    }

    auto algo_it = kv.find("default_algo");
    if (algo_it == kv.end()) {
        throw std::runtime_error("repo config missing default_algo at " + root.string());
    }
    auto algo = Digest::algo_from_name(algo_it->second);
    if (!algo) {
        throw std::runtime_error("unknown default_algo in repo config: " + algo_it->second);
    }

    return Repo(root, *algo);
}
