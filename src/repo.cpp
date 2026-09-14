#include "repo.h"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

#include "fs_util.h"

namespace fs = std::filesystem;

namespace {

constexpr int kFormatVersion = 1;
constexpr const char* kConfigFileName = "repo.conf";

std::unordered_map<std::string, std::string> read_config(const fs::path& path) {
    std::ifstream f(path);
    if (!f) {
        throw std::runtime_error("cannot open repo config: " + path.string());
    }
    std::unordered_map<std::string, std::string> kv;
    std::string line;
    while (std::getline(f, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        kv[line.substr(0, eq)] = line.substr(eq + 1);
    }
    return kv;
}

} // namespace

Repo::Repo(fs::path root, HashAlgo default_algo)
    : root_(std::move(root)),
      default_algo_(default_algo),
      object_store_(root_ / "objects", default_algo) {}

Repo Repo::init(const fs::path& root) {
    std::error_code ec;
    fs::create_directories(root / "objects", ec);
    if (ec) {
        throw std::runtime_error("failed to create repo at " + root.string() + ": " + ec.message());
    }

    std::ostringstream conf;
    conf << "format_version=" << kFormatVersion << "\n";
    conf << "default_algo=sha256\n";
    std::string s = conf.str();
    // Atomic + fsync'd: a crash right after init() returns (or even a
    // clean process exit before the OS flushes an unsynced write) must
    // never leave a truncated repo.conf that Repo::open() can't parse --
    // that would permanently brick the repo before it's ever used.
    write_file_atomically(root / kConfigFileName, std::vector<uint8_t>(s.begin(), s.end()));

    return Repo(root, HashAlgo::SHA256);
}

Repo Repo::open(const fs::path& root) {
    auto kv = read_config(root / kConfigFileName);

    auto version_it = kv.find("format_version");
    if (version_it == kv.end() || std::stoi(version_it->second) != kFormatVersion) {
        throw std::runtime_error("unsupported or missing repo format_version at " + root.string());
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
