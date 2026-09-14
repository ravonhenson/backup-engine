#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "repo.h"

namespace {

std::vector<uint8_t> read_file(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) {
        throw std::runtime_error("cannot open file: " + p.string());
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

void write_file(const std::filesystem::path& p, const std::vector<uint8_t>& data) {
    std::ofstream f(p, std::ios::binary);
    if (!f) {
        throw std::runtime_error("cannot open file for write: " + p.string());
    }
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

void print_usage() {
    std::cerr << "usage:\n"
              << "  backup_engine init <repo>\n"
              << "  backup_engine put <repo> <file>\n"
              << "  backup_engine get <repo> <digest> <output-file>\n"
              << "  backup_engine verify <repo> <digest>\n";
}

Digest parse_digest_arg(const std::string& text) {
    auto digest = Digest::parse(text);
    if (!digest) {
        throw std::runtime_error("invalid digest (expected \"algo:hex\", e.g. sha256:...): " + text);
    }
    return *digest;
}

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);

    try {
        if (args.empty()) {
            print_usage();
            return 1;
        }

        const std::string& cmd = args[0];

        if (cmd == "init" && args.size() == 2) {
            Repo::init(args[1]);
            std::cout << "initialized repo at " << args[1] << "\n";
            return 0;
        }

        if (cmd == "put" && args.size() == 3) {
            Repo repo = Repo::open(args[1]);
            auto data = read_file(args[2]);
            Digest digest = repo.objects().put(data);
            std::cout << digest.to_string() << "\n";
            return 0;
        }

        if (cmd == "get" && args.size() == 4) {
            Repo repo = Repo::open(args[1]);
            Digest digest = parse_digest_arg(args[2]);
            auto data = repo.objects().get(digest);
            write_file(args[3], data);
            return 0;
        }

        if (cmd == "verify" && args.size() == 3) {
            Repo repo = Repo::open(args[1]);
            Digest digest = parse_digest_arg(args[2]);
            try {
                repo.objects().get(digest);
                std::cout << "OK\n";
                return 0;
            } catch (const std::exception&) {
                std::cout << "FAILED\n";
                return 1;
            }
        }

        print_usage();
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
