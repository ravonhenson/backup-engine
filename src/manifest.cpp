#include "manifest.h"

#include <sstream>

namespace {

// Splits exactly `n` leading whitespace-delimited fields off `line`,
// leaving the remainder (which may itself contain spaces, e.g. a file
// path) in `rest`. Returns false if there weren't enough fields.
bool split_fields(const std::string& line, int n, std::vector<std::string>& fields, std::string& rest) {
    fields.clear();
    std::size_t pos = 0;
    for (int i = 0; i < n; ++i) {
        std::size_t space = line.find(' ', pos);
        if (space == std::string::npos) return false;
        fields.push_back(line.substr(pos, space - pos));
        pos = space + 1;
    }
    rest = line.substr(pos);
    return true;
}

} // namespace

std::vector<uint8_t> Manifest::serialize() const {
    std::ostringstream out;
    out << "format_version=2\n";
    out << "created_at=" << created_at << "\n";
    out << "source_root=" << source_root << "\n";
    out << "merkle_root=" << merkle_root.to_string() << "\n";

    for (const auto& e : entries) {
        if (e.is_directory) {
            out << "D " << std::oct << e.mode << std::dec << " " << e.relative_path << "\n";
        } else {
            out << "F " << std::oct << e.mode << std::dec << " " << e.size << " "
                << e.digest.to_string() << " " << e.relative_path << "\n";
        }
    }

    std::string s = out.str();
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::optional<Manifest> Manifest::deserialize(const std::vector<uint8_t>& data) {
    std::string text(data.begin(), data.end());
    std::istringstream in(text);
    std::string line;

    Manifest m;
    bool have_version = false;
    bool have_merkle_root = false;

    while (std::getline(in, line)) {
        if (line.empty()) continue;

        if (line[0] == 'D') {
            std::vector<std::string> fields;
            std::string rest;
            if (!split_fields(line, 2, fields, rest)) return std::nullopt;

            ManifestEntry e;
            e.is_directory = true;
            try {
                e.mode = static_cast<uint32_t>(std::stoul(fields[1], nullptr, 8));
            } catch (const std::exception&) {
                return std::nullopt;
            }
            e.relative_path = rest;
            m.entries.push_back(std::move(e));
            continue;
        }

        if (line[0] == 'F') {
            std::vector<std::string> fields;
            std::string rest;
            if (!split_fields(line, 4, fields, rest)) return std::nullopt;

            ManifestEntry e;
            e.is_directory = false;
            try {
                e.mode = static_cast<uint32_t>(std::stoul(fields[1], nullptr, 8));
                e.size = std::stoull(fields[2]);
            } catch (const std::exception&) {
                return std::nullopt;
            }
            auto digest = Digest::parse(fields[3]);
            if (!digest) return std::nullopt;
            e.digest = *digest;
            e.relative_path = rest;
            m.entries.push_back(std::move(e));
            continue;
        }

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string value = line.substr(eq + 1);

        if (key == "format_version") {
            if (value != "2") return std::nullopt;
            have_version = true;
        } else if (key == "created_at") {
            try {
                m.created_at = std::stoull(value);
            } catch (const std::exception&) {
                return std::nullopt;
            }
        } else if (key == "source_root") {
            m.source_root = value;
        } else if (key == "merkle_root") {
            auto digest = Digest::parse(value);
            if (!digest) return std::nullopt;
            m.merkle_root = *digest;
            have_merkle_root = true;
        }
    }

    if (!have_version || !have_merkle_root) return std::nullopt;
    return m;
}
