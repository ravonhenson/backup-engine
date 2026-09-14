#include "chunk_list.h"

#include <sstream>

std::vector<uint8_t> ChunkList::serialize() const {
    std::ostringstream out;
    out << "format_version=1\n";
    out << "total_size=" << total_size << "\n";
    for (const auto& c : chunks) {
        out << "chunk " << c.digest.to_string() << " " << c.size << "\n";
    }
    std::string s = out.str();
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::optional<ChunkList> ChunkList::deserialize(const std::vector<uint8_t>& data) {
    std::string text(data.begin(), data.end());
    std::istringstream in(text);
    std::string line;

    ChunkList list;
    bool have_version = false;

    while (std::getline(in, line)) {
        if (line.empty()) continue;

        if (line.rfind("chunk ", 0) == 0) {
            std::istringstream fields(line.substr(6));
            std::string digest_text;
            uint64_t size = 0;
            if (!(fields >> digest_text >> size)) return std::nullopt;

            auto digest = Digest::parse(digest_text);
            if (!digest) return std::nullopt;

            list.chunks.push_back({*digest, size});
            continue;
        }

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string value = line.substr(eq + 1);

        if (key == "format_version") {
            if (value != "1") return std::nullopt;
            have_version = true;
        } else if (key == "total_size") {
            try {
                list.total_size = std::stoull(value);
            } catch (const std::exception&) {
                return std::nullopt;
            }
        }
    }

    if (!have_version) return std::nullopt;
    return list;
}
