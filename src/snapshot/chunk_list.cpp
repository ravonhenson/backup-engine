#include "snapshot/chunk_list.h"

#include <sstream>
#include <string_view>

#include "util/text_format.h"

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
            // "chunk <digest> <size>"
            std::string_view fields = std::string_view(line).substr(6);
            auto space = fields.find(' ');
            if (space == std::string_view::npos) return std::nullopt;
            auto digest = Digest::parse(fields.substr(0, space));
            auto size = parse_u64(fields.substr(space + 1));
            if (!digest || !size) return std::nullopt;

            list.chunks.push_back({*digest, *size});
            continue;
        }

        auto kv = split_key_value(line);
        if (!kv) continue;
        auto [key, value] = *kv;

        if (key == "format_version") {
            if (value != "1") return std::nullopt;
            have_version = true;
        } else if (key == "total_size") {
            auto total = parse_u64(value);
            if (!total) return std::nullopt;
            list.total_size = *total;
        }
    }

    if (!have_version) return std::nullopt;
    return list;
}
