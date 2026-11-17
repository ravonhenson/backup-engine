#include "cli/cli.h"

#include <iostream>
#include <optional>
#include <ostream>

#include "cli/command.h"
#include "util/fs_util.h"

namespace {

constexpr std::string_view kProgram = "backup_engine";

const std::vector<CommandGroup>& command_groups() {
    static const std::vector<CommandGroup> groups = {
        object_commands(),
        snapshot_commands(),
        log_commands(),
        proof_commands(),
    };
    return groups;
}

const Command* find_command(std::string_view name) {
    for (const auto& group : command_groups()) {
        for (const auto& cmd : group.commands) {
            if (cmd.name == name) return &cmd;
        }
    }
    return nullptr;
}

std::string signature(const Command& cmd) {
    std::string s(cmd.name);
    if (cmd.opens_repo) s += " <repo>";
    for (auto p : cmd.params) {
        s += ' ';
        s += p;
    }
    return s;
}

std::size_t arg_count(const Command& cmd) { return cmd.params.size() + (cmd.opens_repo ? 1 : 0); }

void print_help(std::ostream& out) {
    out << "usage: " << kProgram << " <command> [args...]\n";
    for (const auto& group : command_groups()) {
        out << "\n" << group.title << ":\n";
        for (const auto& cmd : group.commands) {
            out << "  " << signature(cmd) << "\n      " << cmd.summary << "\n";
        }
    }
    out << "\nRun '" << kProgram << " help <command>' for one command.\n";
}

void print_command_usage(std::ostream& out, const Command& cmd) {
    out << "usage: " << kProgram << " " << signature(cmd) << "\n";
}

int run_help(const std::vector<std::string>& args) {
    if (args.size() == 1) {
        print_help(std::cout);
        return 0;
    }
    const Command* cmd = args.size() == 2 ? find_command(args[1]) : nullptr;
    if (!cmd) {
        std::cerr << "error: unknown command '" << (args.size() > 1 ? args[1] : "") << "'\n";
        return 1;
    }
    print_command_usage(std::cout, *cmd);
    std::cout << "  " << cmd->summary << "\n";
    return 0;
}

} // namespace

Digest parse_digest_arg(const std::string& text) {
    auto digest = Digest::parse(text);
    if (!digest) {
        throw std::runtime_error("invalid digest (expected \"algo:hex\", e.g. sha256:...): " + text);
    }
    return *digest;
}

std::string read_text_file(const std::filesystem::path& path) {
    auto bytes = read_file(path);
    return std::string(bytes.begin(), bytes.end());
}

int run_cli(const std::vector<std::string>& args) {
    if (args.empty()) {
        print_help(std::cerr);
        return 1;
    }
    if (args[0] == "help" || args[0] == "--help" || args[0] == "-h") return run_help(args);

    const Command* cmd = find_command(args[0]);
    if (!cmd) {
        std::cerr << "error: unknown command '" << args[0] << "'\n\n";
        print_help(std::cerr);
        return 1;
    }
    if (args.size() - 1 != arg_count(*cmd)) {
        print_command_usage(std::cerr, *cmd);
        return 1;
    }

    try {
        std::optional<Repo> repo;
        std::vector<std::string> rest(args.begin() + 1, args.end());
        if (cmd->opens_repo) {
            repo.emplace(Repo::open(rest.front()));
            rest.erase(rest.begin());
        }
        return cmd->run(Invocation(rest, repo ? &*repo : nullptr));
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
