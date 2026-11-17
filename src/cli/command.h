#pragma once

#include <cstddef>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "crypto/digest.h"
#include "storage/repo.h"

// What a command handler receives: its own positional arguments (after the
// repo path, for commands that open one) and the opened repo.
class Invocation {
public:
    Invocation(const std::vector<std::string>& args, Repo* repo) : args_(args), repo_(repo) {}

    const std::string& arg(std::size_t i) const { return args_.at(i); }

    Repo& repo() const {
        if (!repo_) throw std::logic_error("this command does not open a repo");
        return *repo_;
    }

private:
    const std::vector<std::string>& args_;
    Repo* repo_;
};

// One row of the command table. The dispatcher checks the argument count
// against `params`, opens the repo when `opens_repo` is set, and builds the
// usage and help text from these fields, so they can't drift apart.
struct Command {
    std::string_view name;
    bool opens_repo;                       // first argument is <repo>, opened before run()
    std::vector<std::string_view> params;  // the remaining arguments, e.g. {"<source-dir>"}
    std::string_view summary;
    int (*run)(const Invocation&);         // returns the process exit code
};

struct CommandGroup {
    std::string_view title;
    std::vector<Command> commands;
};

// Each group lives in its own file. To add a command, write its handler and
// add a row to its group.
CommandGroup object_commands();
CommandGroup snapshot_commands();
CommandGroup log_commands();
CommandGroup proof_commands();

// Shared helpers for handlers.
Digest parse_digest_arg(const std::string& text);
std::string read_text_file(const std::filesystem::path& path);
