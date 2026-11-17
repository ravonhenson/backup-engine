#pragma once

#include <string>
#include <vector>

// Runs the command line (argv without the program name) and returns the
// process exit code. Errors are reported on stderr, never thrown.
int run_cli(const std::vector<std::string>& args);
