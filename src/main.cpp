#include <string>
#include <vector>

#include "cli/cli.h"

int main(int argc, char **argv) {
  return run_cli(std::vector<std::string>(argv + 1, argv + argc));
}
