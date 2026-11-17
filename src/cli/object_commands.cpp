#include <exception>
#include <iostream>

#include "cli/command.h"
#include "util/fs_util.h"

namespace {

int cmd_init(const Invocation& in) {
    Repo::init(in.arg(0));
    std::cout << "initialized repo at " << in.arg(0) << "\n";
    return 0;
}

int cmd_put(const Invocation& in) {
    PutResult result = in.repo().objects().put(read_file(in.arg(0)));
    std::cout << result.digest.to_string() << "\n";
    return 0;
}

int cmd_get(const Invocation& in) {
    auto data = in.repo().objects().get(parse_digest_arg(in.arg(0)));
    write_file(in.arg(1), data);
    return 0;
}

int cmd_verify(const Invocation& in) {
    Digest digest = parse_digest_arg(in.arg(0));
    try {
        in.repo().objects().get(digest);
    } catch (const std::exception&) {
        std::cout << "FAILED\n";
        return 1;
    }
    std::cout << "OK\n";
    return 0;
}

} // namespace

CommandGroup object_commands() {
    return {"repository and objects",
            {
                {"init", false, {"<repo>"}, "Create a new repository", cmd_init},
                {"put", true, {"<file>"}, "Store a file as one object; prints its digest", cmd_put},
                {"get", true, {"<digest>", "<output-file>"}, "Write an object's verified contents to a file", cmd_get},
                {"verify", true, {"<digest>"}, "Check that an object exists and matches its digest", cmd_verify},
            }};
}
