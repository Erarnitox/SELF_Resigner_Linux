#include "application.hpp"
#include "util/branding.hpp"

#include <cstring>
#include <iostream>
#include <string>

namespace {

void print_usage() {
    std::cout
        << eboot_diff::kAppName << "\n"
        << "Usage:\n"
        << "  eboot_diff\n"
        << "  eboot_diff --self-test\n"
        << "  eboot_diff --diff <left> <right> --report <file>\n";
}

} // namespace

int main(int argc, char** argv) {
    eboot_diff::Application app;

    if (argc == 1) {
        return app.run_gui();
    }

    if (argc == 2 && std::strcmp(argv[1], "--self-test") == 0) {
        return app.run_headless_self_test();
    }

    if (argc >= 6 && std::strcmp(argv[1], "--diff") == 0 && std::strcmp(argv[4], "--report") == 0) {
        return app.run_headless_diff(argv[2], argv[3], argv[5]);
    }

    print_usage();
    return 1;
}
