#pragma once

#include <iostream>
#include <string>

namespace resigner {

/// Terminal UI helpers.
class Console {
public:
    static void clear();
    static void set_success_color();

    static void println(std::string_view message);
    static void print_formatted(const char* format, ...);

    static void wait_for_enter();
    static bool confirm(std::string_view prompt);
    static std::string read_line(std::string_view prompt);
    static int read_int(std::string_view prompt);
};

} // namespace resigner
