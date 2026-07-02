#include "console.hpp"

#include <cstdarg>
#include <cstdio>
#include <limits>

namespace resigner {

void Console::clear() {
    std::printf("\033[2J\033[1;1H");
}

void Console::set_success_color() {
    std::printf("\033[1;32m");
}

void Console::println(const std::string_view message) {
    std::cout << message << '\n';
}

void Console::print_formatted(const char* format, ...) {
    va_list args;
    va_start(args, format);
    std::vprintf(format, args);
    va_end(args);
}

void Console::wait_for_enter() {
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();
}

bool Console::confirm(const std::string_view prompt) {
    std::cout << prompt;
    std::string answer;
    std::cin >> answer;
    return answer == "Y" || answer == "y";
}

std::string Console::read_line(const std::string_view prompt) {
    std::cout << prompt;
    std::string value;
    std::cin >> value;
    return value;
}

int Console::read_int(const std::string_view prompt) {
    std::cout << prompt;
    int value{0};
    std::cin >> value;
    return value;
}

} // namespace resigner
