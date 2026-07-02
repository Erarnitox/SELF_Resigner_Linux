#pragma once

#include <string>
#include <string_view>

namespace eboot_diff {

enum class LogLevel {
    Info,
    Warning,
    Error,
};

class Logger {
public:
    static void log(LogLevel level, std::string_view message);
    static void info(std::string_view message);
    static void warning(std::string_view message);
    static void error(std::string_view message);
};

} // namespace eboot_diff
