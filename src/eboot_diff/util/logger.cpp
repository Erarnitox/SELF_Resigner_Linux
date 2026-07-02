#include "logger.hpp"

#include <iostream>

namespace eboot_diff {

namespace {

const char* level_prefix(const LogLevel level) {
    switch (level) {
    case LogLevel::Info:
        return "[*]";
    case LogLevel::Warning:
        return "[!]";
    case LogLevel::Error:
        return "[E]";
    }
    return "[?]";
}

} // namespace

void Logger::log(const LogLevel level, const std::string_view message) {
    std::cerr << level_prefix(level) << ' ' << message << '\n';
}

void Logger::info(const std::string_view message) {
    log(LogLevel::Info, message);
}

void Logger::warning(const std::string_view message) {
    log(LogLevel::Warning, message);
}

void Logger::error(const std::string_view message) {
    log(LogLevel::Error, message);
}

} // namespace eboot_diff
