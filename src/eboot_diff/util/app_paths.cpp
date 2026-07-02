#include "app_paths.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>

namespace eboot_diff {

namespace {

std::filesystem::path home_directory() {
    if (const char* home = std::getenv("HOME"); home != nullptr && home[0] != '\0') {
        return std::filesystem::path{home};
    }
    return std::filesystem::current_path();
}

} // namespace

std::optional<std::filesystem::path> AppPaths::executable_directory() {
    std::error_code error;
#if defined(__linux__)
    const auto executable = std::filesystem::read_symlink("/proc/self/exe", error);
    if (!error) {
        return executable.parent_path();
    }
#endif
    return std::nullopt;
}

std::filesystem::path AppPaths::config_directory() {
    if (const char* xdg_config = std::getenv("XDG_CONFIG_HOME");
        xdg_config != nullptr && xdg_config[0] != '\0') {
        return std::filesystem::path{xdg_config} / "eboot_diff";
    }
    return home_directory() / ".config" / "eboot_diff";
}

std::filesystem::path AppPaths::last_project_file() {
    return config_directory() / "last_project";
}

} // namespace eboot_diff
