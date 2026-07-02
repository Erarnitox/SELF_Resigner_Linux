#pragma once

#include <filesystem>
#include <optional>

namespace eboot_diff {

class AppPaths {
public:
    [[nodiscard]] static std::optional<std::filesystem::path> executable_directory();

    [[nodiscard]] static std::filesystem::path config_directory();
    [[nodiscard]] static std::filesystem::path last_project_file();
};

} // namespace eboot_diff
