#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace eboot_diff {

class FileDialogs {
public:
    [[nodiscard]] static std::optional<std::filesystem::path> open_eboot();
    [[nodiscard]] static std::optional<std::filesystem::path> open_project();
    [[nodiscard]] static std::optional<std::filesystem::path> save_project(const std::string& default_name = "project.ebootdiff");
    [[nodiscard]] static std::optional<std::filesystem::path> save_elf();
    [[nodiscard]] static std::optional<std::filesystem::path> save_bin();
};

} // namespace eboot_diff
