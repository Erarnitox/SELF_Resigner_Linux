#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <unordered_map>

namespace eboot_diff {

struct DiffProject {
    std::optional<std::filesystem::path> left_path;
    std::optional<std::filesystem::path> right_path;
    std::unordered_map<std::uint64_t, std::string> comments;
    std::optional<std::filesystem::path> project_path;
    bool dirty{false};

    void clear();
    [[nodiscard]] bool has_path() const { return project_path.has_value(); }
    [[nodiscard]] std::string display_name() const;
};

} // namespace eboot_diff
