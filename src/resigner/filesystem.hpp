#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace resigner {

namespace paths {
inline constexpr std::string_view kToolDir{"tool"};
inline constexpr std::string_view kSelfDir{"self"};
inline constexpr std::string_view kRapsDir{"raps"};
inline constexpr std::string_view kDataDir{"data"};
inline constexpr std::string_view kEbootBin{"EBOOT.BIN"};
inline constexpr std::string_view kEbootElf{"EBOOT.ELF"};
inline constexpr std::string_view kEbootBinBackup{"EBOOT.BIN.BAK"};
} // namespace paths

/// Filesystem helpers for listing and staging resign assets.
class FileSystem {
public:
    static void ensure_workspace();

    static void cleanup_tool_artifacts();

    [[nodiscard]] static std::vector<std::filesystem::path> list_by_extensions(
        const std::filesystem::path& directory,
        const std::vector<std::string>& extensions);

    [[nodiscard]] static bool backup_file(const std::filesystem::path& path);

    [[nodiscard]] static bool ends_with_ignore_case(
        std::string_view value,
        std::string_view suffix);
};

} // namespace resigner
