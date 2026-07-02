#include "file_dialogs.hpp"

#include <portable-file-dialogs.h>

namespace eboot_diff {

std::optional<std::filesystem::path> FileDialogs::open_eboot() {
    const auto selection = pfd::open_file(
        "Open EBOOT",
        ".",
        {"EBOOT Files", "*.ELF *.elf *.BIN *.bin", "All Files", "*"})
        .result();
    if (selection.empty()) {
        return std::nullopt;
    }
    return std::filesystem::path{selection.front()};
}

std::optional<std::filesystem::path> FileDialogs::open_project() {
    const auto selection = pfd::open_file(
        "Open Project",
        ".",
        {"EBOOT Patcher Projects", "*.ebootdiff", "All Files", "*"})
        .result();
    if (selection.empty()) {
        return std::nullopt;
    }
    return std::filesystem::path{selection.front()};
}

std::optional<std::filesystem::path> FileDialogs::save_project(const std::string& default_name) {
    const auto selection = pfd::save_file(
        "Save Project",
        default_name,
        {"EBOOT Patcher Projects", "*.ebootdiff", "All Files", "*"})
        .result();
    if (selection.empty()) {
        return std::nullopt;
    }
    return std::filesystem::path{selection};
}

std::optional<std::filesystem::path> FileDialogs::save_elf() {
    const auto selection = pfd::save_file(
        "Export EBOOT.ELF",
        "EBOOT.ELF",
        {"ELF Files", "*.ELF *.elf", "All Files", "*"})
        .result();
    if (selection.empty()) {
        return std::nullopt;
    }
    return std::filesystem::path{selection};
}

std::optional<std::filesystem::path> FileDialogs::save_bin() {
    const auto selection = pfd::save_file(
        "Export EBOOT.BIN",
        "EBOOT.BIN",
        {"BIN Files", "*.BIN *.bin", "All Files", "*"})
        .result();
    if (selection.empty()) {
        return std::nullopt;
    }
    return std::filesystem::path{selection};
}

} // namespace eboot_diff
