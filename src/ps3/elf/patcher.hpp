#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace ps3::elf {

struct PatchResult {
    bool patched{false};
    std::uint8_t previous_value{0};
    std::uint8_t new_value{0};
};

class Patcher {
public:
    [[nodiscard]] static std::optional<PatchResult> patch_sdk(
        const std::filesystem::path& file,
        const std::string& sdk_hex);

    [[nodiscard]] static std::optional<PatchResult> patch_sdk_byte(
        const std::filesystem::path& file,
        std::uint8_t sdk_byte);
};

} // namespace ps3::elf
