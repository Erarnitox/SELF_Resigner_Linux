#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace ps3::fself {

struct NpdrmInfo {
    std::array<std::uint8_t, 0x30> content_id{};
};

/// Builds fake SELF (FSELF) files from ELF executables.
class Builder {
public:
    [[nodiscard]] static bool build(
        const std::filesystem::path& elf_path,
        const std::filesystem::path& self_path,
        bool npdrm = false,
        const std::optional<NpdrmInfo>& npdrm_info = std::nullopt);
};

} // namespace ps3::fself
