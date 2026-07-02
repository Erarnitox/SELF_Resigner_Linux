#pragma once

#include <filesystem>

namespace ps3::fself {

/// Extracts ELF payloads from fake SELF (FSELF) files.
class Extractor {
public:
    [[nodiscard]] static bool extract(
        const std::filesystem::path& self_path,
        const std::filesystem::path& elf_path);
};

} // namespace ps3::fself
