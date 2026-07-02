#pragma once

#include "domain/types.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>

namespace resigner {
class SceOperations;
}

namespace eboot_diff {

struct LoadOptions {
    std::optional<std::string> klicensee;
};

class EbootLoader {
public:
    explicit EbootLoader(resigner::SceOperations& sce_ops);

    [[nodiscard]] Result<EbootDocument> load(
        const std::filesystem::path& path,
        const LoadOptions& options = {}) const;

private:
    resigner::SceOperations& sce_ops_;

    [[nodiscard]] static bool is_elf_path(const std::filesystem::path& path);
    [[nodiscard]] static bool is_bin_path(const std::filesystem::path& path);
    [[nodiscard]] static ContainerKind detect_container_kind(std::span<const std::uint8_t> data);
    [[nodiscard]] Result<std::vector<std::uint8_t>> read_file(
        const std::filesystem::path& path) const;
    [[nodiscard]] Result<std::vector<std::uint8_t>> decrypt_bin(
        const std::filesystem::path& path,
        const LoadOptions& options) const;
};

} // namespace eboot_diff
