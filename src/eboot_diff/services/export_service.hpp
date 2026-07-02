#pragma once

#include "domain/types.hpp"

#include "resigner/settings.hpp"

#include <filesystem>

namespace resigner {
class SceOperations;
}

namespace eboot_diff {

class ExportService {
public:
    explicit ExportService(resigner::SceOperations& sce_ops);

    [[nodiscard]] Result<void> export_elf(
        const EbootDocument& document,
        const std::filesystem::path& output_path,
        bool patch_sdk) const;

    [[nodiscard]] Result<void> export_bin(
        const EbootDocument& document,
        const std::filesystem::path& output_path,
        const resigner::Settings& settings) const;

private:
    resigner::SceOperations& sce_ops_;

    [[nodiscard]] Result<std::filesystem::path> write_temp_elf(
        const EbootDocument& document) const;
};

} // namespace eboot_diff
