#include "export_service.hpp"

#include "ps3/elf/patcher.hpp"
#include "ps3/fself/builder.hpp"
#include "resigner/sce_operations.hpp"
#include "util/logger.hpp"

#include <cstring>
#include <fstream>

namespace eboot_diff {

namespace fs = std::filesystem;

ExportService::ExportService(resigner::SceOperations& sce_ops) : sce_ops_{sce_ops} {}

Result<std::filesystem::path> ExportService::write_temp_elf(const EbootDocument& document) const {
    const auto temp_elf = fs::temp_directory_path() / "eboot_diff_export.elf";
    std::ofstream out{temp_elf, std::ios::binary | std::ios::trunc};
    if (!out) {
        return std::unexpected(AppError::from("Failed to create temporary ELF."));
    }
    out.write(reinterpret_cast<const char*>(document.elf_bytes.data()),
        static_cast<std::streamsize>(document.elf_bytes.size()));
    if (!out) {
        return std::unexpected(AppError::from("Failed to write temporary ELF."));
    }
    return temp_elf;
}

Result<void> ExportService::export_elf(
    const EbootDocument& document,
    const fs::path& output_path,
    const bool patch_sdk) const {
    const fs::path temp = fs::temp_directory_path() / "eboot_diff_patch.elf";
    {
        std::ofstream out{temp, std::ios::binary | std::ios::trunc};
        out.write(reinterpret_cast<const char*>(document.elf_bytes.data()),
            static_cast<std::streamsize>(document.elf_bytes.size()));
        if (!out) {
            return std::unexpected(AppError::from("Failed to stage ELF for export."));
        }
    }

    if (patch_sdk) {
        (void)ps3::elf::Patcher::patch_sdk(temp, "41");
    }

    std::ifstream in{temp, std::ios::binary};
    std::vector<std::uint8_t> exported{
        std::istreambuf_iterator<char>{in},
        std::istreambuf_iterator<char>{}};
    fs::remove(temp);

    std::ofstream out{output_path, std::ios::binary | std::ios::trunc};
    if (!out) {
        return std::unexpected(AppError::from("Failed to open export path."));
    }
    out.write(reinterpret_cast<const char*>(exported.data()), static_cast<std::streamsize>(exported.size()));
    if (!out) {
        return std::unexpected(AppError::from("Failed to write exported ELF."));
    }

    Logger::info("Exported ELF to " + output_path.string());
    return {};
}

Result<void> ExportService::export_bin(
    const EbootDocument& document,
    const fs::path& output_path,
    const resigner::Settings& settings) const {
    auto temp_elf = write_temp_elf(document);
    if (!temp_elf) {
        return std::unexpected(temp_elf.error());
    }

    if (document.container_kind == ContainerKind::FakeSelf) {
        std::optional<ps3::fself::NpdrmInfo> npdrm_info;
        if (settings.supports_npdrm() && !settings.content_id.empty()) {
            ps3::fself::NpdrmInfo info{};
            const auto copy_size = std::min(info.content_id.size(), settings.content_id.size());
            std::memcpy(info.content_id.data(), settings.content_id.data(), copy_size);
            npdrm_info = info;
        }
        const bool npdrm = npdrm_info.has_value();
        if (!ps3::fself::Builder::build(*temp_elf, output_path, npdrm, npdrm_info)) {
            fs::remove(*temp_elf);
            return std::unexpected(AppError::from("FSELF export failed."));
        }
        fs::remove(*temp_elf);
        Logger::info("Exported FSELF to " + output_path.string());
        return {};
    }

    if (settings.supports_npdrm() && !settings.content_id.empty()) {
        if (!sce_ops_.encrypt_npdrm_eboot(*temp_elf, output_path, settings.content_id)) {
            fs::remove(*temp_elf);
            return std::unexpected(AppError::from("NPDRM SELF export failed."));
        }
    } else if (!sce_ops_.encrypt_non_drm(*temp_elf, output_path)) {
        fs::remove(*temp_elf);
        return std::unexpected(AppError::from("SELF export failed."));
    }

    fs::remove(*temp_elf);
    Logger::info("Exported SELF to " + output_path.string());
    return {};
}

} // namespace eboot_diff
