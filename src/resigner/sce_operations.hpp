#pragma once

#include "settings.hpp"

#include "tool/scetool_source/scetool.hpp"

#include <filesystem>
#include <optional>
#include <string>

namespace resigner {

/// SCE crypto operations built on top of the scetool engine.
class SceOperations {
public:
    explicit SceOperations(Settings& settings);

    [[nodiscard]] bool decrypt(
        const std::filesystem::path& input,
        const std::filesystem::path& output,
        const std::optional<std::string>& klicensee = std::nullopt) const;

    [[nodiscard]] bool encrypt_non_drm(
        const std::filesystem::path& elf_path,
        const std::filesystem::path& output_path) const;

    [[nodiscard]] bool encrypt_npdrm_eboot(
        const std::filesystem::path& elf_path,
        const std::filesystem::path& bin_path,
        const std::string& content_id) const;

    [[nodiscard]] bool encrypt_npdrm_self(
        const std::filesystem::path& elf_path,
        const std::filesystem::path& self_path,
        const std::string& content_id,
        const std::string& real_filename,
        const std::string& np_app_type) const;

    [[nodiscard]] std::optional<std::string> read_content_id(
        const std::filesystem::path& sce_file) const;

    [[nodiscard]] bool patch_elf_sdk(const std::filesystem::path& elf_path) const;

private:
    Settings& settings_;

    [[nodiscard]] ps3::sce::SelfEncryptBuilder base_encrypt_builder(
        const std::filesystem::path& input,
        const std::filesystem::path& output) const;

    void apply_flag_overrides(ps3::sce::SelfEncryptBuilder& builder) const;
};

} // namespace resigner
