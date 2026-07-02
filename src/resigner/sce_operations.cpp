#include "sce_operations.hpp"

#include "filesystem.hpp"

#include "ps3/elf/patcher.hpp"

namespace resigner {

SceOperations::SceOperations(Settings& settings) : settings_{settings} {}

bool SceOperations::decrypt(
    const std::filesystem::path& input,
    const std::filesystem::path& output,
    const std::optional<std::string>& klicensee) const {
    return ps3::sce::Scetool::decrypt(input, output, klicensee, true).success;
}

ps3::sce::SelfEncryptBuilder SceOperations::base_encrypt_builder(
    const std::filesystem::path& input,
    const std::filesystem::path& output) const {
    return ps3::sce::SelfEncryptBuilder{input, output}
        .verbose()
        .compress_data(settings_.compress_data)
        .skip_sections(true)
        .key_revision(settings_.key_revision())
        .firmware_version(settings_.firmware_version());
}

void SceOperations::apply_flag_overrides(ps3::sce::SelfEncryptBuilder& builder) const {
    if (settings_.use_control_flags) {
        builder.control_flags(settings_.control_flags());
    }
    if (settings_.use_capability_flags) {
        builder.capability_flags(settings_.capability_flags());
    }
}

bool SceOperations::encrypt_non_drm(
    const std::filesystem::path& elf_path,
    const std::filesystem::path& output_path) const {
    auto builder = base_encrypt_builder(elf_path, output_path).self_type("APP");
    apply_flag_overrides(builder);
    return builder.encrypt().success;
}

bool SceOperations::encrypt_npdrm_eboot(
    const std::filesystem::path& elf_path,
    const std::filesystem::path& bin_path,
    const std::string& content_id) const {
    std::string np_app_type{"EXEC"};
    if (content_id.size() > 7 && content_id[7] == 'B') {
        np_app_type = "UEXEC";
    }

    auto builder = base_encrypt_builder(elf_path, bin_path)
                       .add_section_headers(true)
                       .npdrm(content_id, np_app_type, std::string{paths::kEbootBin});
    apply_flag_overrides(builder);
    return builder.encrypt().success;
}

bool SceOperations::encrypt_npdrm_self(
    const std::filesystem::path& elf_path,
    const std::filesystem::path& self_path,
    const std::string& content_id,
    const std::string& real_filename,
    const std::string& np_app_type) const {
    auto builder = base_encrypt_builder(elf_path, self_path)
                       .add_section_headers(true)
                       .npdrm(content_id, np_app_type, real_filename)
                       .np_klicensee(settings_.klicensee);
    apply_flag_overrides(builder);
    return builder.encrypt().success;
}

std::optional<std::string> SceOperations::read_content_id(
    const std::filesystem::path& sce_file) const {
    const auto info_file = std::filesystem::path{paths::kToolDir} / "selfinfo.txt";
    if (!ps3::sce::Scetool::print_info(sce_file, info_file).success) {
        return std::nullopt;
    }
    return ps3::sce::Scetool::content_id_from_info_file(info_file);
}

bool SceOperations::patch_elf_sdk(const std::filesystem::path& elf_path) const {
    const auto result = ps3::elf::Patcher::patch_sdk(elf_path, settings_.elf_sdk_hex());
    return result.has_value();
}

} // namespace resigner
