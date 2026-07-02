#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace ps3::sce {

/// Outcome of a scetool invocation.
struct Result {
    bool success{false};
    int exit_code{-1};
};

/// Parameters for SELF encryption / resigning.
struct SelfEncryptParams {
    std::filesystem::path input;
    std::filesystem::path output;
    bool verbose{false};

    std::string sce_type{"SELF"};
    bool compress_data{true};
    bool skip_sections{true};
    std::string key_revision{"1C"};

    std::string self_auth_id{"1010000001000003"};
    std::string self_vendor_id{"01000002"};
    std::string self_type{"APP"};
    std::string self_app_version{"0001000000000000"};
    std::string self_fw_version{"0004002000000000"};

    std::optional<bool> self_add_shdrs;
    std::optional<std::string> self_ctrl_flags;
    std::optional<std::string> self_cap_flags;

    std::optional<std::string> np_license_type;
    std::optional<std::string> np_app_type;
    std::optional<std::string> np_content_id;
    std::optional<std::string> np_klicensee;
    std::optional<std::string> np_real_fname;
};

/// Fluent builder for common resign workflows.
class SelfEncryptBuilder {
public:
    explicit SelfEncryptBuilder(std::filesystem::path input, std::filesystem::path output);

    SelfEncryptBuilder& verbose(bool value = true);
    SelfEncryptBuilder& compress_data(bool value);
    SelfEncryptBuilder& skip_sections(bool value);
    SelfEncryptBuilder& key_revision(std::string revision);
    SelfEncryptBuilder& firmware_version(std::string version);
    SelfEncryptBuilder& self_type(std::string type);
    SelfEncryptBuilder& add_section_headers(bool value = true);
    SelfEncryptBuilder& control_flags(std::string flags);
    SelfEncryptBuilder& capability_flags(std::string flags);
    SelfEncryptBuilder& npdrm(std::string content_id, std::string app_type, std::string real_fname);
    SelfEncryptBuilder& np_klicensee(std::string klicensee);

    [[nodiscard]] SelfEncryptParams build() const;
    [[nodiscard]] Result encrypt() const;

private:
    SelfEncryptParams params_;
};

/// High-level scetool interface backed by the embedded scetool engine.
class Scetool {
public:
    [[nodiscard]] static Result run(const std::vector<std::string>& args);

    [[nodiscard]] static Result decrypt(
        const std::filesystem::path& input,
        const std::filesystem::path& output,
        const std::optional<std::string>& klicensee = std::nullopt,
        bool verbose = false);

    [[nodiscard]] static Result encrypt(const SelfEncryptParams& params);

    [[nodiscard]] static Result print_info(
        const std::filesystem::path& input,
        const std::optional<std::filesystem::path>& redirect_to = std::nullopt);

    [[nodiscard]] static std::optional<std::string> content_id_from_info_file(
        const std::filesystem::path& info_file);

    [[nodiscard]] static bool ensure_initialized();

    [[nodiscard]] static std::optional<std::string> klicensee_for_content_id(
        const std::string& content_id);
};

} // namespace ps3::sce
