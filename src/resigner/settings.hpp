#pragma once

#include <string>

namespace resigner {

enum class OutputMode {
    CexStd,
    CexAlt,
    CexOde,
    Cfw3xxStd,
    Cfw3xxAlt,
};

/// User-configurable resign settings (replaces former global state).
class Settings {
public:
    OutputMode output_mode{OutputMode::CexStd};
    bool compress_data{true};
    bool use_control_flags{false};
    bool use_capability_flags{false};

    std::string content_id;
    std::string klicensee;

    [[nodiscard]] std::string output_label() const;
    [[nodiscard]] std::string compress_label() const;

    [[nodiscard]] std::string elf_sdk_hex() const;
    [[nodiscard]] std::string key_revision() const;
    [[nodiscard]] std::string firmware_version() const;

    [[nodiscard]] std::string control_flags() const;
    [[nodiscard]] std::string capability_flags() const;

    [[nodiscard]] bool supports_npdrm() const;

    void cycle_output_mode();
    void set_compress_data(bool enabled);

private:
    static constexpr std::string_view kControlFlags{
        "4000000000000000000000000000000000000000000000000000000000000002"};
    static constexpr std::string_view kCapabilityFlags{
        "00000000000000000000000000000000000000000000003B0000000100040000"};
};

} // namespace resigner
