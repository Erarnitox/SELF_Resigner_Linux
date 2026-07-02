#include "settings.hpp"

namespace resigner {

std::string Settings::output_label() const {
    switch (output_mode) {
    case OutputMode::CexStd: return "[4.XX STD]";
    case OutputMode::CexAlt: return "[4.XX ALT]";
    case OutputMode::CexOde: return "[4.XX ODE]";
    case OutputMode::Cfw3xxStd: return "[3.XX STD]";
    case OutputMode::Cfw3xxAlt: return "[3.XX ALT]";
    }
    return "[unknown]";
}

std::string Settings::compress_label() const {
    return compress_data ? "[ON]" : "[OFF]";
}

std::string Settings::elf_sdk_hex() const {
    switch (output_mode) {
    case OutputMode::CexStd:
    case OutputMode::CexAlt:
        return "41";
    case OutputMode::CexOde:
    case OutputMode::Cfw3xxStd:
    case OutputMode::Cfw3xxAlt:
        return "33";
    }
    return "41";
}

std::string Settings::key_revision() const {
    switch (output_mode) {
    case OutputMode::CexStd:
    case OutputMode::CexAlt:
        return "1C";
    case OutputMode::CexOde:
        return "0A";
    case OutputMode::Cfw3xxStd:
    case OutputMode::Cfw3xxAlt:
        return "04";
    }
    return "1C";
}

std::string Settings::firmware_version() const {
    switch (output_mode) {
    case OutputMode::CexStd:
    case OutputMode::CexAlt:
        return "0004002000000000";
    case OutputMode::CexOde:
        return "0003005500000000";
    case OutputMode::Cfw3xxStd:
    case OutputMode::Cfw3xxAlt:
        return "0003004000000000";
    }
    return "0004002000000000";
}

std::string Settings::control_flags() const {
    return std::string{kControlFlags};
}

std::string Settings::capability_flags() const {
    return std::string{kCapabilityFlags};
}

bool Settings::supports_npdrm() const {
    return output_mode != OutputMode::CexOde;
}

void Settings::cycle_output_mode() {
    switch (output_mode) {
    case OutputMode::CexStd:
        output_mode = OutputMode::CexAlt;
        use_control_flags = true;
        use_capability_flags = false;
        break;
    case OutputMode::CexAlt:
        output_mode = OutputMode::CexOde;
        use_control_flags = false;
        use_capability_flags = true;
        break;
    case OutputMode::CexOde:
        output_mode = OutputMode::Cfw3xxStd;
        use_control_flags = false;
        use_capability_flags = false;
        break;
    case OutputMode::Cfw3xxStd:
        output_mode = OutputMode::Cfw3xxAlt;
        use_control_flags = true;
        use_capability_flags = false;
        break;
    case OutputMode::Cfw3xxAlt:
        output_mode = OutputMode::CexStd;
        use_control_flags = false;
        use_capability_flags = false;
        break;
    }
}

void Settings::set_compress_data(const bool enabled) {
    compress_data = enabled;
}

} // namespace resigner
