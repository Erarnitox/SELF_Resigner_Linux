#include "types.hpp"

#include <fmt/format.h>

namespace eboot_diff {

std::string InstructionLine::display_text() const {
    return fmt::format(
        "0x{:016X}  {:02X}{:02X}{:02X}{:02X}  {} {}",
        address,
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        mnemonic,
        operands);
}

std::string InstructionLine::diff_key() const {
    return fmt::format("{:016X} {} {}", address, mnemonic, operands);
}

void DiffSession::clear() {
    left.reset();
    right.reset();
    aligned_addresses.clear();
    diff_rows.clear();
    segments.clear();
    chunk = {};
    selected_row = -1;
}

bool DiffSession::ready() const {
    return left.has_value() && right.has_value() && left->has_elf() && right->has_elf();
}

} // namespace eboot_diff
