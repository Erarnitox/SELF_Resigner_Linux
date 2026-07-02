#pragma once

#include "domain/types.hpp"

#include <span>
#include <vector>

namespace eboot_diff {

class DiffEngine {
public:
    [[nodiscard]] static std::vector<AlignedRow> align(
        const DisassemblyView& left,
        const DisassemblyView& right);

    [[nodiscard]] static std::vector<AlignedRow> align_slice(
        std::span<const std::uint64_t> addresses,
        const DisassemblyView& left,
        const DisassemblyView& right);
};

} // namespace eboot_diff
