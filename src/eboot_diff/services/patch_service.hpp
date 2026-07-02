#pragma once

#include "domain/types.hpp"

namespace eboot_diff {

enum class CopyDirection {
    LeftToRight,
    RightToLeft,
};

class PatchService {
public:
    [[nodiscard]] static Result<void> copy_row(
        CopyDirection direction,
        EbootDocument& left,
        EbootDocument& right,
        const AlignedRow& row);

    [[nodiscard]] static Result<void> copy_range(
        CopyDirection direction,
        EbootDocument& left,
        EbootDocument& right,
        const std::vector<AlignedRow>& rows,
        std::size_t begin,
        std::size_t end);
};

} // namespace eboot_diff
