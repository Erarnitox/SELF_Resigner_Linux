#include "patch_service.hpp"

#include "ps3/elf/image.hpp"

namespace eboot_diff {

namespace {

Result<void> write_instruction(EbootDocument& document, const InstructionLine& line) {
    auto image = ps3::elf::Image::load(document.elf_bytes);
    if (!image) {
        return std::unexpected(AppError::from(image.error().message));
    }
    if (auto written = image->write_at(line.address, std::span<const std::uint8_t>{line.bytes.data(), line.bytes.size()});
        !written) {
        return std::unexpected(AppError::from(written.error().message));
    }
    document.elf_bytes = std::move(image->mutable_bytes());
    document.dirty = true;
    return {};
}

} // namespace

Result<void> PatchService::copy_row(
    const CopyDirection direction,
    EbootDocument& left,
    EbootDocument& right,
    const AlignedRow& row) {
    if (direction == CopyDirection::LeftToRight) {
        if (!row.left.has_value()) {
            return std::unexpected(AppError::from("No left instruction to copy."));
        }
        return write_instruction(right, *row.left);
    }
    if (!row.right.has_value()) {
        return std::unexpected(AppError::from("No right instruction to copy."));
    }
    return write_instruction(left, *row.right);
}

Result<void> PatchService::copy_range(
    const CopyDirection direction,
    EbootDocument& left,
    EbootDocument& right,
    const std::vector<AlignedRow>& rows,
    const std::size_t begin,
    const std::size_t end) {
    if (begin >= end || end > rows.size()) {
        return std::unexpected(AppError::from("Invalid copy range."));
    }
    for (std::size_t index = begin; index < end; ++index) {
        if (auto result = copy_row(direction, left, right, rows[index]); !result) {
            return result;
        }
    }
    return {};
}

} // namespace eboot_diff
