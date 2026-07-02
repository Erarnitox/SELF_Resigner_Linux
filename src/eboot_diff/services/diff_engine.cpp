#include "diff_engine.hpp"

#include <algorithm>
#include <span>
#include <unordered_map>
#include <vector>

namespace eboot_diff {

namespace {

AlignedRow make_row(
    const std::optional<InstructionLine>& left,
    const std::optional<InstructionLine>& right) {
    AlignedRow row{};
    row.left = left;
    row.right = right;

    if (row.left.has_value() && row.right.has_value()) {
        row.kind = (row.left->bytes == row.right->bytes
            && row.left->mnemonic == row.right->mnemonic
            && row.left->operands == row.right->operands)
            ? DiffKind::Equal
            : DiffKind::Changed;
    } else if (row.left.has_value()) {
        row.kind = DiffKind::LeftOnly;
    } else {
        row.kind = DiffKind::RightOnly;
    }

    return row;
}

} // namespace

std::vector<AlignedRow> DiffEngine::align(
    const DisassemblyView& left,
    const DisassemblyView& right) {
    std::unordered_map<std::uint64_t, InstructionLine> left_by_address;
    std::unordered_map<std::uint64_t, InstructionLine> right_by_address;
    left_by_address.reserve(left.lines.size());
    right_by_address.reserve(right.lines.size());

    for (const auto& line : left.lines) {
        left_by_address.emplace(line.address, line);
    }
    for (const auto& line : right.lines) {
        right_by_address.emplace(line.address, line);
    }

    std::vector<std::uint64_t> addresses;
    addresses.reserve(left_by_address.size() + right_by_address.size());
    for (const auto& [address, _] : left_by_address) {
        addresses.push_back(address);
    }
    for (const auto& [address, _] : right_by_address) {
        addresses.push_back(address);
    }

    std::ranges::sort(addresses);
    addresses.erase(std::unique(addresses.begin(), addresses.end()), addresses.end());

    std::vector<AlignedRow> rows;
    rows.reserve(addresses.size());

    for (const auto address : addresses) {
        const auto left_it = left_by_address.find(address);
        const auto right_it = right_by_address.find(address);

        std::optional<InstructionLine> left_line;
        std::optional<InstructionLine> right_line;
        if (left_it != left_by_address.end()) {
            left_line = left_it->second;
        }
        if (right_it != right_by_address.end()) {
            right_line = right_it->second;
        }

        rows.push_back(make_row(left_line, right_line));
    }

    return rows;
}

std::vector<AlignedRow> DiffEngine::align_slice(
    const std::span<const std::uint64_t> addresses,
    const DisassemblyView& left,
    const DisassemblyView& right) {
    std::unordered_map<std::uint64_t, InstructionLine> left_by_address;
    std::unordered_map<std::uint64_t, InstructionLine> right_by_address;
    left_by_address.reserve(left.lines.size());
    right_by_address.reserve(right.lines.size());

    for (const auto& line : left.lines) {
        left_by_address.emplace(line.address, line);
    }
    for (const auto& line : right.lines) {
        right_by_address.emplace(line.address, line);
    }

    std::vector<AlignedRow> rows;
    rows.reserve(addresses.size());

    for (const auto address : addresses) {
        std::optional<InstructionLine> left_line;
        std::optional<InstructionLine> right_line;
        if (const auto left_it = left_by_address.find(address); left_it != left_by_address.end()) {
            left_line = left_it->second;
        }
        if (const auto right_it = right_by_address.find(address); right_it != right_by_address.end()) {
            right_line = right_it->second;
        }
        rows.push_back(make_row(left_line, right_line));
    }

    return rows;
}

} // namespace eboot_diff
