#pragma once

#include "domain/types.hpp"

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace eboot_diff {

class AddressIndex {
public:
    [[nodiscard]] static std::vector<std::uint64_t> build_executable_addresses(const EbootDocument& document);
    [[nodiscard]] static std::vector<std::uint64_t> merge_aligned(
        const std::vector<std::uint64_t>& left,
        const std::vector<std::uint64_t>& right);

    [[nodiscard]] static std::vector<std::size_t> build_diff_row_indices(
        const EbootDocument& left,
        const EbootDocument& right,
        const std::vector<std::uint64_t>& aligned_addresses);

    [[nodiscard]] static std::vector<ExecutableSegmentInfo> build_segment_views(
        const std::vector<std::uint64_t>& aligned_addresses,
        const EbootDocument* left,
        const EbootDocument* right);

    [[nodiscard]] static std::optional<std::uint64_t> parse_address(std::string_view text);
    [[nodiscard]] static std::optional<std::size_t> find_row_for_address(
        const std::vector<std::uint64_t>& aligned_addresses,
        std::uint64_t address);
};

} // namespace eboot_diff
