#include "address_index.hpp"

#include "ps3/elf/image.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <fmt/format.h>
#include <iterator>
#include <optional>
#include <ranges>
#include <unordered_map>

namespace eboot_diff {

namespace {

std::optional<std::array<std::uint8_t, 4>> read_word(
    const ps3::elf::Image& image,
    const std::uint64_t address) {
    const auto bytes = image.read_at(address, 4);
    if (!bytes || bytes->size() != 4) {
        return std::nullopt;
    }
    std::array<std::uint8_t, 4> word{};
    std::memcpy(word.data(), bytes->data(), 4);
    return word;
}

} // namespace

std::vector<std::uint64_t> AddressIndex::build_executable_addresses(const EbootDocument& document) {
    std::vector<std::uint64_t> addresses;
    auto image = ps3::elf::Image::load(document.elf_bytes);
    if (!image) {
        return addresses;
    }

    for (const auto& region : image->code_regions()) {
        if (region.size < 4) {
            continue;
        }
        const auto instruction_count = static_cast<std::size_t>(region.size / 4);
        addresses.reserve(addresses.size() + instruction_count);
        for (std::uint64_t offset = 0; offset + 4 <= region.size; offset += 4) {
            addresses.push_back(region.virtual_address + offset);
        }
    }

    std::ranges::sort(addresses);
    return addresses;
}

std::vector<std::uint64_t> AddressIndex::merge_aligned(
    const std::vector<std::uint64_t>& left,
    const std::vector<std::uint64_t>& right) {
    std::vector<std::uint64_t> merged;
    merged.reserve(left.size() + right.size());
    std::ranges::set_union(left, right, std::back_inserter(merged));
    return merged;
}

std::vector<std::size_t> AddressIndex::build_diff_row_indices(
    const EbootDocument& left,
    const EbootDocument& right,
    const std::vector<std::uint64_t>& aligned_addresses) {
    const auto left_image = ps3::elf::Image::load(left.elf_bytes);
    const auto right_image = ps3::elf::Image::load(right.elf_bytes);

    std::vector<std::size_t> diff_rows;
    diff_rows.reserve(aligned_addresses.size() / 64);

    for (std::size_t index = 0; index < aligned_addresses.size(); ++index) {
        const auto address = aligned_addresses[index];
        const auto left_word = left_image ? read_word(*left_image, address) : std::nullopt;
        const auto right_word = right_image ? read_word(*right_image, address) : std::nullopt;

        if (left_word == right_word) {
            continue;
        }
        diff_rows.push_back(index);
    }

    return diff_rows;
}

std::vector<ExecutableSegmentInfo> AddressIndex::build_segment_views(
    const std::vector<std::uint64_t>& aligned_addresses,
    const EbootDocument* left,
    const EbootDocument* right) {
    std::vector<ExecutableSegmentInfo> segments;
    if (aligned_addresses.empty()) {
        return segments;
    }

    struct SegmentSource {
        std::uint64_t virtual_address{0};
        std::uint64_t end_address{0};
        int index{0};
        char side{'?'};
    };

    std::vector<SegmentSource> sources;
    const auto collect = [&sources](const EbootDocument& document, const char side) {
        const auto image = ps3::elf::Image::load(document.elf_bytes);
        if (!image) {
            return;
        }
        int index = 0;
        for (const auto& region : image->code_regions()) {
            if (region.size < 4) {
                ++index;
                continue;
            }
            sources.push_back(SegmentSource{
                .virtual_address = region.virtual_address,
                .end_address = region.virtual_address + region.size,
                .index = index++,
                .side = side,
            });
        }
    };

    if (left != nullptr) {
        collect(*left, 'L');
    }
    if (right != nullptr) {
        collect(*right, 'R');
    }

    std::ranges::sort(sources, [](const SegmentSource& a, const SegmentSource& b) {
        if (a.virtual_address != b.virtual_address) {
            return a.virtual_address < b.virtual_address;
        }
        return a.end_address < b.end_address;
    });

    std::unordered_map<std::uint64_t, ExecutableSegmentInfo> by_address;
    for (const auto& source : sources) {
        auto& entry = by_address[source.virtual_address];
        if (entry.label.empty()) {
            entry.virtual_address = source.virtual_address;
            entry.end_address = source.end_address;
            entry.label = fmt::format(
                "{} @ 0x{:016X}",
                source.index == 0 ? "code" : "code_" + std::to_string(source.index),
                source.virtual_address);
        } else {
            entry.end_address = std::max(entry.end_address, source.end_address);
            entry.label += fmt::format(" / {}", source.side);
        }
    }

    segments.reserve(by_address.size());
    for (auto& [_, segment] : by_address) {
        const auto begin_it = std::lower_bound(
            aligned_addresses.begin(),
            aligned_addresses.end(),
            segment.virtual_address);
        const auto end_it = std::lower_bound(
            aligned_addresses.begin(),
            aligned_addresses.end(),
            segment.end_address);
        if (begin_it == aligned_addresses.end() || *begin_it >= segment.end_address) {
            continue;
        }

        segment.first_row = static_cast<std::size_t>(std::distance(aligned_addresses.begin(), begin_it));
        segment.row_count = static_cast<std::size_t>(std::distance(begin_it, end_it));
        segments.push_back(std::move(segment));
    }

    std::ranges::sort(segments, [](const ExecutableSegmentInfo& a, const ExecutableSegmentInfo& b) {
        return a.virtual_address < b.virtual_address;
    });
    return segments;
}

std::optional<std::uint64_t> AddressIndex::parse_address(const std::string_view text) {
    std::string_view trimmed = text;
    while (!trimmed.empty() && std::isspace(static_cast<unsigned char>(trimmed.front())) != 0) {
        trimmed.remove_prefix(1);
    }
    while (!trimmed.empty() && std::isspace(static_cast<unsigned char>(trimmed.back())) != 0) {
        trimmed.remove_suffix(1);
    }
    if (trimmed.empty()) {
        return std::nullopt;
    }

    int base = 10;
    if (trimmed.size() > 2 && trimmed[0] == '0' && (trimmed[1] == 'x' || trimmed[1] == 'X')) {
        trimmed.remove_prefix(2);
        base = 16;
    } else if (std::ranges::any_of(trimmed, [](const char ch) { return (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'); })) {
        base = 16;
    }

    if (trimmed.empty()) {
        return std::nullopt;
    }

    std::uint64_t value = 0;
    for (const char ch : trimmed) {
        int digit = -1;
        if (ch >= '0' && ch <= '9') {
            digit = ch - '0';
        } else if (ch >= 'a' && ch <= 'f') {
            digit = 10 + (ch - 'a');
        } else if (ch >= 'A' && ch <= 'F') {
            digit = 10 + (ch - 'A');
        } else {
            return std::nullopt;
        }
        if (digit >= base) {
            return std::nullopt;
        }
        value = value * static_cast<std::uint64_t>(base) + static_cast<std::uint64_t>(digit);
    }

    return value & ~static_cast<std::uint64_t>(3);
}

std::optional<std::size_t> AddressIndex::find_row_for_address(
    const std::vector<std::uint64_t>& aligned_addresses,
    const std::uint64_t address) {
    if (aligned_addresses.empty()) {
        return std::nullopt;
    }

    const auto aligned_address = address & ~static_cast<std::uint64_t>(3);
    const auto exact_it = std::lower_bound(
        aligned_addresses.begin(),
        aligned_addresses.end(),
        aligned_address);
    if (exact_it != aligned_addresses.end() && *exact_it == aligned_address) {
        return static_cast<std::size_t>(std::distance(aligned_addresses.begin(), exact_it));
    }

    if (exact_it != aligned_addresses.end()) {
        return static_cast<std::size_t>(std::distance(aligned_addresses.begin(), exact_it));
    }

    return aligned_addresses.size() - 1;
}

} // namespace eboot_diff
