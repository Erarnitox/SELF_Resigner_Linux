#include "patcher.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <span>
#include <vector>

namespace ps3::elf {

namespace {

constexpr std::array<std::uint8_t, 10> kMarker{
    0x24, 0x13, 0xBC, 0xC5, 0xF6, 0x00, 0x33, 0x00, 0x00, 0x00};

std::optional<std::size_t> find_marker(std::span<const std::uint8_t> data) {
    const auto it = std::search(data.begin(), data.end(), kMarker.begin(), kMarker.end());
    if (it == data.end()) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(std::distance(data.begin(), it));
}

} // namespace

std::optional<PatchResult> Patcher::patch_sdk_byte(
    const std::filesystem::path& file,
    const std::uint8_t sdk_byte) {
    if (!std::filesystem::exists(file) || !std::filesystem::is_regular_file(file)) {
        return std::nullopt;
    }

    std::fstream stream{file, std::ios::binary | std::ios::in | std::ios::out};
    if (!stream) {
        return std::nullopt;
    }

    const auto file_size = std::filesystem::file_size(file);
    std::vector<std::uint8_t> buffer(file_size);
    if (!stream.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(file_size))) {
        return std::nullopt;
    }

    const auto marker_offset = find_marker(buffer);
    if (!marker_offset.has_value()) {
        return PatchResult{};
    }

    const auto sdk_offset = *marker_offset + kMarker.size();
    if (sdk_offset >= buffer.size()) {
        return PatchResult{};
    }

    const auto previous = buffer[sdk_offset];
    if (previous <= 50) {
        return PatchResult{.patched = false, .previous_value = previous, .new_value = previous};
    }

    buffer[sdk_offset] = sdk_byte;
    stream.seekp(static_cast<std::streamoff>(sdk_offset));
    stream.write(reinterpret_cast<const char*>(&sdk_byte), 1);
    if (!stream) {
        return std::nullopt;
    }

    return PatchResult{.patched = true, .previous_value = previous, .new_value = sdk_byte};
}

std::optional<PatchResult> Patcher::patch_sdk(
    const std::filesystem::path& file,
    const std::string& sdk_hex) {
    const auto sdk_byte = static_cast<std::uint8_t>(std::stoi(sdk_hex, nullptr, 16));
    return patch_sdk_byte(file, sdk_byte);
}

} // namespace ps3::elf
