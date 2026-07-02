#pragma once

#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace ps3::binary {

inline std::uint16_t read_be16(std::span<const std::uint8_t> data, std::size_t offset) {
    return static_cast<std::uint16_t>((data[offset] << 8) | data[offset + 1]);
}

inline std::uint32_t read_be32(std::span<const std::uint8_t> data, std::size_t offset) {
    return (static_cast<std::uint32_t>(data[offset]) << 24)
        | (static_cast<std::uint32_t>(data[offset + 1]) << 16)
        | (static_cast<std::uint32_t>(data[offset + 2]) << 8)
        | static_cast<std::uint32_t>(data[offset + 3]);
}

inline std::uint64_t read_be64(std::span<const std::uint8_t> data, std::size_t offset) {
    const auto high = read_be32(data, offset);
    const auto low = read_be32(data, offset + 4);
    return (static_cast<std::uint64_t>(high) << 32) | low;
}

inline void write_be16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value));
}

inline void write_be32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 24));
    out.push_back(static_cast<std::uint8_t>(value >> 16));
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value));
}

inline void write_be64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    write_be32(out, static_cast<std::uint32_t>(value >> 32));
    write_be32(out, static_cast<std::uint32_t>(value));
}

inline void write_be16_at(std::vector<std::uint8_t>& out, std::size_t offset, std::uint16_t value) {
    if (out.size() <= offset + 1) {
        out.resize(offset + 2);
    }
    out[offset] = static_cast<std::uint8_t>(value >> 8);
    out[offset + 1] = static_cast<std::uint8_t>(value);
}

inline void write_be32_at(std::vector<std::uint8_t>& out, std::size_t offset, std::uint32_t value) {
    if (out.size() < offset + 4) {
        out.resize(offset + 4);
    }
    out[offset] = static_cast<std::uint8_t>(value >> 24);
    out[offset + 1] = static_cast<std::uint8_t>(value >> 16);
    out[offset + 2] = static_cast<std::uint8_t>(value >> 8);
    out[offset + 3] = static_cast<std::uint8_t>(value);
}

inline void write_be64_at(std::vector<std::uint8_t>& out, std::size_t offset, std::uint64_t value) {
    write_be32_at(out, offset, static_cast<std::uint32_t>(value >> 32));
    write_be32_at(out, offset + 4, static_cast<std::uint32_t>(value));
}

inline std::size_t align_up(std::size_t value, std::size_t alignment) {
    const auto remainder = value % alignment;
    return remainder == 0 ? value : value + (alignment - remainder);
}

inline void write_padding(std::vector<std::uint8_t>& out, std::size_t alignment) {
    const auto aligned = align_up(out.size(), alignment);
    out.resize(aligned, 0);
}

} // namespace ps3::binary
