#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace ps3::elf {

struct AppError {
    std::string message;
};

struct LoadSegment {
    std::uint64_t virtual_address{0};
    std::uint64_t file_offset{0};
    std::uint64_t file_size{0};
    std::uint64_t memory_size{0};
    std::string name;
};

struct CodeRegion {
    std::uint64_t virtual_address{0};
    std::uint64_t file_offset{0};
    std::uint64_t size{0};
    std::string name;
};

class Image {
public:
    [[nodiscard]] static std::expected<Image, AppError> load(std::vector<std::uint8_t> bytes);

    [[nodiscard]] std::span<const std::uint8_t> bytes() const { return bytes_; }
    [[nodiscard]] std::vector<std::uint8_t>& mutable_bytes() { return bytes_; }
    [[nodiscard]] const std::vector<std::uint8_t>& data() const { return bytes_; }

    [[nodiscard]] const std::vector<LoadSegment>& executable_segments() const {
        return executable_segments_;
    }

    [[nodiscard]] const std::vector<CodeRegion>& code_regions() const {
        return code_regions_;
    }

    [[nodiscard]] std::expected<std::span<const std::uint8_t>, AppError> read_at(
        std::uint64_t virtual_address,
        std::size_t size) const;

    [[nodiscard]] std::expected<void, AppError> write_at(
        std::uint64_t virtual_address,
        std::span<const std::uint8_t> data);

private:
    explicit Image(std::vector<std::uint8_t> bytes);

    [[nodiscard]] std::expected<void, AppError> parse();
    [[nodiscard]] std::expected<void, AppError> parse_sections();

    std::vector<std::uint8_t> bytes_;
    std::vector<LoadSegment> load_segments_;
    std::vector<LoadSegment> executable_segments_;
    std::vector<CodeRegion> code_regions_;
};

} // namespace ps3::elf
