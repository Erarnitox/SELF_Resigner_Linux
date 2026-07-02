#pragma once

#include "error.hpp"

#include <array>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace eboot_diff {

enum class ContainerKind {
    Elf,
    RetailSelf,
    FakeSelf,
};

enum class DiffKind {
    Equal,
    Changed,
    LeftOnly,
    RightOnly,
};

struct InstructionLine {
    std::uint64_t address{0};
    std::array<std::uint8_t, 4> bytes{};
    std::string mnemonic;
    std::string operands;
    std::string segment_name;

    [[nodiscard]] std::string display_text() const;
    [[nodiscard]] std::string diff_key() const;
};

struct DisassemblyView {
    std::vector<InstructionLine> lines;
};

struct AlignedRow {
    DiffKind kind{DiffKind::Equal};
    std::optional<InstructionLine> left;
    std::optional<InstructionLine> right;
    std::size_t left_index{0};
    std::size_t right_index{0};
};

struct EbootDocument {
    std::filesystem::path source_path;
    std::vector<std::uint8_t> elf_bytes;
    ContainerKind container_kind{ContainerKind::Elf};
    bool opened_from_bin{false};
    bool dirty{false};
    std::optional<std::string> content_id;
    std::optional<std::string> klicensee;
    DisassemblyView disassembly;

    [[nodiscard]] bool has_elf() const { return !elf_bytes.empty(); }
};

struct ExecutableSegmentInfo {
    std::string label;
    std::uint64_t virtual_address{0};
    std::uint64_t end_address{0};
    std::size_t first_row{0};
    std::size_t row_count{0};
};

struct DiffChunkCache {
    std::size_t row_begin{0};
    std::size_t row_end{0};
    std::vector<AlignedRow> rows;
    bool valid{false};
};

struct DiffSession {
    std::optional<EbootDocument> left;
    std::optional<EbootDocument> right;
    std::vector<std::uint64_t> aligned_addresses;
    std::vector<std::size_t> diff_rows;
    std::vector<ExecutableSegmentInfo> segments;
    DiffChunkCache chunk;
    int selected_row{-1};

    void clear();
    [[nodiscard]] bool ready() const;
    [[nodiscard]] std::size_t total_rows() const { return aligned_addresses.size(); }
};

template <typename T>
using Result = std::expected<T, AppError>;

} // namespace eboot_diff
