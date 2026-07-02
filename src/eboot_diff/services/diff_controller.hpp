#pragma once

#include "domain/types.hpp"
#include "services/assembler.hpp"
#include "services/diff_engine.hpp"
#include "services/disassembler.hpp"
#include "services/eboot_loader.hpp"
#include "services/export_service.hpp"
#include "services/patch_service.hpp"

#include "resigner/settings.hpp"

namespace resigner {
class SceOperations;
}

namespace eboot_diff {

class DiffController {
public:
    DiffController(
        resigner::SceOperations& sce_ops,
        resigner::Settings& settings);

    [[nodiscard]] Result<void> open_left(const std::filesystem::path& path, const LoadOptions& options = {});
    [[nodiscard]] Result<void> open_right(const std::filesystem::path& path, const LoadOptions& options = {});
    [[nodiscard]] Result<void> refresh_diff();
    [[nodiscard]] Result<void> copy_row(CopyDirection direction, std::size_t row_index);
    [[nodiscard]] Result<void> apply_assembly_edit(bool left_side, std::size_t row_index, std::string_view text);
    [[nodiscard]] Result<void> export_side(bool left_side, const std::filesystem::path& path, bool as_bin);

    void ensure_rows_loaded(std::size_t visible_start, std::size_t visible_end);
    [[nodiscard]] const AlignedRow* row_at(std::size_t row_index) const;
    [[nodiscard]] std::string_view chunk_error() const { return chunk_error_; }

    [[nodiscard]] std::size_t diff_count() const { return session_.diff_rows.size(); }
    [[nodiscard]] std::optional<std::size_t> diff_position(std::size_t row_index) const;
    [[nodiscard]] std::optional<std::size_t> jump_to_next_diff();
    [[nodiscard]] std::optional<std::size_t> jump_to_prev_diff();
    [[nodiscard]] std::optional<std::size_t> jump_to_row(std::size_t row_index);
    [[nodiscard]] std::optional<std::size_t> jump_to_address(std::string_view address_text);
    [[nodiscard]] std::optional<std::size_t> jump_to_segment(std::size_t segment_index);
    void sync_edit_buffer(bool edit_left, std::string& edit_buffer) const;

    [[nodiscard]] const std::vector<ExecutableSegmentInfo>& segments() const { return session_.segments; }

    [[nodiscard]] DiffSession& session() { return session_; }
    [[nodiscard]] const DiffSession& session() const { return session_; }
    [[nodiscard]] resigner::Settings& settings() { return settings_; }

private:
    [[nodiscard]] Result<void> load_chunk(std::size_t row_begin, std::size_t row_end);
    void rebuild_diff_index();
    [[nodiscard]] std::optional<std::size_t> next_diff_row() const;
    [[nodiscard]] std::optional<std::size_t> prev_diff_row() const;
    [[nodiscard]] bool address_in_executable(std::uint64_t address) const;

    resigner::SceOperations& sce_ops_;
    resigner::Settings& settings_;
    DiffSession session_;
    EbootLoader loader_;
    DisassemblerService disassembler_;
    AssemblerService assembler_;
    ExportService exporter_;
    std::string chunk_error_;
};

} // namespace eboot_diff
