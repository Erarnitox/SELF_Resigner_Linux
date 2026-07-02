#include "diff_controller.hpp"

#include "ps3/elf/image.hpp"
#include "services/address_index.hpp"
#include "util/logger.hpp"

#include <algorithm>

namespace eboot_diff {

namespace {

constexpr std::size_t kChunkRowCount = 4096;
constexpr std::size_t kChunkRecenterMargin = 512;

} // namespace

DiffController::DiffController(resigner::SceOperations& sce_ops, resigner::Settings& settings)
    : sce_ops_{sce_ops},
      settings_{settings},
      loader_{sce_ops},
      exporter_{sce_ops} {}

Result<void> DiffController::open_left(const std::filesystem::path& path, const LoadOptions& options) {
    auto document = loader_.load(path, options);
    if (!document) {
        return std::unexpected(document.error());
    }
    session_.left = std::move(*document);
    return refresh_diff();
}

Result<void> DiffController::open_right(const std::filesystem::path& path, const LoadOptions& options) {
    auto document = loader_.load(path, options);
    if (!document) {
        return std::unexpected(document.error());
    }
    session_.right = std::move(*document);
    return refresh_diff();
}

Result<void> DiffController::refresh_diff() {
    session_.chunk = {};
    chunk_error_.clear();

    if (!session_.ready()) {
        session_.aligned_addresses.clear();
        session_.diff_rows.clear();
        session_.segments.clear();
        return {};
    }

    const auto left_addresses = AddressIndex::build_executable_addresses(*session_.left);
    const auto right_addresses = AddressIndex::build_executable_addresses(*session_.right);
    session_.aligned_addresses = AddressIndex::merge_aligned(left_addresses, right_addresses);
    session_.segments = AddressIndex::build_segment_views(
        session_.aligned_addresses,
        session_.left.has_value() ? &*session_.left : nullptr,
        session_.right.has_value() ? &*session_.right : nullptr);
    rebuild_diff_index();

    if (session_.selected_row >= static_cast<int>(session_.total_rows())) {
        session_.selected_row = -1;
    }

    return {};
}

Result<void> DiffController::load_chunk(const std::size_t row_begin, const std::size_t row_end) {
    if (!session_.ready()) {
        return std::unexpected(AppError::from("Both sides must be loaded."));
    }
    if (row_begin >= row_end || row_end > session_.aligned_addresses.size()) {
        return std::unexpected(AppError::from("Invalid diff chunk range."));
    }

    const auto address_slice = std::span<const std::uint64_t>{
        session_.aligned_addresses.data() + row_begin,
        row_end - row_begin};

    auto left_view = disassembler_.disassemble_addresses(*session_.left, address_slice);
    if (!left_view) {
        return std::unexpected(left_view.error());
    }
    auto right_view = disassembler_.disassemble_addresses(*session_.right, address_slice);
    if (!right_view) {
        return std::unexpected(right_view.error());
    }

    session_.chunk.row_begin = row_begin;
    session_.chunk.row_end = row_end;
    session_.chunk.rows = DiffEngine::align_slice(address_slice, *left_view, *right_view);
    session_.chunk.valid = true;
    chunk_error_.clear();
    return {};
}

void DiffController::ensure_rows_loaded(const std::size_t visible_start, const std::size_t visible_end) {
    const std::size_t total = session_.total_rows();
    if (total == 0 || !session_.ready()) {
        return;
    }

    const std::size_t clamped_start = std::min(visible_start, total);
    const std::size_t clamped_end = std::min(std::max(visible_end, clamped_start + 1), total);
    const std::size_t view_center = (clamped_start + clamped_end) / 2;

    auto& cache = session_.chunk;
    const bool needs_load = !cache.valid
        || view_center < cache.row_begin + kChunkRecenterMargin
        || view_center + kChunkRecenterMargin >= cache.row_end;

    if (!needs_load) {
        return;
    }

    const std::size_t chunk_rows = std::min(kChunkRowCount, total);
    std::size_t row_begin = view_center > chunk_rows / 2 ? view_center - chunk_rows / 2 : 0;
    if (row_begin + chunk_rows > total) {
        row_begin = total - chunk_rows;
    }
    const std::size_t row_end = row_begin + chunk_rows;

    if (cache.valid && cache.row_begin == row_begin && cache.row_end == row_end) {
        return;
    }

    if (auto result = load_chunk(row_begin, row_end); !result) {
        cache.valid = false;
        chunk_error_ = result.error().message;
    }
}

const AlignedRow* DiffController::row_at(const std::size_t row_index) const {
    const auto& cache = session_.chunk;
    if (!cache.valid || row_index < cache.row_begin || row_index >= cache.row_end) {
        return nullptr;
    }
    return &cache.rows[row_index - cache.row_begin];
}

void DiffController::rebuild_diff_index() {
    if (!session_.ready()) {
        session_.diff_rows.clear();
        return;
    }
    session_.diff_rows = AddressIndex::build_diff_row_indices(
        *session_.left,
        *session_.right,
        session_.aligned_addresses);
}

std::optional<std::size_t> DiffController::next_diff_row() const {
    const auto& diffs = session_.diff_rows;
    if (diffs.empty()) {
        return std::nullopt;
    }
    if (session_.selected_row < 0) {
        return diffs.front();
    }

    const auto pivot = static_cast<std::size_t>(session_.selected_row);
    const auto it = std::upper_bound(diffs.begin(), diffs.end(), pivot);
    if (it == diffs.end()) {
        return diffs.front();
    }
    return *it;
}

std::optional<std::size_t> DiffController::prev_diff_row() const {
    const auto& diffs = session_.diff_rows;
    if (diffs.empty()) {
        return std::nullopt;
    }
    if (session_.selected_row < 0) {
        return diffs.back();
    }

    const auto pivot = static_cast<std::size_t>(session_.selected_row);
    const auto it = std::lower_bound(diffs.begin(), diffs.end(), pivot);
    if (it == diffs.begin()) {
        return diffs.back();
    }
    return *std::prev(it);
}

std::optional<std::size_t> DiffController::diff_position(const std::size_t row_index) const {
    const auto& diffs = session_.diff_rows;
    const auto it = std::lower_bound(diffs.begin(), diffs.end(), row_index);
    if (it == diffs.end() || *it != row_index) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(std::distance(diffs.begin(), it)) + 1;
}

std::optional<std::size_t> DiffController::jump_to_row(const std::size_t row_index) {
    if (row_index >= session_.total_rows()) {
        return std::nullopt;
    }
    session_.selected_row = static_cast<int>(row_index);
    ensure_rows_loaded(row_index, row_index + 1);
    return row_index;
}

bool DiffController::address_in_executable(const std::uint64_t address) const {
    for (const auto& segment : session_.segments) {
        if (address >= segment.virtual_address && address < segment.end_address) {
            return true;
        }
    }

    const auto in_document = [&](const std::optional<EbootDocument>& document) {
        if (!document.has_value()) {
            return false;
        }
        const auto image = ps3::elf::Image::load(document->elf_bytes);
        if (!image) {
            return false;
        }
        for (const auto& region : image->code_regions()) {
            const auto end = region.virtual_address + region.size;
            if (address >= region.virtual_address && address < end) {
                return true;
            }
        }
        return false;
    };

    return in_document(session_.left) || in_document(session_.right);
}

std::optional<std::size_t> DiffController::jump_to_address(const std::string_view address_text) {
    if (!session_.ready()) {
        return std::nullopt;
    }

    const auto address = AddressIndex::parse_address(address_text);
    if (!address.has_value()) {
        return std::nullopt;
    }
    if (!address_in_executable(*address)) {
        return std::nullopt;
    }

    const auto row = AddressIndex::find_row_for_address(session_.aligned_addresses, *address);
    if (!row.has_value()) {
        return std::nullopt;
    }
    return jump_to_row(*row);
}

std::optional<std::size_t> DiffController::jump_to_segment(const std::size_t segment_index) {
    if (segment_index >= session_.segments.size()) {
        return std::nullopt;
    }
    return jump_to_row(session_.segments[segment_index].first_row);
}

std::optional<std::size_t> DiffController::jump_to_next_diff() {
    const auto row = next_diff_row();
    if (!row.has_value()) {
        return std::nullopt;
    }
    return jump_to_row(*row);
}

std::optional<std::size_t> DiffController::jump_to_prev_diff() {
    const auto row = prev_diff_row();
    if (!row.has_value()) {
        return std::nullopt;
    }
    return jump_to_row(*row);
}

void DiffController::sync_edit_buffer(const bool edit_left, std::string& edit_buffer) const {
    if (session_.selected_row < 0) {
        return;
    }

    const auto row_index = static_cast<std::size_t>(session_.selected_row);
    const auto* row = row_at(row_index);
    if (row == nullptr) {
        return;
    }

    const auto& line = edit_left ? row->left : row->right;
    if (!line.has_value()) {
        edit_buffer.clear();
        return;
    }
    edit_buffer = line->mnemonic + (line->operands.empty() ? "" : " " + line->operands);
}

Result<void> DiffController::copy_row(const CopyDirection direction, const std::size_t row_index) {
    if (!session_.left.has_value() || !session_.right.has_value()) {
        return std::unexpected(AppError::from("Both sides must be loaded."));
    }
    if (row_index >= session_.total_rows()) {
        return std::unexpected(AppError::from("Row index is out of range."));
    }

    ensure_rows_loaded(row_index, row_index + 1);
    const auto* row = row_at(row_index);
    if (row == nullptr) {
        return std::unexpected(AppError::from(chunk_error_.empty() ? "Diff row is not loaded." : chunk_error_));
    }

    auto result = PatchService::copy_row(direction, *session_.left, *session_.right, *row);
    if (!result) {
        return result;
    }

    session_.chunk.valid = false;
    rebuild_diff_index();
    return {};
}

Result<void> DiffController::apply_assembly_edit(
    const bool left_side,
    const std::size_t row_index,
    const std::string_view text) {
    if (!session_.ready()) {
        return std::unexpected(AppError::from("Both sides must be loaded."));
    }
    if (row_index >= session_.total_rows()) {
        return std::unexpected(AppError::from("Row index is out of range."));
    }

    ensure_rows_loaded(row_index, row_index + 1);
    const auto* row = row_at(row_index);
    if (row == nullptr) {
        return std::unexpected(AppError::from(chunk_error_.empty() ? "Diff row is not loaded." : chunk_error_));
    }

    auto& document = left_side ? *session_.left : *session_.right;
    const auto& original = left_side ? row->left : row->right;
    if (!original.has_value()) {
        return std::unexpected(AppError::from("Selected row has no instruction on this side."));
    }

    auto assembled = assembler_.assemble_line(*original, text);
    if (!assembled) {
        return std::unexpected(assembled.error());
    }

    auto image = ps3::elf::Image::load(document.elf_bytes);
    if (!image) {
        return std::unexpected(AppError::from(image.error().message));
    }
    if (auto written = image->write_at(
            assembled->address,
            std::span<const std::uint8_t>{assembled->bytes.data(), assembled->bytes.size()});
        !written) {
        return std::unexpected(AppError::from(written.error().message));
    }

    document.elf_bytes = std::move(image->mutable_bytes());
    document.dirty = true;
    session_.chunk.valid = false;
    rebuild_diff_index();
    return {};
}

Result<void> DiffController::export_side(
    const bool left_side,
    const std::filesystem::path& path,
    const bool as_bin) {
    const auto& document = left_side ? session_.left : session_.right;
    if (!document.has_value()) {
        return std::unexpected(AppError::from("Nothing loaded on selected side."));
    }
    if (as_bin) {
        return exporter_.export_bin(*document, path, settings_);
    }
    return exporter_.export_elf(*document, path, true);
}

} // namespace eboot_diff
