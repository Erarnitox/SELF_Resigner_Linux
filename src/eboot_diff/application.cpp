#include "application.hpp"

#include "services/address_index.hpp"
#include "services/diff_engine.hpp"
#include "services/disassembler.hpp"
#include "services/eboot_loader.hpp"
#include "ui/main_window.hpp"
#include "util/logger.hpp"

#include <algorithm>
#include <fstream>
#include <span>

namespace eboot_diff {

Application::Application()
    : sce_ops_{settings_},
      controller_{sce_ops_, settings_} {}

int Application::run_gui() {
    MainWindow window{controller_, project_};
    if (window.should_close()) {
        Logger::error("Failed to initialize GUI.");
        return 1;
    }

    if (auto result = project_.try_restore_last_project(controller_); !result) {
        window.set_status_message(result.error().message);
    }
    window.update_title();

    while (!window.should_close()) {
        window.render_frame();
    }
    return 0;
}

int Application::run_headless_self_test() {
    DisassemblyView left_view{};

    InstructionLine a{};
    a.address = 0x1000;
    a.bytes = {0x7C, 0x08, 0x02, 0xA6};
    a.mnemonic = "mflr";
    a.operands = "r0";
    left_view.lines.push_back(a);

    InstructionLine b = a;
    b.bytes = {0x38, 0x60, 0x00, 0x01};
    b.mnemonic = "li";
    b.operands = "r3, 1";

    DisassemblyView right_view{};
    right_view.lines.push_back(a);
    right_view.lines.push_back(b);

    const auto rows = DiffEngine::align(left_view, right_view);
    if (rows.empty()) {
        Logger::error("Self-test failed: no diff rows produced.");
        return 1;
    }

    Logger::info("Self-test passed.");
    return 0;
}

int Application::run_headless_diff(
    const std::filesystem::path& left,
    const std::filesystem::path& right,
    const std::filesystem::path& report) {
    EbootLoader loader{sce_ops_};

    auto left_doc = loader.load(left);
    if (!left_doc) {
        Logger::error(left_doc.error().message);
        return 1;
    }
    auto right_doc = loader.load(right);
    if (!right_doc) {
        Logger::error(right_doc.error().message);
        return 1;
    }

    const auto left_addresses = AddressIndex::build_executable_addresses(*left_doc);
    const auto right_addresses = AddressIndex::build_executable_addresses(*right_doc);
    const auto aligned_addresses = AddressIndex::merge_aligned(left_addresses, right_addresses);

    std::ofstream out{report};
    if (!out) {
        Logger::error("Failed to open report file.");
        return 1;
    }

    DisassemblerService disassembler{};
    constexpr std::size_t kChunkRows = 4096;
    for (std::size_t row_begin = 0; row_begin < aligned_addresses.size(); row_begin += kChunkRows) {
        const std::size_t row_end = std::min(row_begin + kChunkRows, aligned_addresses.size());
        const auto address_slice = std::span<const std::uint64_t>{
            aligned_addresses.data() + row_begin,
            row_end - row_begin};

        auto left_view = disassembler.disassemble_addresses(*left_doc, address_slice);
        auto right_view = disassembler.disassemble_addresses(*right_doc, address_slice);
        if (!left_view || !right_view) {
            Logger::error("Disassembly failed.");
            return 1;
        }

        const auto rows = DiffEngine::align_slice(address_slice, *left_view, *right_view);
        for (const auto& row : rows) {
            switch (row.kind) {
            case DiffKind::Equal:
                out << "= ";
                break;
            case DiffKind::Changed:
                out << "~ ";
                break;
            case DiffKind::LeftOnly:
                out << "< ";
                break;
            case DiffKind::RightOnly:
                out << "> ";
                break;
            }
            if (row.left) {
                out << row.left->display_text();
            }
            out << " | ";
            if (row.right) {
                out << row.right->display_text();
            }
            out << '\n';
        }
    }

    Logger::info("Diff report written to " + report.string());
    return 0;
}

} // namespace eboot_diff
