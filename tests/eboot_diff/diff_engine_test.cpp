#include <catch2/catch_test_macros.hpp>

#include "eboot_diff/services/diff_engine.hpp"

TEST_CASE("DiffEngine aligns equal and changed rows", "[diff]") {
    eboot_diff::DisassemblyView left{};
    eboot_diff::DisassemblyView right{};

    eboot_diff::InstructionLine shared{};
    shared.address = 0x1000;
    shared.bytes = {0x7C, 0x08, 0x02, 0xA6};
    shared.mnemonic = "mflr";
    shared.operands = "r0";

    eboot_diff::InstructionLine changed = shared;
    changed.bytes = {0x38, 0x60, 0x00, 0x01};
    changed.mnemonic = "addi";
    changed.operands = "3, 0, 1";

    left.lines.push_back(shared);
    right.lines.push_back(changed);

    const auto rows = eboot_diff::DiffEngine::align(left, right);
    REQUIRE(rows.size() == 1);
    REQUIRE(rows.front().kind == eboot_diff::DiffKind::Changed);
}

TEST_CASE("DiffEngine reports left-only rows", "[diff]") {
    eboot_diff::DisassemblyView left{};
    eboot_diff::DisassemblyView right{};

    eboot_diff::InstructionLine only_left{};
    only_left.address = 0x2000;
    only_left.bytes = {0x60, 0x00, 0x00, 0x00};
    only_left.mnemonic = "nop";
    left.lines.push_back(only_left);

    const auto rows = eboot_diff::DiffEngine::align(left, right);
    REQUIRE(rows.size() == 1);
    REQUIRE(rows.front().kind == eboot_diff::DiffKind::LeftOnly);
}

TEST_CASE("DiffEngine aligns identical addresses as equal", "[diff]") {
    eboot_diff::DisassemblyView left{};
    eboot_diff::DisassemblyView right{};

    eboot_diff::InstructionLine line{};
    line.address = 0x3000;
    line.bytes = {0x60, 0x00, 0x00, 0x00};
    line.mnemonic = "nop";
    left.lines.push_back(line);
    right.lines.push_back(line);

    const auto rows = eboot_diff::DiffEngine::align(left, right);
    REQUIRE(rows.size() == 1);
    REQUIRE(rows.front().kind == eboot_diff::DiffKind::Equal);
}
