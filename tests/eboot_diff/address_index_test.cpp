#include <catch2/catch_test_macros.hpp>

#include "eboot_diff/services/address_index.hpp"
#include "eboot_diff/services/diff_engine.hpp"
#include "eboot_diff/services/disassembler.hpp"
#include "test_elf_fixture.hpp"

TEST_CASE("AddressIndex builds sorted executable addresses", "[address_index]") {
    eboot_diff::EbootDocument document{};
    document.elf_bytes = make_minimal_ppc64_elf({0x60, 0x00, 0x00, 0x00});

    const auto addresses = eboot_diff::AddressIndex::build_executable_addresses(document);
    REQUIRE(addresses.size() == 1);
    REQUIRE(addresses.front() == 0x10);
}

TEST_CASE("AddressIndex merge produces union of both sides", "[address_index]") {
    const std::vector<std::uint64_t> left{0x1000, 0x1008};
    const std::vector<std::uint64_t> right{0x1004, 0x1008};
    const auto merged = eboot_diff::AddressIndex::merge_aligned(left, right);

    REQUIRE(merged.size() == 3);
    REQUIRE(merged[0] == 0x1000);
    REQUIRE(merged[1] == 0x1004);
    REQUIRE(merged[2] == 0x1008);
}

TEST_CASE("DisassemblerService disassembles address slices", "[address_index]") {
    eboot_diff::EbootDocument document{};
    document.elf_bytes = make_minimal_ppc64_elf({0x60, 0x00, 0x00, 0x00});

    const auto addresses = eboot_diff::AddressIndex::build_executable_addresses(document);
    REQUIRE(addresses.size() == 1);

    eboot_diff::DisassemblerService disassembler{};
    const auto view = disassembler.disassemble_addresses(
        document,
        std::span<const std::uint64_t>{addresses.data(), addresses.size()});
    REQUIRE(view);
    REQUIRE(view->lines.size() == 1);
    REQUIRE(view->lines.front().mnemonic == "nop");
}

TEST_CASE("DiffEngine align_slice matches full align for a slice", "[address_index]") {
    eboot_diff::DisassemblyView left{};
    eboot_diff::DisassemblyView right{};

    eboot_diff::InstructionLine shared{};
    shared.address = 0x1000;
    shared.bytes = {0x60, 0x00, 0x00, 0x00};
    shared.mnemonic = "nop";
    left.lines.push_back(shared);
    right.lines.push_back(shared);

    eboot_diff::InstructionLine changed = shared;
    changed.address = 0x1004;
    changed.bytes = {0x38, 0x60, 0x00, 0x01};
    changed.mnemonic = "li";
    changed.operands = "r3, 1";
    right.lines.push_back(changed);

    const std::array<std::uint64_t, 2> addresses{0x1000, 0x1004};
    const auto slice = eboot_diff::DiffEngine::align_slice(
        std::span<const std::uint64_t>{addresses.data(), addresses.size()},
        left,
        right);

    REQUIRE(slice.size() == 2);
    REQUIRE(slice[0].kind == eboot_diff::DiffKind::Equal);
    REQUIRE(slice[1].kind == eboot_diff::DiffKind::RightOnly);
}

TEST_CASE("AddressIndex build_diff_row_indices finds byte differences", "[address_index]") {
    eboot_diff::EbootDocument left{};
    left.elf_bytes = make_minimal_ppc64_elf({0x60, 0x00, 0x00, 0x00});

    eboot_diff::EbootDocument right{};
    right.elf_bytes = make_minimal_ppc64_elf({0x38, 0x60, 0x00, 0x01});

    const auto left_addresses = eboot_diff::AddressIndex::build_executable_addresses(left);
    const auto right_addresses = eboot_diff::AddressIndex::build_executable_addresses(right);
    const auto aligned = eboot_diff::AddressIndex::merge_aligned(left_addresses, right_addresses);
    const auto diff_rows = eboot_diff::AddressIndex::build_diff_row_indices(left, right, aligned);

    REQUIRE(diff_rows.size() == 1);
    REQUIRE(diff_rows.front() == 0);
}

TEST_CASE("AddressIndex build_diff_row_indices ignores equal rows", "[address_index]") {
    eboot_diff::EbootDocument left{};
    left.elf_bytes = make_minimal_ppc64_elf({0x60, 0x00, 0x00, 0x00});

    const eboot_diff::EbootDocument right = left;
    const auto aligned = eboot_diff::AddressIndex::build_executable_addresses(left);
    const auto diff_rows = eboot_diff::AddressIndex::build_diff_row_indices(left, right, aligned);

    REQUIRE(diff_rows.empty());
}

TEST_CASE("AddressIndex parse_address accepts decimal and hex", "[address_index]") {
    REQUIRE(eboot_diff::AddressIndex::parse_address("4096") == 4096);
    REQUIRE(eboot_diff::AddressIndex::parse_address("0x1000") == 4096);
    REQUIRE(eboot_diff::AddressIndex::parse_address("  0X1004  ") == 4100);
    REQUIRE_FALSE(eboot_diff::AddressIndex::parse_address("not-an-address").has_value());
}

TEST_CASE("AddressIndex find_row_for_address resolves aligned rows", "[address_index]") {
    const std::vector<std::uint64_t> aligned{0x1000, 0x1004, 0x1008};
    REQUIRE(eboot_diff::AddressIndex::find_row_for_address(aligned, 0x1004) == 1);
    REQUIRE(eboot_diff::AddressIndex::find_row_for_address(aligned, 0x1005) == 1);
    REQUIRE(eboot_diff::AddressIndex::find_row_for_address(aligned, 0x1009) == 2);
}
