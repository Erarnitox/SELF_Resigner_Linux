#include <catch2/catch_test_macros.hpp>

#include "test_elf_fixture.hpp"

#include "eboot_diff/services/patch_service.hpp"

#include "ps3/elf/image.hpp"

TEST_CASE("PatchService copies instruction bytes between documents", "[patch]") {
    eboot_diff::EbootDocument left{};
    eboot_diff::EbootDocument right{};
    left.elf_bytes = make_minimal_ppc64_elf({0x7C, 0x08, 0x02, 0xA6});
    right.elf_bytes = make_minimal_ppc64_elf({0x60, 0x00, 0x00, 0x00});

    eboot_diff::AlignedRow row{};
    row.left = eboot_diff::InstructionLine{};
    row.left->address = 0x10;
    row.left->bytes = {0x7C, 0x08, 0x02, 0xA6};

    REQUIRE(eboot_diff::PatchService::copy_row(
        eboot_diff::CopyDirection::LeftToRight,
        left,
        right,
        row).has_value());

    auto image = ps3::elf::Image::load(right.elf_bytes);
    REQUIRE(image.has_value());
    auto bytes = image->read_at(0x10, 4);
    REQUIRE(bytes.has_value());
    REQUIRE((*bytes)[0] == 0x7C);
}
