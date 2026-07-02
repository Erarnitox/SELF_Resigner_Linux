#include <catch2/catch_test_macros.hpp>

#include "test_elf_fixture.hpp"

#include "eboot_diff/services/disassembler.hpp"

TEST_CASE("DisassemblerService decodes mflr r0", "[disasm]") {
    eboot_diff::EbootDocument document{};
    document.elf_bytes = make_minimal_ppc64_elf({0x7C, 0x08, 0x02, 0xA6});

    eboot_diff::DisassemblerService disassembler{};
    auto view = disassembler.disassemble(document);
    REQUIRE(view.has_value());
    REQUIRE_FALSE(view->lines.empty());
    REQUIRE(view->lines.front().mnemonic == "mflr");
}
