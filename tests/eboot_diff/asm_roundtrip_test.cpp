#include <catch2/catch_test_macros.hpp>

#include "eboot_diff/services/assembler.hpp"

TEST_CASE("AssemblerService assembles li r3, 1", "[asm]") {
    eboot_diff::AssemblerService assembler{};
    eboot_diff::InstructionLine original{};
    original.address = 0x1000;

    auto line = assembler.assemble_line(original, "addi r3, r0, 1");
    if (!line) {
        FAIL(line.error().message);
    }
    REQUIRE(line->bytes.size() == 4);
}
