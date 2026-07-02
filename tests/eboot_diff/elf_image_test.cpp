#include <catch2/catch_test_macros.hpp>

#include "test_elf_fixture.hpp"

#include "ps3/elf/image.hpp"

#include <cstring>

TEST_CASE("ElfImage loads executable PPC64 segment", "[elf]") {
    auto bytes = make_minimal_ppc64_elf({0x60, 0x00, 0x00, 0x00});
    auto image = ps3::elf::Image::load(bytes);
    REQUIRE(image.has_value());
    REQUIRE_FALSE(image->executable_segments().empty());

    auto value = image->read_at(0x10, 4);
    REQUIRE(value.has_value());
    REQUIRE((*value)[0] == 0x60);
}

TEST_CASE("ElfImage writes bytes back to segment", "[elf]") {
    auto bytes = make_minimal_ppc64_elf({0x60, 0x00, 0x00, 0x00});
    auto image = ps3::elf::Image::load(bytes);
    REQUIRE(image.has_value());

    const std::array<std::uint8_t, 4> patch{0x7C, 0x08, 0x02, 0xA6};
    REQUIRE(image->write_at(0x10, patch).has_value());

    auto value = image->read_at(0x10, 4);
    REQUIRE(value.has_value());
    REQUIRE(std::memcmp(value->data(), patch.data(), 4) == 0);
}
