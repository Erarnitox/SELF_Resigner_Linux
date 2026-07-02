#include "ps3/binary/endian.hpp"

#include <array>
#include <vector>

inline std::vector<std::uint8_t> make_minimal_ppc64_elf(const std::array<std::uint8_t, 4>& code) {
    std::vector<std::uint8_t> bytes(0x200, 0);
    bytes[0] = 0x7F;
    bytes[1] = 'E';
    bytes[2] = 'L';
    bytes[3] = 'F';
    bytes[4] = 2;
    bytes[5] = 2;
    bytes[0x12] = 0;
    bytes[0x13] = 21;
    ps3::binary::write_be64_at(bytes, 0x20, 0x40);
    ps3::binary::write_be16_at(bytes, 0x36, 0x38);
    ps3::binary::write_be16_at(bytes, 0x38, 1);

    const std::size_t phdr = 0x40;
    ps3::binary::write_be32_at(bytes, phdr + 0x00, 1);
    ps3::binary::write_be32_at(bytes, phdr + 0x04, 5);
    ps3::binary::write_be64_at(bytes, phdr + 0x08, 0x80);
    ps3::binary::write_be64_at(bytes, phdr + 0x10, 0x10);
    ps3::binary::write_be64_at(bytes, phdr + 0x18, 0x10);
    ps3::binary::write_be64_at(bytes, phdr + 0x20, 4);
    ps3::binary::write_be64_at(bytes, phdr + 0x28, 4);

    bytes[0x80] = code[0];
    bytes[0x81] = code[1];
    bytes[0x82] = code[2];
    bytes[0x83] = code[3];
    return bytes;
}
