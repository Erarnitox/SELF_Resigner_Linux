#include "extractor.hpp"

#include "ps3/binary/endian.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <span>
#include <vector>
#include <zlib.h>

namespace ps3::fself {

namespace {

struct ElfHdr {
    std::uint16_t phnum{0};
    std::uint16_t phentsize{0};
    std::uint64_t phoff{0};
    std::uint64_t shoff{0};
    std::uint16_t shnum{0};
    bool arch64{true};
};

struct ElfPhdr {
    std::uint64_t offset{0};
    std::uint64_t filesz{0};
};

struct SelfSection {
    std::uint64_t self_offset{0};
    std::uint64_t size{0};
    bool compressed{false};
    std::uint64_t size_uncompressed{0};
    std::uint64_t elf_offset{0};
};

struct SelfSec {
    std::uint32_t idx{0};
    std::uint64_t offset{0};
    std::uint64_t size{0};
    bool compressed{false};
    std::uint64_t next{0};
};

bool decompress_zlib(
    const std::uint8_t* input,
    std::size_t input_size,
    std::vector<std::uint8_t>& output) {
    z_stream stream{};
    if (inflateInit(&stream) != Z_OK) {
        return false;
    }

    std::vector<std::uint8_t> buffer(input_size * 4 + 0x1000);
    stream.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(input));
    stream.avail_in = static_cast<uInt>(input_size);
    stream.next_out = reinterpret_cast<Bytef*>(buffer.data());
    stream.avail_out = static_cast<uInt>(buffer.size());

    const int result = inflate(&stream, Z_FINISH);
    inflateEnd(&stream);
    if (result != Z_STREAM_END && result != Z_OK) {
        return false;
    }

    output.assign(buffer.begin(), buffer.begin() + stream.total_out);
    return true;
}

bool read_phdr(
    std::span<const std::uint8_t> elf,
    const ElfHdr& hdr,
    std::uint32_t index,
    ElfPhdr& phdr) {
    const auto offset = static_cast<std::size_t>(hdr.phoff + static_cast<std::uint64_t>(index) * hdr.phentsize);
    if (offset + 0x38 > elf.size()) {
        return false;
    }
    phdr.offset = ps3::binary::read_be64(elf, offset + 8);
    phdr.filesz = ps3::binary::read_be64(elf, offset + 32);
    return true;
}

bool build_sections(
    std::span<const std::uint8_t> self,
    std::span<const std::uint8_t> elf,
    const ElfHdr& hdr,
    std::uint64_t sec_offset,
    std::uint64_t header_len,
    std::uint64_t filesize,
    std::vector<SelfSection>& sections) {
    std::vector<SelfSec> compressed_sections;
    for (std::uint32_t i = 0; i < hdr.phnum; ++i) {
        const auto ptr_offset = static_cast<std::size_t>(sec_offset + static_cast<std::uint64_t>(i) * 0x20);
        if (ptr_offset + 0x28 > self.size()) {
            return false;
        }
        SelfSec sec{};
        sec.idx = i;
        sec.offset = ps3::binary::read_be64(self, ptr_offset);
        sec.size = ps3::binary::read_be64(self, ptr_offset + 8);
        sec.compressed = ps3::binary::read_be32(self, ptr_offset + 0x10) == 2;
        sec.next = ps3::binary::read_be64(self, ptr_offset + 0x20);
        if (sec.compressed) {
            compressed_sections.push_back(sec);
        }
    }

    std::ranges::sort(compressed_sections, [](const SelfSec& a, const SelfSec& b) {
        return a.offset < b.offset;
    });

    std::uint64_t elf_offset = 0;
    std::uint64_t self_offset = header_len;
    std::size_t section_index = 0;
    std::size_t compressed_index = 0;

    while (elf_offset < filesize) {
        SelfSection section{};
        if (compressed_index >= compressed_sections.size()) {
            section.self_offset = self_offset;
            section.size = filesize - elf_offset;
            section.compressed = false;
            section.size_uncompressed = section.size;
            section.elf_offset = elf_offset;
            elf_offset = filesize;
        } else {
            const auto& sec = compressed_sections[compressed_index];
            if (self_offset == sec.offset) {
                section.self_offset = self_offset;
                section.size = sec.size;
                section.compressed = true;
                ElfPhdr phdr{};
                if (!read_phdr(elf, hdr, sec.idx, phdr)) {
                    return false;
                }
                section.size_uncompressed = phdr.filesz;
                section.elf_offset = phdr.offset;
                elf_offset = phdr.offset + phdr.filesz;
                self_offset = sec.next;
                ++compressed_index;
            } else {
                ElfPhdr phdr{};
                if (!read_phdr(elf, hdr, sec.idx, phdr)) {
                    return false;
                }
                section.self_offset = self_offset;
                section.size = phdr.offset - elf_offset;
                section.compressed = false;
                section.size_uncompressed = section.size;
                section.elf_offset = elf_offset;
                elf_offset += section.size;
                self_offset += sec.offset - self_offset;
            }
        }

        sections.push_back(section);
        ++section_index;
        if (section_index > 255) {
            return false;
        }
    }

    return true;
}

bool write_elf_sections(
    const std::vector<std::uint8_t>& self,
    const std::vector<SelfSection>& sections,
    std::vector<std::uint8_t>& output) {
    for (const auto& section : sections) {
        if (section.elf_offset + section.size_uncompressed > output.size()) {
            output.resize(static_cast<std::size_t>(section.elf_offset + section.size_uncompressed), 0);
        }

        if (section.compressed) {
            std::vector<std::uint8_t> decompressed;
            if (!decompress_zlib(
                    self.data() + section.self_offset,
                    static_cast<std::size_t>(section.size),
                    decompressed)) {
                return false;
            }
            if (decompressed.size() != section.size_uncompressed) {
                decompressed.resize(static_cast<std::size_t>(section.size_uncompressed), 0);
            }
            std::memcpy(output.data() + section.elf_offset, decompressed.data(), decompressed.size());
        } else {
            if (section.self_offset + section.size > self.size()) {
                return false;
            }
            std::memcpy(
                output.data() + section.elf_offset,
                self.data() + section.self_offset,
                static_cast<std::size_t>(section.size));
        }
    }
    return true;
}

bool finalize_elf_layout(std::vector<std::uint8_t>& output, std::span<const std::uint8_t> elf, bool arch64) {
    constexpr std::array<char, 4> kElfMagic{'\x7F', 'E', 'L', 'F'};
    if (output.size() >= 4 && std::equal(kElfMagic.begin(), kElfMagic.end(), output.begin())) {
        return true;
    }

    const auto embedded_elf_offset = ps3::binary::read_be64(elf, 0x30 - 0x30);
    (void)embedded_elf_offset;

    const auto phdr_offset = ps3::binary::read_be64(elf, 0x38) - ps3::binary::read_be64(elf, 0x30);
    const auto shdr_offset = ps3::binary::read_be64(elf, 0x40) - ps3::binary::read_be64(elf, 0x30);
    const auto n_phdr = ps3::binary::read_be16(elf, arch64 ? 0x38 : 0x2C);
    const auto n_shdr = ps3::binary::read_be16(elf, arch64 ? 0x3C : 0x30);

    const char shstrtab[] = ".unknown\0\0";
    const auto phdr_size = arch64 ? 0x38U : 0x20U;
    const auto shdr_size = arch64 ? 0x40U : 0x28U;
    const auto ehdr_size = arch64 ? 0x48U : 0x34U;
    const auto phdr_offset_new = ehdr_size;
    const auto shdr_offset_new = static_cast<std::uint64_t>(output.size());
    const auto shstrtab_offset = shdr_offset_new + static_cast<std::uint64_t>(n_shdr) * shdr_size;

    output.resize(static_cast<std::size_t>(shstrtab_offset + sizeof(shstrtab)), 0);
    std::memcpy(output.data(), elf.data(), ehdr_size);
    std::memcpy(output.data() + phdr_offset_new, elf.data() + phdr_offset, static_cast<std::size_t>(n_phdr) * phdr_size);
    std::memcpy(output.data() + shdr_offset_new, elf.data() + shdr_offset, static_cast<std::size_t>(n_shdr) * shdr_size);
    std::memcpy(output.data() + shstrtab_offset, shstrtab, sizeof(shstrtab));

    if (arch64) {
        ps3::binary::write_be64_at(output, 0x20, phdr_offset_new);
        ps3::binary::write_be64_at(output, 0x28, shdr_offset_new);
    } else {
        ps3::binary::write_be32_at(output, 0x1C, static_cast<std::uint32_t>(phdr_offset_new));
        ps3::binary::write_be32_at(output, 0x20, static_cast<std::uint32_t>(shdr_offset_new));
    }

    return true;
}

} // namespace

bool Extractor::extract(const std::filesystem::path& self_path, const std::filesystem::path& elf_path) {
    std::ifstream input{self_path, std::ios::binary};
    if (!input) {
        return false;
    }

    std::vector<std::uint8_t> self{
        std::istreambuf_iterator<char>{input},
        std::istreambuf_iterator<char>{}};
    if (self.size() < 0x58 || ps3::binary::read_be32(self, 0) != 0x53434500) {
        return false;
    }

    const auto key_ver = ps3::binary::read_be16(self, 0x08);
    if (key_ver != 0x8000) {
        return false;
    }

    const auto header_len = ps3::binary::read_be64(self, 0x10);
    const auto filesize = ps3::binary::read_be64(self, 0x18);
    const auto sec_offset = ps3::binary::read_be64(self, 0x48);
    const auto elf_offset = ps3::binary::read_be64(self, 0x30);

    if (elf_offset >= self.size()) {
        return false;
    }

    std::span<const std::uint8_t> elf{self.data() + elf_offset, self.size() - elf_offset};
    ElfHdr hdr{};
    hdr.arch64 = elf[4] == 2;
    hdr.phnum = ps3::binary::read_be16(elf, hdr.arch64 ? 0x38 : 0x2C);
    hdr.phentsize = ps3::binary::read_be16(elf, hdr.arch64 ? 0x36 : 0x2A);
    hdr.phoff = ps3::binary::read_be64(elf, hdr.arch64 ? 0x20 : 0x1C);
    hdr.shoff = ps3::binary::read_be64(elf, hdr.arch64 ? 0x28 : 0x20);
    hdr.shnum = ps3::binary::read_be16(elf, hdr.arch64 ? 0x3C : 0x30);

    std::vector<SelfSection> sections;
    if (!build_sections(self, elf, hdr, sec_offset, header_len, filesize, sections)) {
        return false;
    }

    std::vector<std::uint8_t> output;
    if (!write_elf_sections(self, sections, output)) {
        return false;
    }

    if (!finalize_elf_layout(output, elf, hdr.arch64)) {
        return false;
    }

    std::ofstream out{elf_path, std::ios::binary | std::ios::trunc};
    if (!out) {
        return false;
    }
    out.write(reinterpret_cast<const char*>(output.data()), static_cast<std::streamsize>(output.size()));
    return static_cast<bool>(out);
}

} // namespace ps3::fself
