#include "builder.hpp"

#include "ps3/binary/endian.hpp"

#include <fstream>
#include <vector>

namespace ps3::fself {

namespace {

struct Elf64Ehdr {
    std::array<std::uint8_t, 16> ident{};
    std::uint16_t type{0};
    std::uint16_t machine{0};
    std::uint32_t version{0};
    std::uint64_t entry{0};
    std::uint64_t phoff{0};
    std::uint64_t shoff{0};
    std::uint32_t flags{0};
    std::uint16_t ehsize{0};
    std::uint16_t phentsize{0};
    std::uint16_t phnum{0};
    std::uint16_t shentsize{0};
    std::uint16_t shnum{0};
    std::uint16_t shstrndx{0};
};

struct Elf64Phdr {
    std::uint32_t type{0};
    std::uint32_t flags{0};
    std::uint64_t offset{0};
    std::uint64_t vaddr{0};
    std::uint64_t paddr{0};
    std::uint64_t filesz{0};
    std::uint64_t memsz{0};
    std::uint64_t align{0};
};

bool read_elf(const std::vector<std::uint8_t>& data, Elf64Ehdr& ehdr, std::vector<Elf64Phdr>& phdrs) {
    if (data.size() < 0x40) {
        return false;
    }

    std::memcpy(ehdr.ident.data(), data.data(), 16);
    ehdr.type = ps3::binary::read_be16(data, 0x10);
    ehdr.machine = ps3::binary::read_be16(data, 0x12);
    ehdr.version = ps3::binary::read_be32(data, 0x14);
    ehdr.entry = ps3::binary::read_be64(data, 0x18);
    ehdr.phoff = ps3::binary::read_be64(data, 0x20);
    ehdr.shoff = ps3::binary::read_be64(data, 0x28);
    ehdr.flags = ps3::binary::read_be32(data, 0x30);
    ehdr.ehsize = ps3::binary::read_be16(data, 0x34);
    ehdr.phentsize = ps3::binary::read_be16(data, 0x36);
    ehdr.phnum = ps3::binary::read_be16(data, 0x38);
    ehdr.shentsize = ps3::binary::read_be16(data, 0x3A);
    ehdr.shnum = ps3::binary::read_be16(data, 0x3C);
    ehdr.shstrndx = ps3::binary::read_be16(data, 0x3E);

    if (ehdr.ident[0] != 0x7F || ehdr.ident[1] != 'E' || ehdr.ident[2] != 'L' || ehdr.ident[3] != 'F') {
        return false;
    }

    phdrs.clear();
    phdrs.reserve(ehdr.phnum);
    for (std::uint16_t i = 0; i < ehdr.phnum; ++i) {
        const auto offset = static_cast<std::size_t>(ehdr.phoff + static_cast<std::uint64_t>(i) * ehdr.phentsize);
        if (offset + 0x38 > data.size()) {
            return false;
        }
        Elf64Phdr phdr{};
        phdr.type = ps3::binary::read_be32(data, offset);
        phdr.flags = ps3::binary::read_be32(data, offset + 4);
        phdr.offset = ps3::binary::read_be64(data, offset + 8);
        phdr.vaddr = ps3::binary::read_be64(data, offset + 16);
        phdr.paddr = ps3::binary::read_be64(data, offset + 24);
        phdr.filesz = ps3::binary::read_be64(data, offset + 32);
        phdr.memsz = ps3::binary::read_be64(data, offset + 40);
        phdr.align = ps3::binary::read_be64(data, offset + 48);
        phdrs.push_back(phdr);
    }
    return true;
}

void write_ehdr(std::vector<std::uint8_t>& out, const Elf64Ehdr& ehdr) {
    out.insert(out.end(), ehdr.ident.begin(), ehdr.ident.end());
    ps3::binary::write_be16(out, ehdr.type);
    ps3::binary::write_be16(out, ehdr.machine);
    ps3::binary::write_be32(out, ehdr.version);
    ps3::binary::write_be64(out, ehdr.entry);
    ps3::binary::write_be64(out, ehdr.phoff);
    ps3::binary::write_be64(out, ehdr.shoff);
    ps3::binary::write_be32(out, ehdr.flags);
    ps3::binary::write_be16(out, ehdr.ehsize);
    ps3::binary::write_be16(out, ehdr.phentsize);
    ps3::binary::write_be16(out, ehdr.phnum);
    ps3::binary::write_be16(out, ehdr.shentsize);
    ps3::binary::write_be16(out, ehdr.shnum);
    ps3::binary::write_be16(out, ehdr.shstrndx);
}

void write_phdr(std::vector<std::uint8_t>& out, const Elf64Phdr& phdr) {
    ps3::binary::write_be32(out, phdr.type);
    ps3::binary::write_be32(out, phdr.flags);
    ps3::binary::write_be64(out, phdr.offset);
    ps3::binary::write_be64(out, phdr.vaddr);
    ps3::binary::write_be64(out, phdr.paddr);
    ps3::binary::write_be64(out, phdr.filesz);
    ps3::binary::write_be64(out, phdr.memsz);
    ps3::binary::write_be64(out, phdr.align);
}

void write_digest(std::vector<std::uint8_t>& out, bool npdrm, const std::optional<NpdrmInfo>& npdrm_info) {
    ps3::binary::write_be32(out, 2);
    ps3::binary::write_be32(out, 0x40);
    ps3::binary::write_be64(out, npdrm ? 1 : 0);

  const std::array<std::uint8_t, 0x14> magic_bits{
        0x62, 0x7c, 0xb1, 0x80, 0x8a, 0xb9, 0x38, 0xe3, 0x2c, 0x8c,
        0x09, 0x17, 0x08, 0x72, 0x6a, 0x57, 0x9e, 0x25, 0x86, 0xe4};
    out.insert(out.end(), magic_bits.begin(), magic_bits.end());
    out.insert(out.end(), 0x14, 0);
    out.insert(out.end(), 8, 0);

    if (!npdrm) {
        return;
    }

    ps3::binary::write_be32(out, 3);
    ps3::binary::write_be32(out, 0x90);
    ps3::binary::write_be64(out, 0);

    ps3::binary::write_be32(out, 0x4E504400);
    ps3::binary::write_be32(out, 1);
    ps3::binary::write_be32(out, 2);
    ps3::binary::write_be32(out, 1);

    if (npdrm_info.has_value()) {
        out.insert(out.end(), npdrm_info->content_id.begin(), npdrm_info->content_id.end());
    } else {
        out.insert(out.end(), 0x2F, static_cast<std::uint8_t>('0'));
        out.push_back(0);
    }

    const std::array<std::uint8_t, 0x10> file_sha1{
        0x42, 0x69, 0x74, 0x65, 0x20, 0x4d, 0x65, 0x2c, 0x20, 0x53,
        0x6f, 0x6e, 0x79, 0x00, 0xde, 0x07};
    out.insert(out.end(), file_sha1.begin(), file_sha1.end());
    out.insert(out.end(), 0x10, static_cast<std::uint8_t>(0xAB));
    out.insert(out.end(), 0x0F, static_cast<std::uint8_t>(0x01));
    out.push_back(0x02);
}

} // namespace

bool Builder::build(
    const std::filesystem::path& elf_path,
    const std::filesystem::path& self_path,
    const bool npdrm,
    const std::optional<NpdrmInfo>& npdrm_info) {
    std::ifstream input{elf_path, std::ios::binary};
    if (!input) {
        return false;
    }

    std::vector<std::uint8_t> elf{
        std::istreambuf_iterator<char>{input},
        std::istreambuf_iterator<char>{}};
    if (elf.empty()) {
        return false;
    }

    Elf64Ehdr ehdr{};
    std::vector<Elf64Phdr> phdrs;
    if (!read_elf(elf, ehdr, phdrs)) {
        return false;
    }

    constexpr std::size_t kSelfHeaderSize = 0x30;
    constexpr std::size_t kAppInfoSize = 0x18;
    constexpr std::size_t kPhdrOffsetEntrySize = 0x20;
    constexpr std::size_t kDigestSubHeaderSize = 0x10;
    constexpr std::size_t kDigestType2Size = 0x30;
    constexpr std::size_t kDigestTypeNpdrmSize = 0x70;

    const std::size_t app_info_offset = ps3::binary::align_up(kSelfHeaderSize, 0x10);
    const std::size_t elf_offset = ps3::binary::align_up(app_info_offset + kAppInfoSize, 0x10);
    const std::size_t phdr_offset = elf_offset + ehdr.ehsize;
    const std::size_t phdr_offsets_offset =
        ps3::binary::align_up(phdr_offset + phdrs.size() * 0x38, 0x10);
    const std::size_t digest_offset =
        phdr_offsets_offset + phdrs.size() * kPhdrOffsetEntrySize;
    const std::size_t digest_size = kDigestSubHeaderSize + kDigestType2Size
        + (npdrm ? (kDigestSubHeaderSize + kDigestTypeNpdrmSize) : 0);
    const std::size_t end_of_header = digest_offset + digest_size;
    const std::size_t payload_offset = ps3::binary::align_up(end_of_header, 0x80);
    const std::size_t shdr_offset = payload_offset + ehdr.shoff;

    std::vector<std::uint8_t> out;
    out.reserve(payload_offset + elf.size());

    ps3::binary::write_be32(out, 0x53434500);
    ps3::binary::write_be32(out, 2);
    ps3::binary::write_be16(out, 0x8000);
    ps3::binary::write_be16(out, 1);
    ps3::binary::write_be32(out, static_cast<std::uint32_t>(end_of_header - 0x10));
    ps3::binary::write_be64(out, payload_offset);
    ps3::binary::write_be64(out, elf.size());
    ps3::binary::write_be64(out, 3);
    ps3::binary::write_be64(out, app_info_offset);
    ps3::binary::write_be64(out, elf_offset);
    ps3::binary::write_be64(out, phdr_offset);
    ps3::binary::write_be64(out, shdr_offset);
    ps3::binary::write_be64(out, phdr_offsets_offset);
    ps3::binary::write_be64(out, 0);
    ps3::binary::write_be64(out, digest_offset);
    ps3::binary::write_be64(out, digest_size);

    ps3::binary::write_padding(out, 0x10);

    ps3::binary::write_be64(out, 0x1010000001000003ULL);
    ps3::binary::write_be32(out, 0x01000002);
    ps3::binary::write_be32(out, npdrm ? 0x8 : 0x4);
    ps3::binary::write_be64(out, 0x0001000000000000ULL);

    ps3::binary::write_padding(out, 0x10);

    write_ehdr(out, ehdr);
    for (const auto& phdr : phdrs) {
        write_phdr(out, phdr);
    }

    ps3::binary::write_padding(out, 0x10);

    for (const auto& phdr : phdrs) {
        ps3::binary::write_be64(out, phdr.offset + payload_offset);
        ps3::binary::write_be64(out, phdr.filesz);
        ps3::binary::write_be32(out, 1);
        ps3::binary::write_be32(out, 0);
        ps3::binary::write_be32(out, 0);
        ps3::binary::write_be32(out, phdr.type == 1 ? 2 : 0);
    }

    ps3::binary::write_padding(out, 0x10);
    write_digest(out, npdrm, npdrm_info);
    ps3::binary::write_padding(out, 0x80);
    out.insert(out.end(), elf.begin(), elf.end());

    std::ofstream output{self_path, std::ios::binary | std::ios::trunc};
    if (!output) {
        return false;
    }
    output.write(reinterpret_cast<const char*>(out.data()), static_cast<std::streamsize>(out.size()));
    return static_cast<bool>(output);
}

} // namespace ps3::fself
