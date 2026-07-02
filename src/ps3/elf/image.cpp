#include "image.hpp"

#include "ps3/binary/endian.hpp"

#include <algorithm>
#include <cstring>

namespace ps3::elf {

namespace {

constexpr std::uint8_t kElfMagic0 = 0x7F;
constexpr std::uint8_t kElfMagic1 = 'E';
constexpr std::uint8_t kElfMagic2 = 'L';
constexpr std::uint8_t kElfMagic3 = 'F';

constexpr std::uint16_t kElfClass64 = 2;
constexpr std::uint16_t kElfDataBe = 2;
constexpr std::uint16_t kMachinePpc64 = 21;

constexpr std::uint32_t kPtLoad = 1;
constexpr std::uint32_t kPfX = 1;

constexpr std::uint32_t kShfExecInstr = 0x4;

constexpr std::size_t kPhdr64Size = 56;
constexpr std::size_t kShdr64Size = 64;

bool is_elf_magic(std::span<const std::uint8_t> data) {
    return data.size() >= 4
        && data[0] == kElfMagic0
        && data[1] == kElfMagic1
        && data[2] == kElfMagic2
        && data[3] == kElfMagic3;
}

} // namespace

Image::Image(std::vector<std::uint8_t> bytes) : bytes_(std::move(bytes)) {}

std::expected<Image, AppError> Image::load(std::vector<std::uint8_t> bytes) {
    Image image{std::move(bytes)};
    if (auto parsed = image.parse(); !parsed) {
        return std::unexpected(parsed.error());
    }
    return image;
}

std::expected<void, AppError> Image::parse() {
    if (!is_elf_magic(bytes_)) {
        return std::unexpected(AppError{.message = "Not a valid ELF file."});
    }
    if (bytes_.size() < 0x40) {
        return std::unexpected(AppError{.message = "ELF header is truncated."});
    }
    if (bytes_[4] != kElfClass64) {
        return std::unexpected(AppError{.message = "Only ELF64 images are supported."});
    }
    if (bytes_[5] != kElfDataBe) {
        return std::unexpected(AppError{.message = "Only big-endian ELF images are supported."});
    }

    const auto machine = ps3::binary::read_be16(bytes_, 0x12);
    if (machine != kMachinePpc64) {
        return std::unexpected(AppError{.message = "ELF machine type is not PPC64."});
    }

    const auto phoff = ps3::binary::read_be64(bytes_, 0x20);
    const auto phentsize = ps3::binary::read_be16(bytes_, 0x36);
    const auto phnum = ps3::binary::read_be16(bytes_, 0x38);

    if (phentsize < kPhdr64Size) {
        return std::unexpected(AppError{.message = "Invalid program header entry size."});
    }

    for (std::uint16_t index = 0; index < phnum; ++index) {
        const auto offset = static_cast<std::size_t>(phoff + static_cast<std::uint64_t>(index) * phentsize);
        if (offset + kPhdr64Size > bytes_.size()) {
            return std::unexpected(AppError{.message = "Program header table is truncated."});
        }

        const auto type = ps3::binary::read_be32(bytes_, offset);
        const auto flags = ps3::binary::read_be32(bytes_, offset + 0x04);
        const auto file_offset = ps3::binary::read_be64(bytes_, offset + 0x08);
        const auto vaddr = ps3::binary::read_be64(bytes_, offset + 0x10);

        std::uint64_t filesz = 0;
        std::uint64_t memsz = 0;
        if (phentsize >= 56) {
            // PS3 / extended ELF64 program headers include p_paddr at 0x18.
            filesz = ps3::binary::read_be64(bytes_, offset + 0x20);
            memsz = ps3::binary::read_be64(bytes_, offset + 0x28);
        } else {
            filesz = ps3::binary::read_be64(bytes_, offset + 0x18);
            memsz = ps3::binary::read_be64(bytes_, offset + 0x20);
        }

        if (type != kPtLoad) {
            continue;
        }

        LoadSegment segment{
            .virtual_address = vaddr,
            .file_offset = file_offset,
            .file_size = filesz,
            .memory_size = memsz,
            .name = "PT_LOAD",
        };
        load_segments_.push_back(segment);
        if ((flags & kPfX) != 0 && filesz > 0) {
            executable_segments_.push_back(segment);
        }
    }

    if (executable_segments_.empty()) {
        return std::unexpected(AppError{.message = "No executable PT_LOAD segments found."});
    }

    std::ranges::sort(executable_segments_, [](const LoadSegment& a, const LoadSegment& b) {
        return a.virtual_address < b.virtual_address;
    });

    if (auto sections = parse_sections(); !sections) {
        return std::unexpected(sections.error());
    }

    if (code_regions_.empty()) {
        for (const auto& segment : executable_segments_) {
            if (segment.file_size < 4) {
                continue;
            }
            code_regions_.push_back(CodeRegion{
                .virtual_address = segment.virtual_address,
                .file_offset = segment.file_offset,
                .size = segment.file_size,
                .name = segment.name,
            });
        }
    }

    if (code_regions_.empty()) {
        return std::unexpected(AppError{.message = "No executable code regions found."});
    }

    return {};
}

std::expected<void, AppError> Image::parse_sections() {
    if (bytes_.size() < 0x40) {
        return {};
    }

    const auto shoff = ps3::binary::read_be64(bytes_, 0x28);
    const auto shentsize = ps3::binary::read_be16(bytes_, 0x3A);
    const auto shnum = ps3::binary::read_be16(bytes_, 0x3C);
    const auto shstrndx = ps3::binary::read_be16(bytes_, 0x3E);

    if (shnum == 0 || shoff == 0 || shentsize < kShdr64Size) {
        return {};
    }

    const auto string_table_offset = static_cast<std::size_t>(shoff + static_cast<std::uint64_t>(shstrndx) * shentsize);
    if (string_table_offset + kShdr64Size > bytes_.size()) {
        return std::unexpected(AppError{.message = "Section header string table index is invalid."});
    }

    const auto shstr_name = ps3::binary::read_be32(bytes_, string_table_offset);
    const auto shstr_addr = ps3::binary::read_be64(bytes_, string_table_offset + 0x10);
    const auto shstr_file_offset = ps3::binary::read_be64(bytes_, string_table_offset + 0x18);
    const auto shstr_size = ps3::binary::read_be64(bytes_, string_table_offset + 0x20);
    (void)shstr_name;
    (void)shstr_addr;

    if (shstr_file_offset + shstr_size > bytes_.size()) {
        return std::unexpected(AppError{.message = "Section header string table is truncated."});
    }

    const auto read_section_name = [&](const std::uint32_t name_offset) -> std::string {
        const auto absolute = static_cast<std::size_t>(shstr_file_offset + name_offset);
        if (absolute >= bytes_.size()) {
            return {};
        }
        std::string name;
        for (std::size_t index = absolute; index < bytes_.size() && bytes_[index] != 0; ++index) {
            name.push_back(static_cast<char>(bytes_[index]));
        }
        if (name.empty()) {
            return "section";
        }
        return name;
    };

    for (std::uint16_t index = 0; index < shnum; ++index) {
        const auto offset = static_cast<std::size_t>(shoff + static_cast<std::uint64_t>(index) * shentsize);
        if (offset + kShdr64Size > bytes_.size()) {
            return std::unexpected(AppError{.message = "Section header table is truncated."});
        }

        const auto name_offset = ps3::binary::read_be32(bytes_, offset);
        const auto type = ps3::binary::read_be32(bytes_, offset + 0x04);
        const auto flags = ps3::binary::read_be64(bytes_, offset + 0x08);
        const auto address = ps3::binary::read_be64(bytes_, offset + 0x10);
        const auto file_offset = ps3::binary::read_be64(bytes_, offset + 0x18);
        const auto size = ps3::binary::read_be64(bytes_, offset + 0x20);

        if (type != 1 || (flags & kShfExecInstr) == 0 || size < 4) {
            continue;
        }
        if (file_offset + size > bytes_.size()) {
            return std::unexpected(AppError{.message = "Executable section exceeds ELF bounds."});
        }

        auto name = read_section_name(name_offset);
        if (name == "section") {
            name = "section_" + std::to_string(index);
        }

        code_regions_.push_back(CodeRegion{
            .virtual_address = address,
            .file_offset = file_offset,
            .size = size,
            .name = std::move(name),
        });
    }

    std::ranges::sort(code_regions_, [](const CodeRegion& a, const CodeRegion& b) {
        return a.virtual_address < b.virtual_address;
    });

    return {};
}

std::expected<std::span<const std::uint8_t>, AppError> Image::read_at(
    const std::uint64_t virtual_address,
    const std::size_t size) const {
    for (const auto& segment : load_segments_) {
        const auto segment_end = segment.virtual_address + segment.file_size;
        if (virtual_address < segment.virtual_address || virtual_address >= segment_end) {
            continue;
        }
        const auto relative = virtual_address - segment.virtual_address;
        if (relative + size > segment.file_size) {
            break;
        }
        const auto file_offset = static_cast<std::size_t>(segment.file_offset + relative);
        if (file_offset + size > bytes_.size()) {
            return std::unexpected(AppError{.message = "Read exceeds ELF file bounds."});
        }
        return std::span<const std::uint8_t>{bytes_.data() + file_offset, size};
    }
    return std::unexpected(AppError{.message = "Virtual address is not mapped in ELF image."});
}

std::expected<void, AppError> Image::write_at(
    const std::uint64_t virtual_address,
    const std::span<const std::uint8_t> data) {
    for (auto& segment : load_segments_) {
        const auto segment_end = segment.virtual_address + segment.file_size;
        if (virtual_address < segment.virtual_address || virtual_address >= segment_end) {
            continue;
        }
        const auto relative = virtual_address - segment.virtual_address;
        if (relative + data.size() > segment.file_size) {
            break;
        }
        const auto file_offset = static_cast<std::size_t>(segment.file_offset + relative);
        if (file_offset + data.size() > bytes_.size()) {
            return std::unexpected(AppError{.message = "Write exceeds ELF file bounds."});
        }
        std::memcpy(bytes_.data() + file_offset, data.data(), data.size());
        return {};
    }
    return std::unexpected(AppError{.message = "Virtual address is not writable in ELF image."});
}

} // namespace ps3::elf
