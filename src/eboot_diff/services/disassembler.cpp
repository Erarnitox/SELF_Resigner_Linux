#include "disassembler.hpp"

#include "ps3/elf/image.hpp"

#include <capstone/capstone.h>

#include <cstring>
#include <unordered_map>

namespace eboot_diff {

namespace {

constexpr cs_mode kPpcCellMode = CS_MODE_BIG_ENDIAN;

const ps3::elf::CodeRegion* find_code_region(
    const ps3::elf::Image& image,
    const std::uint64_t address) {
    for (const auto& region : image.code_regions()) {
        const auto end = region.virtual_address + region.size;
        if (address >= region.virtual_address && address + 4 <= end) {
            return &region;
        }
    }
    return nullptr;
}

InstructionLine make_word_line(
    const std::uint64_t address,
    const std::span<const std::uint8_t> bytes,
    const std::string& region_name) {
    InstructionLine line{};
    line.address = address;
    std::memcpy(line.bytes.data(), bytes.data(), 4);
    line.mnemonic = ".word";
    line.segment_name = region_name;
    return line;
}

void disassemble_region(
    const csh handle,
    const ps3::elf::CodeRegion& region,
    const std::span<const std::uint8_t> code,
    const std::uint64_t start_address,
    std::unordered_map<std::uint64_t, InstructionLine>& out) {
    cs_insn* instructions{nullptr};
    const auto instruction_count = cs_disasm(
        handle,
        code.data(),
        code.size(),
        start_address,
        0,
        &instructions);
    if (instruction_count == 0 || instructions == nullptr) {
        for (std::uint64_t offset = 0; offset + 4 <= code.size(); offset += 4) {
            const auto address = start_address + offset;
            out.emplace(
                address,
                make_word_line(
                    address,
                    code.subspan(static_cast<std::size_t>(offset), 4),
                    region.name));
        }
        return;
    }

    for (std::size_t index = 0; index < instruction_count; ++index) {
        const auto& insn = instructions[index];
        InstructionLine line{};
        line.address = insn.address;
        const auto copy_size = std::min<std::size_t>(insn.size, line.bytes.size());
        std::memcpy(line.bytes.data(), insn.bytes, copy_size);
        line.mnemonic = insn.mnemonic;
        line.operands = insn.op_str;
        line.segment_name = region.name;
        out.emplace(line.address, std::move(line));
    }
    cs_free(instructions, instruction_count);
}

} // namespace

struct DisassemblerService::CapstoneState {
    csh handle{0};
    bool valid{false};
};

DisassemblerService::DisassemblerService() : state_{new CapstoneState{}} {
    if (cs_open(CS_ARCH_PPC, kPpcCellMode, &state_->handle) != CS_ERR_OK) {
        state_->valid = false;
        return;
    }
    cs_option(state_->handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(state_->handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    state_->valid = true;
}

DisassemblerService::~DisassemblerService() {
    if (state_->valid) {
        cs_close(&state_->handle);
    }
    delete state_;
}

Result<DisassemblyView> DisassemblerService::disassemble(const EbootDocument& document) const {
    if (!state_->valid) {
        return std::unexpected(AppError::from("Capstone initialization failed."));
    }

    auto image = ps3::elf::Image::load(document.elf_bytes);
    if (!image) {
        return std::unexpected(AppError::from(image.error().message));
    }

    const auto& bytes = image->data();
    DisassemblyView view{};

    for (const auto& region : image->code_regions()) {
        if (region.size < 4) {
            continue;
        }

        const auto file_offset = static_cast<std::size_t>(region.file_offset);
        if (file_offset + region.size > bytes.size()) {
            return std::unexpected(AppError::from("Executable code region exceeds ELF bounds."));
        }

        const auto* code = bytes.data() + file_offset;
        const auto code_size = static_cast<std::size_t>(region.size);

        cs_insn* instructions{nullptr};
        const auto instruction_count = cs_disasm(
            state_->handle,
            code,
            code_size,
            region.virtual_address,
            0,
            &instructions);
        if (instruction_count == 0 || instructions == nullptr) {
            for (std::uint64_t offset = 0; offset + 4 <= region.size; offset += 4) {
                InstructionLine line{};
                line.address = region.virtual_address + offset;
                std::memcpy(line.bytes.data(), code + offset, 4);
                line.mnemonic = ".word";
                line.segment_name = region.name;
                view.lines.push_back(std::move(line));
            }
            continue;
        }

        view.lines.reserve(view.lines.size() + static_cast<std::size_t>(instruction_count));
        for (std::size_t index = 0; index < instruction_count; ++index) {
            const auto& insn = instructions[index];
            InstructionLine line{};
            line.address = insn.address;
            const auto copy_size = std::min<std::size_t>(insn.size, line.bytes.size());
            std::memcpy(line.bytes.data(), insn.bytes, copy_size);
            line.mnemonic = insn.mnemonic;
            line.operands = insn.op_str;
            line.segment_name = region.name;
            view.lines.push_back(std::move(line));
        }
        cs_free(instructions, instruction_count);
    }

    return view;
}

Result<DisassemblyView> DisassemblerService::disassemble_addresses(
    const EbootDocument& document,
    const std::span<const std::uint64_t> addresses) const {
    if (!state_->valid) {
        return std::unexpected(AppError::from("Capstone initialization failed."));
    }
    if (addresses.empty()) {
        return DisassemblyView{};
    }

    auto image = ps3::elf::Image::load(document.elf_bytes);
    if (!image) {
        return std::unexpected(AppError::from(image.error().message));
    }

    std::unordered_map<std::uint64_t, InstructionLine> lines_by_address;
    lines_by_address.reserve(addresses.size());

    std::size_t index = 0;
    while (index < addresses.size()) {
        const auto* region = find_code_region(*image, addresses[index]);
        if (region == nullptr) {
            ++index;
            continue;
        }

        const std::size_t run_start = index;
        while (index + 1 < addresses.size()) {
            const auto* next_region = find_code_region(*image, addresses[index + 1]);
            if (next_region != region || addresses[index + 1] != addresses[index] + 4) {
                break;
            }
            ++index;
        }
        const std::size_t run_end = index + 1;

        const auto start_address = addresses[run_start];
        const auto end_address = addresses[run_end - 1] + 4;
        const auto file_offset = static_cast<std::size_t>(
            region->file_offset + (start_address - region->virtual_address));
        const auto byte_count = static_cast<std::size_t>(end_address - start_address);
        if (file_offset + byte_count > image->data().size()) {
            return std::unexpected(AppError::from("Executable code region exceeds ELF bounds."));
        }

        const auto code = std::span<const std::uint8_t>{
            image->data().data() + file_offset,
            byte_count};
        disassemble_region(state_->handle, *region, code, start_address, lines_by_address);
        ++index;
    }

    DisassemblyView view{};
    view.lines.reserve(addresses.size());
    for (const auto address : addresses) {
        if (const auto found = lines_by_address.find(address); found != lines_by_address.end()) {
            view.lines.push_back(found->second);
            continue;
        }

        const auto* region = find_code_region(*image, address);
        if (region == nullptr) {
            continue;
        }

        const auto bytes = image->read_at(address, 4);
        if (!bytes) {
            continue;
        }
        view.lines.push_back(make_word_line(address, *bytes, region->name));
    }

    return view;
}

} // namespace eboot_diff
