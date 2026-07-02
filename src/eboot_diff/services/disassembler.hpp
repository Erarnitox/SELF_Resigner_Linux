#pragma once

#include "domain/types.hpp"

#include <cstdint>
#include <span>

namespace eboot_diff {

class DisassemblerService {
public:
    DisassemblerService();
    ~DisassemblerService();

    DisassemblerService(const DisassemblerService&) = delete;
    DisassemblerService& operator=(const DisassemblerService&) = delete;

    [[nodiscard]] Result<DisassemblyView> disassemble(const EbootDocument& document) const;
    [[nodiscard]] Result<DisassemblyView> disassemble_addresses(
        const EbootDocument& document,
        std::span<const std::uint64_t> addresses) const;

private:
    struct CapstoneState;
    CapstoneState* state_{nullptr};
};

} // namespace eboot_diff
