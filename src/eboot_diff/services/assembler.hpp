#pragma once

#include "domain/types.hpp"

namespace eboot_diff {

class AssemblerService {
public:
    AssemblerService();
    ~AssemblerService();

    AssemblerService(const AssemblerService&) = delete;
    AssemblerService& operator=(const AssemblerService&) = delete;

    [[nodiscard]] Result<InstructionLine> assemble_line(
        const InstructionLine& original,
        std::string_view assembly_text) const;

private:
    struct KeystoneState;
    KeystoneState* state_{nullptr};
};

} // namespace eboot_diff
