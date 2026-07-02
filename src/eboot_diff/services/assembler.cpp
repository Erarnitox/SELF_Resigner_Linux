#include "assembler.hpp"

#include <keystone/keystone.h>

#include <cctype>
#include <cstring>
#include <sstream>

namespace eboot_diff {

struct AssemblerService::KeystoneState {
    ks_engine* engine{nullptr};
    bool valid{false};
};

AssemblerService::AssemblerService() : state_{new KeystoneState{}} {
    if (ks_open(KS_ARCH_PPC, static_cast<ks_mode>(KS_MODE_64 | KS_MODE_BIG_ENDIAN), &state_->engine) != KS_ERR_OK) {
        state_->valid = false;
        return;
    }
    state_->valid = true;
}

AssemblerService::~AssemblerService() {
    if (state_->valid && state_->engine != nullptr) {
        ks_close(state_->engine);
    }
    delete state_;
}

namespace {

std::string normalize_ppc_syntax(std::string input) {
    std::string output;
    output.reserve(input.size());
    for (std::size_t index = 0; index < input.size(); ++index) {
        if (input[index] == 'r' && index + 1 < input.size() && std::isdigit(static_cast<unsigned char>(input[index + 1]))) {
            continue;
        }
        output.push_back(input[index]);
    }
    return output;
}

} // namespace

Result<InstructionLine> AssemblerService::assemble_line(
    const InstructionLine& original,
    const std::string_view assembly_text) const {
    if (!state_->valid) {
        return std::unexpected(AppError::from("Keystone initialization failed."));
    }

    std::string input = normalize_ppc_syntax(std::string{assembly_text});

    unsigned char* encode{nullptr};
    std::size_t size{0};
    std::size_t count{0};
    const auto error = ks_asm(
        state_->engine,
        input.c_str(),
        original.address,
        &encode,
        &size,
        &count);
    if (error != KS_ERR_OK || encode == nullptr || size != 4 || count != 1) {
        const char* message = ks_strerror(ks_errno(state_->engine));
        return std::unexpected(AppError::from(message != nullptr ? message : "Assembly failed."));
    }

    InstructionLine line = original;
    std::memcpy(line.bytes.data(), encode, 4);

    std::istringstream iss{input};
    iss >> line.mnemonic;
    std::getline(iss, line.operands);
    if (!line.operands.empty() && line.operands.front() == ' ') {
        line.operands.erase(line.operands.begin());
    }

    ks_free(encode);
    return line;
}

} // namespace eboot_diff
