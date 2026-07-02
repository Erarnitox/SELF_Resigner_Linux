#include <catch2/catch_test_macros.hpp>

#include "eboot_diff/services/address_index.hpp"
#include "eboot_diff/services/disassembler.hpp"
#include "eboot_diff/services/eboot_loader.hpp"
#include "resigner/sce_operations.hpp"
#include "resigner/settings.hpp"

#include <filesystem>

namespace {

std::filesystem::path sample_eboot_path() {
    const std::filesystem::path candidates[] = {
        "bin/EBOOT/original/BLES00669 (AC2)/EBOOT.ELF",
        "../build-asan/bin/EBOOT/original/BLES00669 (AC2)/EBOOT.ELF",
        "build-asan/bin/EBOOT/original/BLES00669 (AC2)/EBOOT.ELF",
    };
    for (const auto& candidate : candidates) {
        if (std::filesystem::exists(candidate)) {
            return candidate;
        }
    }
    return {};
}

} // namespace

TEST_CASE("DisassemblerService decodes real PS3 EBOOT instructions", "[disasm][integration]") {
    const auto path = sample_eboot_path();
    if (path.empty()) {
        SKIP("No sample EBOOT.ELF available for integration test.");
    }

    resigner::Settings settings;
    resigner::SceOperations sce{settings};
    eboot_diff::EbootLoader loader{sce};
    auto document = loader.load(path);
    REQUIRE(document);

    const auto addresses = eboot_diff::AddressIndex::build_executable_addresses(*document);
    REQUIRE_FALSE(addresses.empty());

    eboot_diff::DisassemblerService disassembler{};
    const auto slice = std::span<const std::uint64_t>{addresses.data(), std::min<std::size_t>(64, addresses.size())};
    const auto view = disassembler.disassemble_addresses(*document, slice);
    REQUIRE(view);
    REQUIRE(view->lines.size() == slice.size());

    std::size_t decoded = 0;
    for (const auto& line : view->lines) {
        if (line.mnemonic != ".word") {
            ++decoded;
        }
    }
    INFO("first line: " << view->lines.front().display_text());
    REQUIRE(decoded > 0);
}
