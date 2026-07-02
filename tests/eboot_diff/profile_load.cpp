#include "eboot_diff/services/eboot_loader.hpp"
#include "eboot_diff/services/disassembler.hpp"
#include "ps3/elf/image.hpp"
#include "resigner/sce_operations.hpp"
#include "resigner/settings.hpp"

#include <chrono>
#include <filesystem>
#include <iostream>

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    const std::filesystem::path path{argv[1]};
    resigner::Settings settings;
    resigner::SceOperations sce{settings};
    eboot_diff::EbootLoader loader{sce};

    const auto t0 = std::chrono::steady_clock::now();
    auto doc = loader.load(path);
    const auto t1 = std::chrono::steady_clock::now();
    if (!doc) { std::cerr << doc.error().message << '\n'; return 1; }
    std::cout << "load " << std::chrono::duration<double>(t1-t0).count() << "s size=" << doc->elf_bytes.size() << '\n';

    auto image = ps3::elf::Image::load(doc->elf_bytes);
    if (image) {
        for (const auto& s : image->executable_segments()) {
            std::cout << "exec filesz=" << s.file_size << " insns=" << (s.file_size/4) << '\n';
        }
    }

    eboot_diff::DisassemblerService d{};
    const auto t2 = std::chrono::steady_clock::now();
    auto view = d.disassemble(*doc);
    const auto t3 = std::chrono::steady_clock::now();
    std::cout << "disasm " << std::chrono::duration<double>(t3-t2).count() << "s lines=" << (view ? view->lines.size() : 0) << '\n';
    return 0;
}
