#include "eboot_loader.hpp"

#include "ps3/binary/endian.hpp"
#include "ps3/elf/image.hpp"
#include "ps3/fself/extractor.hpp"
#include "resigner/sce_operations.hpp"
#include "tool/scetool_source/scetool.hpp"
#include "util/logger.hpp"

#include <fstream>
#include <iterator>

namespace eboot_diff {

namespace fs = std::filesystem;

EbootLoader::EbootLoader(resigner::SceOperations& sce_ops) : sce_ops_{sce_ops} {}

bool EbootLoader::is_elf_path(const fs::path& path) {
    const auto ext = path.extension().string();
    return ext == ".elf" || ext == ".ELF";
}

bool EbootLoader::is_bin_path(const fs::path& path) {
    const auto ext = path.extension().string();
    return ext == ".bin" || ext == ".BIN";
}

ContainerKind EbootLoader::detect_container_kind(const std::span<const std::uint8_t> data) {
    if (data.size() >= 4 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
        return ContainerKind::Elf;
    }
    if (data.size() >= 8 && ps3::binary::read_be32(data, 0) == 0x53434500) {
        const auto key_ver = ps3::binary::read_be16(data, 0x08);
        if (key_ver == 0x8000) {
            return ContainerKind::FakeSelf;
        }
        return ContainerKind::RetailSelf;
    }
    return ContainerKind::Elf;
}

Result<std::vector<std::uint8_t>> EbootLoader::read_file(const fs::path& path) const {
    std::ifstream input{path, std::ios::binary};
    if (!input) {
        return std::unexpected(AppError::from("Failed to open file: " + path.string()));
    }
    return std::vector<std::uint8_t>{
        std::istreambuf_iterator<char>{input},
        std::istreambuf_iterator<char>{}};
}

Result<std::vector<std::uint8_t>> EbootLoader::decrypt_bin(
    const fs::path& path,
    const LoadOptions& options) const {
    auto container = read_file(path);
    if (!container) {
        return container;
    }

    const auto kind = detect_container_kind(*container);
    const auto temp_elf = fs::temp_directory_path()
        / fs::path{path.stem().string() + "_eboot_diff.elf"};

    if (kind == ContainerKind::FakeSelf) {
        if (!ps3::fself::Extractor::extract(path, temp_elf)) {
            return std::unexpected(AppError::from("FSELF extraction failed."));
        }
    } else if (kind == ContainerKind::RetailSelf) {
        if (!sce_ops_.decrypt(path, temp_elf, options.klicensee)) {
            std::optional<std::string> klicensee = options.klicensee;
            if (!klicensee.has_value()) {
                const auto info_file = fs::temp_directory_path() / "eboot_diff_selfinfo.txt";
                if (ps3::sce::Scetool::print_info(path, info_file).success) {
                    if (auto content_id = ps3::sce::Scetool::content_id_from_info_file(info_file)) {
                        klicensee = ps3::sce::Scetool::klicensee_for_content_id(*content_id);
                    }
                }
            }
            if (!sce_ops_.decrypt(path, temp_elf, klicensee)) {
                return std::unexpected(AppError::from(
                    "SELF decryption failed. Provide a klicensee or matching RAP in raps/."));
            }
        }
    } else {
        return std::unexpected(AppError::from("Input is not a recognized SELF container."));
    }

    if (!fs::exists(temp_elf) || fs::file_size(temp_elf) == 0) {
        fs::remove(temp_elf);
        return std::unexpected(AppError::from("SELF decryption did not produce an ELF output."));
    }

    auto elf_bytes = read_file(temp_elf);
    fs::remove(temp_elf);
    if (!elf_bytes) {
        return elf_bytes;
    }
    return elf_bytes;
}

Result<EbootDocument> EbootLoader::load(const fs::path& path, const LoadOptions& options) const {
    if (!fs::exists(path)) {
        return std::unexpected(AppError::from("File does not exist: " + path.string()));
    }

    EbootDocument document{};
    document.source_path = path;

    if (is_elf_path(path)) {
        auto bytes = read_file(path);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        document.elf_bytes = std::move(*bytes);
        document.opened_from_bin = false;
        document.container_kind = ContainerKind::Elf;
    } else if (is_bin_path(path)) {
        auto container_bytes = read_file(path);
        if (!container_bytes) {
            return std::unexpected(container_bytes.error());
        }
        document.container_kind = detect_container_kind(*container_bytes);
        if (document.container_kind == ContainerKind::Elf) {
            document.container_kind = ContainerKind::RetailSelf;
        }

        auto bytes = decrypt_bin(path, options);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        document.elf_bytes = std::move(*bytes);
        document.opened_from_bin = true;
    } else {
        return std::unexpected(AppError::from("Unsupported file extension. Use .ELF or .BIN."));
    }

    if (auto image = ps3::elf::Image::load(document.elf_bytes); !image) {
        return std::unexpected(AppError::from(image.error().message));
    }

    Logger::info("Loaded " + path.string());
    return document;
}

} // namespace eboot_diff
