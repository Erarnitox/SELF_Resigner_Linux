#include "eboot_service.hpp"

#include "ps3/fself/builder.hpp"
#include "ps3/fself/extractor.hpp"

#include <filesystem>
#include <cstring>

namespace resigner {

namespace fs = std::filesystem;

EbootService::EbootService(Settings& settings, SceOperations& sce_ops)
    : settings_{settings}, sce_{sce_ops} {}

void EbootService::decrypt_only() {
    const fs::path eboot_bin{paths::kEbootBin};
    const fs::path eboot_elf{paths::kEbootElf};

    if (!fs::exists(eboot_bin)) {
        Console::println("[^^!] EBOOT.BIN cannot be found.");
        Console::println("[^^!] Decrypt aborted.");
        Console::println("[*] Press [ENTER] to continue...");
        Console::wait_for_enter();
        return;
    }

    if (fs::exists(eboot_elf)) {
        fs::remove(eboot_elf);
    }

    Console::println("[*] Decrypting EBOOT.BIN...");
    if (sce_.decrypt(eboot_bin, eboot_elf)) {
        Console::println("[*] Decrypt finished.");
    } else {
        Console::println("[^^!] Decrypt EBOOT.BIN failed.");
    }

    Console::println("[*] Press [ENTER] to continue...");
    Console::wait_for_enter();
}

bool EbootService::ensure_elf_available(bool& decrypted_temp) {
    const fs::path eboot_bin{paths::kEbootBin};
    const fs::path eboot_elf{paths::kEbootElf};
    decrypted_temp = false;

    if (!fs::exists(eboot_bin) && !fs::exists(eboot_elf)) {
        Console::println("[^^!] EBOOT.BIN/ELF cannot be found.");
        Console::println("[^^!] Resign aborted.");
        Console::println("[*] Press [ENTER] to continue...");
        Console::wait_for_enter();
        return false;
    }

    if (!fs::exists(eboot_elf) && fs::exists(eboot_bin)) {
        Console::println("[*] Decrypting EBOOT.BIN...");
        if (!sce_.decrypt(eboot_bin, eboot_elf)) {
            Console::println("[^^!] Decrypt EBOOT.BIN failed.");
            Console::println("[^^!] Resign aborted.");
            Console::println("[*] Press [ENTER] to continue...");
            Console::wait_for_enter();
            return false;
        }
        decrypted_temp = true;
    }

    if (!fs::exists(eboot_elf)) {
        Console::println("[^^!] Decrypt EBOOT.BIN failed.");
        Console::println("[^^!] Resign aborted.");
        Console::println("[*] Press [ENTER] to continue...");
        Console::wait_for_enter();
        return false;
    }

    return true;
}

void EbootService::backup_eboot_bin() {
    (void)FileSystem::backup_file(paths::kEbootBin);
}

void EbootService::cleanup_temp_elf(const bool remove_elf) {
    if (remove_elf && fs::exists(paths::kEbootElf)) {
        fs::remove(paths::kEbootElf);
    }
}

void EbootService::finish_resign(const bool decrypted_temp) {
    cleanup_temp_elf(decrypted_temp);
    Console::println("[*] Resign finished.");
    Console::println("[*] Press [ENTER] to continue...");
    Console::wait_for_enter();
}

void EbootService::resign_non_drm() {
    bool decrypted_temp{false};
    if (!ensure_elf_available(decrypted_temp)) {
        return;
    }

    backup_eboot_bin();

    Console::println("[*] Patching EBOOT.ELF...");
    (void)sce_.patch_elf_sdk(paths::kEbootElf);

    Console::println("[*] Encrypting EBOOT.ELF...");
    if (!sce_.encrypt_non_drm(paths::kEbootElf, paths::kEbootBin)) {
        Console::println("[^^!] Encrypt EBOOT.ELF failed.");
    }

    finish_resign(decrypted_temp);
}

bool EbootService::validate_content_id(const std::string& content_id) const {
    if (content_id.size() != 36) {
        return false;
    }
    if (content_id[6] != '-') {
        return false;
    }
    return content_id.substr(16, 4) == "_00-";
}

bool EbootService::prompt_for_content_id() {
    while (true) {
        Console::println("[*] Enter custom ContentID:");
        Console::println("[*] Please follow this sample ContentID:JP9000-NPJA00001_00-0000000000000000");
        const auto value = Console::read_line("Enter custom ContentID (A to abort): ");
        if (value == "A" || value == "a") {
            return false;
        }
        if (validate_content_id(value)) {
            settings_.content_id = value;
            return true;
        }
        Console::println("[^^!] Invalid ContentID format, please enter following the sample ContentID.");
        Console::println("[*] Press [ENTER] to continue...");
        Console::wait_for_enter();
    }
}

void EbootService::resign_npdrm() {
    if (!settings_.supports_npdrm()) {
        Console::println("[^^!] NPDRM Resign is inapplicable for ODE Output.");
        Console::wait_for_enter();
        return;
    }

    bool decrypted_temp{false};
    if (!ensure_elf_available(decrypted_temp)) {
        return;
    }

    settings_.content_id.clear();
    if (fs::exists(paths::kEbootBin)) {
        if (auto content_id = sce_.read_content_id(paths::kEbootBin)) {
            settings_.content_id = *content_id;
        }
    }

    if (settings_.content_id.empty()) {
        if (!prompt_for_content_id()) {
            cleanup_temp_elf(decrypted_temp);
            return;
        }
    } else {
        Console::print_formatted("[*] Found ContentID in EBOOT.BIN: %s\n", settings_.content_id.c_str());
        const auto choice = Console::read_int(
            "1: Use this Content-ID  2: Enter custom ContentID: ");
        if (choice == 2) {
            if (!prompt_for_content_id()) {
                cleanup_temp_elf(decrypted_temp);
                return;
            }
        }
    }

    backup_eboot_bin();
    Console::println("[*] Patching EBOOT.ELF...");
    (void)sce_.patch_elf_sdk(paths::kEbootElf);

    Console::println("[*] Encrypting EBOOT.ELF...");
    if (!sce_.encrypt_npdrm_eboot(paths::kEbootElf, paths::kEbootBin, settings_.content_id)) {
        Console::println("[^^!] Encrypt EBOOT.ELF failed.");
    }

    finish_resign(decrypted_temp);
}

void EbootService::decrypt_fself() {
    const fs::path eboot_bin{paths::kEbootBin};
    const fs::path eboot_elf{paths::kEbootElf};

    if (!fs::exists(eboot_bin)) {
        Console::println("[^^!] EBOOT.BIN cannot be found.");
        Console::println("[^^!] Decrypt aborted.");
        Console::println("[*] Press [ENTER] to continue...");
        Console::wait_for_enter();
        return;
    }

    if (fs::exists(eboot_elf)) {
        fs::remove(eboot_elf);
    }

    Console::println("[*] Decrypting EBOOT.BIN (FSELF)...");
    if (ps3::fself::Extractor::extract(eboot_bin, eboot_elf)) {
        Console::println("[*] Decrypt finished.");
    } else {
        Console::println("[^^!] Decrypt EBOOT.BIN failed.");
    }

    Console::println("[*] Press [ENTER] to continue...");
    Console::wait_for_enter();
}

void EbootService::resign_non_drm_dex() {
    bool decrypted_temp{false};
    if (!ensure_elf_available(decrypted_temp)) {
        return;
    }

    backup_eboot_bin();

    Console::println("[*] Patching EBOOT.ELF...");
    (void)sce_.patch_elf_sdk(paths::kEbootElf);

    Console::println("[*] Encrypting EBOOT.ELF (FSELF)...");
    if (!ps3::fself::Builder::build(paths::kEbootElf, paths::kEbootBin, false)) {
        Console::println("[^^!] Encrypt EBOOT.ELF failed.");
    }

    finish_resign(decrypted_temp);
}

void EbootService::resign_npdrm_dex() {
    if (!settings_.supports_npdrm()) {
        Console::println("[^^!] NPDRM Resign is inapplicable for ODE Output.");
        Console::wait_for_enter();
        return;
    }

    bool decrypted_temp{false};
    if (!ensure_elf_available(decrypted_temp)) {
        return;
    }

    settings_.content_id.clear();
    if (fs::exists(paths::kEbootBin)) {
        if (auto content_id = sce_.read_content_id(paths::kEbootBin)) {
            settings_.content_id = *content_id;
        }
    }

    backup_eboot_bin();

    if (!settings_.content_id.empty()) {
        Console::print_formatted("[*] Found ContentID in EBOOT.BIN: %s\n", settings_.content_id.c_str());
    }

    Console::println("[*] Patching EBOOT.ELF...");
    (void)sce_.patch_elf_sdk(paths::kEbootElf);

    std::optional<ps3::fself::NpdrmInfo> npdrm_info;
    if (!settings_.content_id.empty()) {
        ps3::fself::NpdrmInfo info{};
        const auto copy_size = std::min(info.content_id.size(), settings_.content_id.size());
        std::memcpy(info.content_id.data(), settings_.content_id.data(), copy_size);
        npdrm_info = info;
    }

    Console::println("[*] Encrypting EBOOT.ELF (NPDRM FSELF)...");
    if (!ps3::fself::Builder::build(paths::kEbootElf, paths::kEbootBin, true, npdrm_info)) {
        Console::println("[^^!] Encrypt EBOOT.ELF failed.");
    }

    finish_resign(decrypted_temp);
}

} // namespace resigner
