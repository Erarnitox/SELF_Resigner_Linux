#include "self_service.hpp"

namespace resigner {

namespace fs = std::filesystem;

SelfService::SelfService(Settings& settings, SceOperations& sce_ops)
    : settings_{settings}, sce_{sce_ops}, klicense_{sce_ops} {}

std::optional<SelfEntry> SelfService::entry_from_filename(const fs::path& filename) const {
    const auto name = filename.string();
    if (name.size() < 5) {
        return std::nullopt;
    }

    SelfEntry entry{
        .filename = filename,
        .short_name = name.substr(0, name.size() - 5),
        .suffix = name.substr(name.size() - 4),
    };

    if (FileSystem::ends_with_ignore_case(name, ".self")) {
        entry.elf_extension = FileSystem::ends_with_ignore_case(name, ".SELF") ? "ELF" : "elf";
        entry.backup_extension = FileSystem::ends_with_ignore_case(name, ".SELF") ? "BAK" : "bak";
    } else if (FileSystem::ends_with_ignore_case(name, ".sprx")) {
        entry.elf_extension = FileSystem::ends_with_ignore_case(name, ".SPRX") ? "PRX" : "prx";
        entry.backup_extension = FileSystem::ends_with_ignore_case(name, ".SPRX") ? "BAK" : "bak";
    } else {
        return std::nullopt;
    }

    return entry;
}

std::vector<SelfEntry> SelfService::collect_self_entries() const {
    std::vector<SelfEntry> entries;
    const auto files = FileSystem::list_by_extensions(
        paths::kSelfDir,
        {".self", ".SELF", ".sprx", ".SPRX"});

    for (const auto& file : files) {
        if (auto entry = entry_from_filename(file)) {
            entries.push_back(*entry);
        }
    }
    return entries;
}

fs::path SelfService::elf_path_for(const SelfEntry& entry) const {
    return fs::path{paths::kSelfDir} / (entry.short_name + "." + entry.elf_extension);
}

fs::path SelfService::self_path_for(const SelfEntry& entry) const {
    return fs::path{paths::kSelfDir} / entry.filename;
}

fs::path SelfService::backup_path_for(const SelfEntry& entry) const {
    return self_path_for(entry).string() + "." + entry.backup_extension;
}

std::string SelfService::np_app_type_for(const SelfEntry& /*entry*/) const {
    const bool update = settings_.content_id.size() > 7 && settings_.content_id[7] == 'B';
    return update ? "USPRX" : "SPRX";
}


void SelfService::print_numbered_list(const std::vector<SelfEntry>& entries) const {
    Console::println("===============================================================================");
    Console::println(" SELF/SPRX Files List");
    Console::println("===============================================================================");

    if (entries.empty()) {
        Console::println(" No SELF/SPRX is Found.");
    } else {
        int index{1};
        for (const auto& entry : entries) {
            Console::print_formatted(" %d. %s\n", index++, entry.filename.string().c_str());
        }
    }

    Console::println("===============================================================================");
}

std::optional<SelfEntry> SelfService::select_entry(const std::vector<SelfEntry>& entries) const {
    if (entries.empty()) {
        return std::nullopt;
    }

    const int choice = Console::read_int("Enter SELF/SPRX file number to decrypt / 99 to Back: ");
    if (choice == 99) {
        return std::nullopt;
    }
    if (choice < 1 || choice > static_cast<int>(entries.size())) {
        Console::println("[^^!] Invalid input, please enter again.");
        Console::println("[*] Press [ENTER] to continue...");
        Console::wait_for_enter();
        return std::nullopt;
    }
    return entries[static_cast<std::size_t>(choice - 1)];
}

std::optional<BatchChoice> SelfService::prompt_batch_selection(
    const std::vector<SelfEntry>& entries) const {
    const auto input = Console::read_line(
        "[?] Enter SELF/SPRX file number to resign / A for All / B to Back: ");

    if (input == "B" || input == "b") {
        return BatchChoice{.selection = BatchSelection::Back};
    }
    if (input == "A" || input == "a") {
        return BatchChoice{.selection = BatchSelection::All};
    }

    try {
        const int choice = std::stoi(input);
        if (choice < 1 || choice > static_cast<int>(entries.size())) {
            Console::println("[^^!] Invalid input, please enter again.");
            Console::println("[*] Press [ENTER] to continue...");
            Console::wait_for_enter();
            return std::nullopt;
        }
        return BatchChoice{.selection = BatchSelection::Single, .index = choice};
    } catch (...) {
        Console::println("[^^!] Invalid input, please enter again.");
        Console::println("[*] Press [ENTER] to continue...");
        Console::wait_for_enter();
        return std::nullopt;
    }
}

void SelfService::report_batch_result(const int errors, const std::string_view action) const {
    if (errors == 0) {
        Console::print_formatted("[*] %s all SELF/SPRX files successfully.\n", action.data());
    } else {
        Console::print_formatted(
            "[^^!] %s all SELF/SPRX files finished, %d file(s) failed.\n",
            action.data(),
            errors);
    }
    Console::println("[*] Press [ENTER] to continue...");
    Console::wait_for_enter();
}

bool SelfService::resign_entry_non_drm(const SelfEntry& entry) {
    const auto elf_path = elf_path_for(entry);
    const auto self_path = self_path_for(entry);
    const auto backup_path = backup_path_for(entry);

    if (fs::exists(elf_path)) {
        fs::remove(elf_path);
    }

    Console::print_formatted("[*] Decrypting %s...\n", entry.filename.string().c_str());
    if (!sce_.decrypt(self_path, elf_path)) {
        Console::print_formatted("[^^!] Decrypt %s failed.\n", entry.filename.string().c_str());
        return false;
    }

    if (fs::exists(backup_path)) {
        fs::remove(backup_path);
    }
    fs::copy_file(self_path, backup_path, fs::copy_options::overwrite_existing);

    Console::print_formatted("[*] Patching %s.%s...\n", entry.short_name.c_str(), entry.elf_extension.c_str());
    (void)sce_.patch_elf_sdk(elf_path);

    Console::print_formatted("[*] Encrypting %s.%s...\n", entry.short_name.c_str(), entry.elf_extension.c_str());
    if (!sce_.encrypt_non_drm(elf_path, self_path)) {
        Console::print_formatted("[^^!] Encrypt %s failed.\n", entry.filename.string().c_str());
        if (fs::exists(elf_path)) {
            fs::remove(elf_path);
        }
        return false;
    }

    if (fs::exists(elf_path)) {
        fs::remove(elf_path);
    }

    Console::print_formatted("[*] Resign %s finished.\n", entry.filename.string().c_str());
    return true;
}

bool SelfService::resign_entry_npdrm(
    const SelfEntry& entry,
    const std::string& content_id,
    const std::string& klicensee) {
    settings_.klicensee = klicensee;

    const auto elf_path = elf_path_for(entry);
    const auto self_path = self_path_for(entry);
    const auto backup_path = backup_path_for(entry);

    if (fs::exists(elf_path)) {
        fs::remove(elf_path);
    }

    Console::print_formatted("[*] Resigning %s...\n", entry.filename.string().c_str());
    if (!sce_.decrypt(self_path, elf_path, klicensee)) {
        Console::print_formatted("[^^!] Decrypt %s failed.\n", entry.filename.string().c_str());
        return false;
    }

    if (fs::exists(backup_path)) {
        fs::remove(backup_path);
    }
    fs::copy_file(self_path, backup_path, fs::copy_options::overwrite_existing);

    (void)sce_.patch_elf_sdk(elf_path);

    const auto np_app_type = np_app_type_for(entry);
    if (!sce_.encrypt_npdrm_self(
            elf_path,
            self_path,
            content_id,
            entry.filename.string(),
            np_app_type)) {
        Console::print_formatted("[^^!] Encrypt %s failed.\n", entry.filename.string().c_str());
        if (fs::exists(elf_path)) {
            fs::remove(elf_path);
        }
        return false;
    }

    if (fs::exists(elf_path)) {
        fs::remove(elf_path);
    }

    Console::print_formatted("[*] Resign %s finished.\n", entry.filename.string().c_str());
    return true;
}

int SelfService::batch_resign_non_drm(const std::vector<SelfEntry>& entries) {
    int errors{0};
    for (const auto& entry : entries) {
        if (!resign_entry_non_drm(entry)) {
            Console::print_formatted("[^^!] Resign %s aborted.\n", entry.filename.string().c_str());
            ++errors;
        }
    }
    return errors;
}

int SelfService::batch_resign_npdrm(
    const std::vector<SelfEntry>& entries,
    const std::string& content_id,
    const std::string& klicensee) {
    int errors{0};
    for (const auto& entry : entries) {
        if (!resign_entry_npdrm(entry, content_id, klicensee)) {
            Console::print_formatted("[^^!] Resign %s aborted.\n", entry.filename.string().c_str());
            ++errors;
        }
    }
    return errors;
}

void SelfService::list_self_files() {
    Console::clear();
    const auto entries = collect_self_entries();
    print_numbered_list(entries);

    if (entries.empty()) {
        Console::wait_for_enter();
        return;
    }

    Console::println("Note: To decrypt NPDRM file, EBOOT.BIN might be needed in Resigner folder.");
    Console::println("===============================================================================");
    decrypt_selected();
}

void SelfService::decrypt_selected() {
    const auto entries = collect_self_entries();
    if (entries.empty()) {
        Console::wait_for_enter();
        return;
    }

    const auto selected = select_entry(entries);
    if (!selected.has_value()) {
        return;
    }

    const auto elf_path = elf_path_for(*selected);
    if (fs::exists(elf_path)) {
        fs::remove(elf_path);
    }

    Console::print_formatted("[*] Decrypting %s...\n", selected->filename.string().c_str());
    const auto self_path = self_path_for(*selected);
    if (!sce_.decrypt(self_path, elf_path)) {
        if (auto content_id = sce_.read_content_id(self_path)) {
            Console::print_formatted(
                "[*] Found ContentID in %s file: %s\n",
                selected->suffix.c_str(),
                content_id->c_str());
        }
        Console::print_formatted("[^^!] Decrypt %s failed.\n", selected->filename.string().c_str());
        Console::println("[*] Press [ENTER] to continue...");
        Console::wait_for_enter();
        return;
    }

    Console::print_formatted(
        "[*] Decrypt file to %s.%s successfully.\n",
        selected->short_name.c_str(),
        selected->elf_extension.c_str());
    Console::println("[*] Press [ENTER] to continue...");
    Console::wait_for_enter();
}

void SelfService::fast_resign_non_drm() {
    Console::clear();
    auto entries = collect_self_entries();
    print_numbered_list(entries);

    if (entries.empty()) {
        Console::wait_for_enter();
        return;
    }

    while (true) {
        const auto choice = prompt_batch_selection(entries);
        if (!choice.has_value()) {
            continue;
        }
        if (choice->selection == BatchSelection::Back) {
            return;
        }
        if (choice->selection == BatchSelection::All) {
            const int errors = batch_resign_non_drm(entries);
            report_batch_result(errors, "Resign");
            return;
        }

        const auto& entry = entries[static_cast<std::size_t>(choice->index - 1)];
        if (!resign_entry_non_drm(entry)) {
            Console::println("[^^!] Resign aborted.");
        } else {
            Console::println("[*] Resign finished.");
        }
        Console::println("[*] Press [ENTER] to continue...");
        Console::wait_for_enter();
        return;
    }
}

bool SelfService::ensure_eboot_for_npdrm() const {
    if (!fs::exists(paths::kEbootBin)) {
        Console::println("[^^!] EBOOT.BIN cannot be found in Resigner folder.");
        return false;
    }
    return true;
}

bool SelfService::resolve_npdrm_credentials(const SelfEntry& probe_entry) {
    settings_.content_id.clear();
    if (auto content_id = sce_.read_content_id(paths::kEbootBin)) {
        settings_.content_id = *content_id;
    }

    if (settings_.content_id.empty()) {
        Console::println("[^^!] EBOOT.BIN should be an NPDRM EBOOT.");
        return false;
    }

    Console::print_formatted("[*] Found ContentID in EBOOT.BIN: %s\n", settings_.content_id.c_str());

    if (auto klicensee = klicense_.resolve(settings_.content_id, probe_entry)) {
        settings_.klicensee = *klicensee;
        return true;
    }

    Console::println("[^^!] Cannot find Klicensee.");
    Console::println("[*] Place a matching RAP in raps/, add an entry to tool/kliclist.txt,");
    Console::println("[*] or ensure tool/klicpool.txt / res/klicpool.txt contains the key.");
    return false;
}

void SelfService::fast_resign_npdrm() {
    if (!settings_.supports_npdrm()) {
        Console::println("[^^!] NPDRM Resign is inapplicable for ODE Output.");
        Console::wait_for_enter();
        return;
    }

    Console::clear();
    auto entries = collect_self_entries();
    print_numbered_list(entries);

    if (entries.empty()) {
        Console::wait_for_enter();
        return;
    }

    if (!ensure_eboot_for_npdrm()) {
        Console::println("[^^!] Resign aborted.");
        Console::wait_for_enter();
        return;
    }

    Console::println(" Note: BruteForce Detecting Klicensee method will be used in this option.");
    Console::println("       EBOOT.BIN must be placed into Resigner folder for detecting Klicensee.");
    Console::println("       Make sure that EBOOT.BIN and SELF/SPRX files are from the same game.");
    Console::println("===============================================================================");

    const auto continue_input = Console::read_line("[?] Enter Y to continue / N to Abort: ");
    if (continue_input != "Y" && continue_input != "y") {
        return;
    }

    if (!resolve_npdrm_credentials(entries.front())) {
        Console::println("[^^!] Resign aborted.");
        Console::wait_for_enter();
        return;
    }

    const int errors = batch_resign_npdrm(entries, settings_.content_id, settings_.klicensee);
    report_batch_result(errors, "Resign");
}

void SelfService::list_elf_files(const bool require_npdrm) {
    if (require_npdrm && !settings_.supports_npdrm()) {
        Console::println("[^^!] NPDRM Resign is inapplicable for ODE Output.");
        Console::wait_for_enter();
        return;
    }

    Console::clear();
    const auto files = FileSystem::list_by_extensions(paths::kSelfDir, {".elf", ".ELF", ".prx", ".PRX"});
    Console::println("===============================================================================");
    Console::println(" ELF/PRX Files List");
    Console::println("===============================================================================");

    if (files.empty()) {
        Console::println(" No ELF/PRX is Found.");
    } else {
        int index{1};
        for (const auto& file : files) {
            Console::print_formatted(" %d. %s\n", index++, file.string().c_str());
        }
    }

    Console::println("===============================================================================");
    if (files.empty()) {
        Console::wait_for_enter();
    }
}

} // namespace resigner
