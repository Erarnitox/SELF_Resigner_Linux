#include "klicense_service.hpp"

#include "console.hpp"
#include "filesystem.hpp"
#include "ps3/np/klicense_bruteforce.hpp"
#include "tool/scetool_source/scetool.hpp"

#include <fstream>
#include <sstream>

namespace resigner {

namespace fs = std::filesystem;

KlicenseService::KlicenseService(SceOperations& sce_ops) : sce_{sce_ops} {}

std::optional<std::string> KlicenseService::lookup_cache(const std::string& content_id) const {
    const fs::path cache_file = fs::path{paths::kToolDir} / "kliclist.txt";
    std::ifstream in{cache_file};
    if (!in) {
        return std::nullopt;
    }

    std::string line;
    while (std::getline(in, line)) {
        std::istringstream iss{line};
        std::string cached_content_id;
        std::string klicensee;
        if (iss >> cached_content_id >> klicensee) {
            if (cached_content_id == content_id
                && ps3::np::KlicenseBruteforcer::is_valid_klicensee(klicensee)) {
                return klicensee;
            }
        }
    }
    return std::nullopt;
}

bool KlicenseService::probe_klicensee(const SelfEntry& entry, const std::string& klicensee) const {
    const auto self_path = fs::path{paths::kSelfDir} / entry.filename;
    const auto elf_path = fs::path{paths::kSelfDir}
        / (entry.short_name + "." + entry.elf_extension);

    if (fs::exists(elf_path)) {
        fs::remove(elf_path);
    }

    if (!sce_.decrypt(self_path, elf_path, klicensee)) {
        return false;
    }

    const bool success = fs::exists(elf_path) && fs::file_size(elf_path) > 0;
    if (fs::exists(elf_path)) {
        fs::remove(elf_path);
    }
    return success;
}

void KlicenseService::remember(const std::string& content_id, const std::string& klicensee) const {
    if (!ps3::np::KlicenseBruteforcer::is_valid_klicensee(klicensee)) {
        return;
    }

    const fs::path tool_dir{paths::kToolDir};
    if (!fs::exists(tool_dir)) {
        fs::create_directories(tool_dir);
    }

    {
        std::ofstream pool{tool_dir / "klicpool.txt", std::ios::app};
        pool << klicensee << '\n';
    }
    {
        std::ofstream cache{tool_dir / "kliclist.txt", std::ios::app};
        cache << content_id << ' ' << klicensee << '\n';
    }
}

std::optional<std::string> KlicenseService::bruteforce_pool(
    const SelfEntry& probe_entry,
    const std::vector<std::string>& candidates) const {
    const auto trial = [this, &probe_entry](const std::string& klicensee) {
        return probe_klicensee(probe_entry, klicensee);
    };

    const auto result = ps3::np::KlicenseBruteforcer::search_candidates(candidates, trial);
    if (result.found) {
        Console::println(result.message);
        return result.klicensee;
    }
    return std::nullopt;
}

std::optional<std::string> KlicenseService::bruteforce_with_eboot(
    const SelfEntry& probe_entry) const {
    if (!fs::exists(paths::kEbootElf)) {
        return std::nullopt;
    }

    Console::println("[*] Start BruteForce Detecting Klicensee from EBOOT.ELF, please wait...");

    if (auto found = bruteforce_pool(probe_entry, ps3::np::KlicenseBruteforcer::load_default_pools())) {
        Console::print_formatted("[*] Found Klicensee in EBOOT.BIN: %s\n", found->c_str());
        return found;
    }

    Console::println("[^^!] Cannot find Klicensee, BruteForce Detecting failed.");
    return std::nullopt;
}

std::optional<std::string> KlicenseService::resolve(
    const std::string& content_id,
    const SelfEntry& probe_entry) {
    if (auto cached = lookup_cache(content_id)) {
        Console::print_formatted("[*] Found Klicensee in Klic List: %s\n", cached->c_str());
        return cached;
    }

    if (auto from_rap = ps3::sce::Scetool::klicensee_for_content_id(content_id)) {
        Console::print_formatted("[*] Found Klicensee from RAP/RIF: %s\n", from_rap->c_str());
        remember(content_id, *from_rap);
        return from_rap;
    }

    Console::println("[*] Searching Klic Pool for matching Klicensee...");
    if (auto from_pool = bruteforce_pool(probe_entry, ps3::np::KlicenseBruteforcer::load_default_pools())) {
        Console::print_formatted("[*] Found Klicensee in Klic Pool: %s\n", from_pool->c_str());
        remember(content_id, *from_pool);
        return from_pool;
    }

    if (fs::exists(paths::kEbootBin)) {
        const fs::path eboot_elf{paths::kEbootElf};
        if (!fs::exists(eboot_elf)) {
            (void)sce_.decrypt(paths::kEbootBin, eboot_elf);
        }
        if (auto from_eboot = bruteforce_with_eboot(probe_entry)) {
            remember(content_id, *from_eboot);
            return from_eboot;
        }
    }

    return std::nullopt;
}

} // namespace resigner
