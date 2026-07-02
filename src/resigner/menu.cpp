#include "menu.hpp"

namespace resigner {

Menu::Menu(Settings& settings, EbootService& eboot, SelfService& self)
    : settings_{settings}, eboot_{eboot}, self_{self} {}

void Menu::render() const {
    Console::clear();
    Console::set_success_color();

    Console::println(" =============================================================================== ");
    Console::println("^|                       TrueAncestor SELF Resigner (Linux)                    ^|");
    Console::println("^|                           by JjKkYu and Erarnitox                           ^|");
    Console::println("^|                                Verision 2.00                                ^|");
    Console::println(" =============================================================================== ");
    Console::println("^|               CEX CFW                ^|                DEX OFW              ^|");
    Console::println(" =============================================================================== ");
    Console::println("^| 1. Decrypt EBOOT.BIN Only            ^| 9. Decrypt EBOOT.BIN (FSELF) Only   ^|");
    Console::println("^| 2. Resign to NON-DRM EBOOT           ^| 10. Resign to NON-DRM EBOOT         ^|");
    Console::println("^| 3. Resign to NPDRM EBOOT             ^| 11. Resign to NPDRM EBOOT           ^|");
    Console::println("^| 4. Decrypt SELF/SPRX Only            ^|                                     ^|");
    Console::println("^| 5. Fast Resign NON-DRM SELF/SPRX     ^|                                     ^|");
    Console::println("^| 6. Fast Resign NPDRM SELF/SPRX       ^|                                     ^|");
    Console::println("^| 7. Custom Sign to NON-DRM SELF/SPRX  ^|                                     ^|");
    Console::println("^| 8. Custom Sign to NPDRM SELF/SPRX    ^|                                     ^|");
    Console::println(" =============================================================================== ");
    Console::println("^|                               SWITCH (CEX CFW)                              ^|");
    Console::println(" =============================================================================== ");
    Console::print_formatted("^| 12. Output Method: %-50s^|\n", settings_.output_label().c_str());
    Console::print_formatted("^| 13. Compress Data: %-56s^|\n", settings_.compress_label().c_str());
    Console::println("^|                                                                             ^|");
    Console::println("^|                                                                             ^|");
    Console::println(" =============================================================================== ");
    Console::println("^| Note: Place EBOOT.BIN/ELF into Resigner folder before operation.            ^|");
    Console::println("^|       Place SELF/SPRX files into self folder before operation.              ^|");
    Console::println(" =============================================================================== ");
}

void Menu::cycle_output_mode() {
    settings_.cycle_output_mode();
    Console::print_formatted("[*] Output method has been set to %s.\n", settings_.output_label().c_str());
    Console::wait_for_enter();
}

void Menu::toggle_compress_data() {
    if (settings_.compress_data) {
        if (Console::confirm("Enter Y to disable Compress Data / any other key to abort: ")) {
            settings_.set_compress_data(false);
            Console::println("[*] Compress Data disabled.");
        }
    } else if (Console::confirm("Enter Y to enable Compress Data / any other key to abort: ")) {
        settings_.set_compress_data(true);
        Console::println("[*] Compress Data enabled.");
    }
    Console::wait_for_enter();
}

void Menu::handle_choice(const int choice) {
    switch (choice) {
    case 1: eboot_.decrypt_only(); return;
    case 2: eboot_.resign_non_drm(); return;
    case 3: eboot_.resign_npdrm(); return;
    case 4: self_.list_self_files(); return;
    case 5: self_.fast_resign_non_drm(); return;
    case 6: self_.fast_resign_npdrm(); return;
    case 7: self_.list_elf_files(false); return;
    case 8: self_.list_elf_files(true); return;
    case 9: eboot_.decrypt_fself(); return;
    case 10: eboot_.resign_non_drm_dex(); return;
    case 11: eboot_.resign_npdrm_dex(); return;
    case 12: cycle_output_mode(); return;
    case 13: toggle_compress_data(); return;
    default: break;
    }

    Console::println("Invalid input, please enter among (1-13).");
    Console::println("[*] Press [ENTER] to continue...");
    Console::wait_for_enter();
}

void Menu::run_once() {
    FileSystem::ensure_workspace();
    FileSystem::cleanup_tool_artifacts();
    render();

    const int choice = Console::read_int("Please enter your choice (1-13): ");
    handle_choice(choice);
}

} // namespace resigner
