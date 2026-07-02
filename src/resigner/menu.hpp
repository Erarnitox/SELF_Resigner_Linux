#pragma once

#include "console.hpp"
#include "eboot_service.hpp"
#include "filesystem.hpp"
#include "self_service.hpp"
#include "settings.hpp"

namespace resigner {

/// Main menu and option dispatch.
class Menu {
public:
    Menu(Settings& settings, EbootService& eboot, SelfService& self);

    void run_once();

private:
    Settings& settings_;
    EbootService& eboot_;
    SelfService& self_;

    void render() const;
    void handle_choice(int choice);
    void cycle_output_mode();
    void toggle_compress_data();
};

} // namespace resigner
