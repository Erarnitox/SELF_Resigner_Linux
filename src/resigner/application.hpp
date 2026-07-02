#pragma once

#include "eboot_service.hpp"
#include "menu.hpp"
#include "sce_operations.hpp"
#include "self_service.hpp"
#include "settings.hpp"

namespace resigner {

/// Application entry point and dependency wiring.
class Application {
public:
    Application();

    [[nodiscard]] int run();

private:
    Settings settings_;
    SceOperations sce_ops_;
    EbootService eboot_service_;
    SelfService self_service_;
    Menu menu_;
};

} // namespace resigner
