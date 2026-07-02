#pragma once

#include "services/diff_controller.hpp"
#include "services/project_service.hpp"

#include "resigner/sce_operations.hpp"
#include "resigner/settings.hpp"

#include <filesystem>

namespace eboot_diff {

class Application {
public:
    Application();
    [[nodiscard]] int run_gui();
    int run_headless_self_test();
    int run_headless_diff(
        const std::filesystem::path& left,
        const std::filesystem::path& right,
        const std::filesystem::path& report);

private:
    resigner::Settings settings_;
    resigner::SceOperations sce_ops_;
    DiffController controller_;
    ProjectService project_;
};

} // namespace eboot_diff
