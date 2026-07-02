#pragma once

#include "services/diff_controller.hpp"
#include "services/project_service.hpp"
#include "ui/diff_pane.hpp"

#include <string>

struct GLFWwindow;

namespace eboot_diff {

class MainWindow {
public:
    MainWindow(DiffController& controller, ProjectService& project);

    [[nodiscard]] bool should_close() const;
    void render_frame();
    void set_status_message(std::string message);
    void update_title();

private:
    void request_quit();
    void open_left_file();
    void open_right_file();

    DiffController& controller_;
    ProjectService& project_;
    GLFWwindow* window_{nullptr};
    std::string status_message_;
    DiffPaneState pane_state_;
    bool show_settings_{false};
    bool quit_handled_{false};
    DiffPane diff_pane_;
};

} // namespace eboot_diff
