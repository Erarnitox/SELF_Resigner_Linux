#include "main_window.hpp"

#include "ui/diff_pane.hpp"
#include "ui/file_dialogs.hpp"
#include "ui/imgui_theme.hpp"
#include "util/branding.hpp"
#include "util/window_icon.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include <GL/gl.h>
#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>

#include "util/branding.hpp"

#include <cstring>

namespace eboot_diff {

MainWindow::MainWindow(DiffController& controller, ProjectService& project)
    : controller_{controller},
      project_{project} {
    if (!glfwInit()) {
        return;
    }

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 2);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 1);

    window_ = glfwCreateWindow(1400, 900, (std::string{kStar} + " " + kAppName + " " + kStar).c_str(), nullptr, nullptr);
    if (window_ == nullptr) {
        return;
    }

    (void)set_window_icon(window_);

    glfwMakeContextCurrent(window_);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;

    apply_modern_style();

    ImGui_ImplGlfw_InitForOpenGL(window_, true);
    ImGui_ImplOpenGL3_Init("#version 120");
}

bool MainWindow::should_close() const {
    return window_ == nullptr || glfwWindowShouldClose(window_);
}

void MainWindow::set_status_message(const std::string message) {
    status_message_ = std::move(message);
}

void MainWindow::update_title() {
    if (window_ == nullptr) {
        return;
    }
    glfwSetWindowTitle(window_, window_title(project_.project()).c_str());
}

void MainWindow::request_quit() {
    if (quit_handled_) {
        return;
    }
    quit_handled_ = true;

    if (auto result = project_.save_if_dirty(); !result) {
        status_message_ = result.error().message;
    }
    project_.persist_last_project_path();
    if (window_ != nullptr) {
        glfwSetWindowShouldClose(window_, GLFW_TRUE);
    }
}

void MainWindow::open_left_file() {
    if (auto path = FileDialogs::open_eboot()) {
        if (auto result = controller_.open_left(*path); !result) {
            status_message_ = result.error().message;
        } else {
            project_.sync_paths_from_session(controller_);
            status_message_.clear();
            update_title();
        }
    }
}

void MainWindow::open_right_file() {
    if (auto path = FileDialogs::open_eboot()) {
        if (auto result = controller_.open_right(*path); !result) {
            status_message_ = result.error().message;
        } else {
            project_.sync_paths_from_session(controller_);
            status_message_.clear();
            update_title();
        }
    }
}

void MainWindow::render_frame() {
    if (window_ == nullptr) {
        return;
    }

    glfwPollEvents();

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();

    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("New Project")) {
                project_.new_project();
                controller_.session().clear();
                status_message_.clear();
                update_title();
            }
            if (ImGui::MenuItem("Open Project...")) {
                if (auto path = FileDialogs::open_project()) {
                    if (auto result = project_.load(*path); !result) {
                        status_message_ = result.error().message;
                    } else if (auto apply = project_.apply_to_controller(controller_, true); !apply) {
                        status_message_ = apply.error().message;
                        update_title();
                    } else {
                        status_message_.clear();
                        update_title();
                    }
                }
            }
            const bool has_project_path = project_.project().has_path();
            if (ImGui::MenuItem("Save Project", "Ctrl+S", false, has_project_path)) {
                if (auto result = project_.save(*project_.project().project_path); !result) {
                    status_message_ = result.error().message;
                } else {
                    status_message_.clear();
                    update_title();
                }
            }
            if (ImGui::MenuItem("Save Project As...")) {
                const std::string default_name = has_project_path
                    ? project_.project().project_path->filename().string()
                    : "project.ebootdiff";
                if (auto path = FileDialogs::save_project(default_name)) {
                    if (auto result = project_.save(*path); !result) {
                        status_message_ = result.error().message;
                    } else {
                        status_message_.clear();
                        update_title();
                    }
                }
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Open Left...")) {
                open_left_file();
            }
            if (ImGui::MenuItem("Open Right...")) {
                open_right_file();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Export Left ELF...")) {
                if (auto path = FileDialogs::save_elf()) {
                    if (auto result = controller_.export_side(true, *path, false); !result) {
                        status_message_ = result.error().message;
                    }
                }
            }
            if (ImGui::MenuItem("Export Left BIN...")) {
                if (auto path = FileDialogs::save_bin()) {
                    if (auto result = controller_.export_side(true, *path, true); !result) {
                        status_message_ = result.error().message;
                    }
                }
            }
            if (ImGui::MenuItem("Export Right ELF...")) {
                if (auto path = FileDialogs::save_elf()) {
                    if (auto result = controller_.export_side(false, *path, false); !result) {
                        status_message_ = result.error().message;
                    }
                }
            }
            if (ImGui::MenuItem("Export Right BIN...")) {
                if (auto path = FileDialogs::save_bin()) {
                    if (auto result = controller_.export_side(false, *path, true); !result) {
                        status_message_ = result.error().message;
                    }
                }
            }
            if (ImGui::MenuItem("Quit")) {
                request_quit();
            }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Navigate")) {
            const bool has_diffs = controller_.session().ready() && controller_.diff_count() > 0;
            const bool can_goto = controller_.session().ready() && controller_.session().total_rows() > 0;
            if (ImGui::MenuItem("Next Difference", "F3", false, has_diffs)) {
                diff_pane_.jump_to_next_diff(controller_, pane_state_, status_message_);
            }
            if (ImGui::MenuItem("Previous Difference", "Shift+F3", false, has_diffs)) {
                diff_pane_.jump_to_prev_diff(controller_, pane_state_, status_message_);
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Go To Address...", "Ctrl+G", false, can_goto)) {
                pane_state_.focus_goto_address = true;
            }
            if (ImGui::MenuItem("Go To Section...", nullptr, false, can_goto && !controller_.segments().empty())) {
                pane_state_.focus_goto_address = false;
                if (!controller_.segments().empty()) {
                    diff_pane_.jump_to_segment(controller_, pane_state_, status_message_);
                }
            }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Settings")) {
            if (ImGui::MenuItem("Resign Settings...")) {
                show_settings_ = true;
            }
            ImGui::EndMenu();
        }
        ImGui::EndMainMenuBar();
    }

    if (show_settings_) {
        ImGui::Begin("Resign Settings", &show_settings_);
        auto& settings = controller_.settings();
        int output_mode = static_cast<int>(settings.output_mode);
        ImGui::SliderInt("Output Mode", &output_mode, 0, 4);
        settings.output_mode = static_cast<resigner::OutputMode>(output_mode);
        ImGui::Checkbox("Compress Data", &settings.compress_data);
        char content_id[64]{};
        std::strncpy(content_id, settings.content_id.c_str(), sizeof(content_id) - 1);
        if (ImGui::InputText("Content ID", content_id, sizeof(content_id))) {
            settings.content_id = content_id;
        }
        char klicensee[40]{};
        std::strncpy(klicensee, settings.klicensee.c_str(), sizeof(klicensee) - 1);
        if (ImGui::InputText("Klicensee", klicensee, sizeof(klicensee))) {
            settings.klicensee = klicensee;
        }
        ImGui::End();
    }

    ImGui::SetNextWindowPos(ImVec2{0.0f, ImGui::GetFrameHeight()}, ImGuiCond_Always);
    ImGui::SetNextWindowSize(
        ImVec2{ImGui::GetIO().DisplaySize.x, ImGui::GetIO().DisplaySize.y - ImGui::GetFrameHeight() - 24.0f},
        ImGuiCond_Always);
    ImGui::Begin(
        "DiffView",
        nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus);

    if (ImGui::Button("Open Left")) {
        open_left_file();
    }
    ImGui::SameLine();
    if (ImGui::Button("Open Right")) {
        open_right_file();
    }

    const auto& session = controller_.session();
    if (session.left) {
        ImGui::SameLine();
        ImGui::Text("Left: %s", session.left->source_path.string().c_str());
    }
    if (session.right) {
        ImGui::SameLine();
        ImGui::Text("Right: %s", session.right->source_path.string().c_str());
    }

    diff_pane_.draw(project_, controller_, pane_state_, status_message_);
    ImGui::End();

    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_S)) {
        if (project_.project().has_path()) {
            if (auto result = project_.save(*project_.project().project_path); !result) {
                status_message_ = result.error().message;
            } else {
                status_message_.clear();
                update_title();
            }
        } else if (auto path = FileDialogs::save_project("project.ebootdiff")) {
            if (auto result = project_.save(*path); !result) {
                status_message_ = result.error().message;
            } else {
                status_message_.clear();
                update_title();
            }
        }
    }

    if (window_ != nullptr && glfwWindowShouldClose(window_)) {
        request_quit();
    }

    ImGui::SetNextWindowPos(ImVec2{0.0f, ImGui::GetIO().DisplaySize.y - 24.0f}, ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2{ImGui::GetIO().DisplaySize.x, 24.0f}, ImGuiCond_Always);
    ImGui::Begin(
        "StatusBar",
        nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus);
    if (!status_message_.empty()) {
        ImGui::TextUnformatted(status_message_.c_str());
    } else {
        ImGui::TextUnformatted("Ready");
    }
    ImGui::End();

    ImGui::Render();
    const int display_w = static_cast<int>(ImGui::GetIO().DisplaySize.x);
    const int display_h = static_cast<int>(ImGui::GetIO().DisplaySize.y);
    glViewport(0, 0, display_w, display_h);
    glClearColor(0.067f, 0.078f, 0.110f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    glfwSwapBuffers(window_);
}

} // namespace eboot_diff
