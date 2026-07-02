#pragma once

#include "services/diff_controller.hpp"
#include "services/project_service.hpp"

#include <string>

namespace eboot_diff {

struct DiffPaneState {
    std::string edit_buffer;
    bool edit_left{true};
    int scroll_to_row{-1};
    char goto_address[32]{};
    int goto_segment{0};
    int goto_comment{0};
    bool focus_goto_address{false};
};

class DiffPane {
public:
    void draw(
        ProjectService& project,
        DiffController& controller,
        DiffPaneState& state,
        std::string& status_message);
    bool jump_to_next_diff(DiffController& controller, DiffPaneState& state, std::string& status_message);
    bool jump_to_prev_diff(DiffController& controller, DiffPaneState& state, std::string& status_message);
    bool jump_to_address(DiffController& controller, DiffPaneState& state, std::string& status_message);
    bool jump_to_segment(DiffController& controller, DiffPaneState& state, std::string& status_message);
    bool jump_to_comment(
        ProjectService& project,
        DiffController& controller,
        DiffPaneState& state,
        std::string& status_message);
};

} // namespace eboot_diff
