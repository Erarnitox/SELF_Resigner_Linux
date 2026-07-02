#include "diff_pane.hpp"

#include "services/project_service.hpp"

#include <fmt/format.h>

#include <imgui.h>

#include <cstring>

namespace eboot_diff {

namespace {

ImVec4 color_for_kind(const DiffKind kind) {
    switch (kind) {
    case DiffKind::Equal:
        return ImVec4{0.0f, 0.0f, 0.0f, 0.0f};
    case DiffKind::Changed:
        return ImVec4{0.78f, 0.42f, 0.08f, 0.55f};
    case DiffKind::LeftOnly:
        return ImVec4{0.72f, 0.18f, 0.14f, 0.55f};
    case DiffKind::RightOnly:
        return ImVec4{0.74f, 0.28f, 0.10f, 0.55f};
    }
    return ImVec4{0, 0, 0, 0};
}

ImVec4 text_color_for_kind(const DiffKind kind) {
    switch (kind) {
    case DiffKind::Equal:
        return ImGui::GetStyleColorVec4(ImGuiCol_Text);
    case DiffKind::Changed:
        return ImVec4{1.0f, 0.86f, 0.62f, 1.0f};
    case DiffKind::LeftOnly:
    case DiffKind::RightOnly:
        return ImVec4{1.0f, 0.78f, 0.74f, 1.0f};
    }
    return ImGui::GetStyleColorVec4(ImGuiCol_Text);
}

void apply_row_highlight(const DiffKind kind) {
    if (kind == DiffKind::Equal) {
        return;
    }
    const ImU32 color = ImGui::GetColorU32(color_for_kind(kind));
    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, color);
    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, color);
}

void draw_instruction_cell(const std::optional<InstructionLine>& line, const DiffKind kind) {
    if (!line.has_value()) {
        ImGui::TextUnformatted(" ");
        return;
    }
    if (kind != DiffKind::Equal) {
        ImGui::PushStyleColor(ImGuiCol_Text, text_color_for_kind(kind));
        ImGui::TextUnformatted(line->display_text().c_str());
        ImGui::PopStyleColor();
        return;
    }
    ImGui::TextUnformatted(line->display_text().c_str());
}

void draw_comment_cell(ProjectService& project, const std::uint64_t address) {
    char comment_buffer[512]{};
    const auto& comment = project.comment_for(address);
    std::strncpy(comment_buffer, comment.c_str(), sizeof(comment_buffer) - 1);

    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2{0.0f, 0.0f});
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 0.0f);
    ImGui::SetNextItemWidth(-1.0f);
    if (ImGui::InputText("##comment", comment_buffer, sizeof(comment_buffer))) {
        project.set_comment(address, comment_buffer);
    }
    ImGui::PopStyleVar(2);
}

} // namespace

namespace {

bool perform_row_jump(
    DiffController& controller,
    DiffPaneState& state,
    const std::size_t row_index,
    std::string& status_message) {
    if (!controller.jump_to_row(row_index).has_value()) {
        status_message = "Unable to jump to the selected row.";
        return false;
    }
    state.scroll_to_row = static_cast<int>(row_index);
    controller.sync_edit_buffer(state.edit_left, state.edit_buffer);
    status_message.clear();
    return true;
}

} // namespace

bool DiffPane::jump_to_next_diff(
    DiffController& controller,
    DiffPaneState& state,
    std::string& status_message) {
    if (controller.diff_count() == 0) {
        status_message = "No differences found.";
        return false;
    }
    if (!controller.jump_to_next_diff().has_value()) {
        status_message = "No differences found.";
        return false;
    }
    return perform_row_jump(
        controller,
        state,
        static_cast<std::size_t>(controller.session().selected_row),
        status_message);
}

bool DiffPane::jump_to_prev_diff(
    DiffController& controller,
    DiffPaneState& state,
    std::string& status_message) {
    if (controller.diff_count() == 0) {
        status_message = "No differences found.";
        return false;
    }
    if (!controller.jump_to_prev_diff().has_value()) {
        status_message = "No differences found.";
        return false;
    }
    return perform_row_jump(
        controller,
        state,
        static_cast<std::size_t>(controller.session().selected_row),
        status_message);
}

bool DiffPane::jump_to_address(
    DiffController& controller,
    DiffPaneState& state,
    std::string& status_message) {
    if (!controller.session().ready()) {
        status_message = "Load both sides before jumping to an address.";
        return false;
    }

    const auto row = controller.jump_to_address(state.goto_address);
    if (!row.has_value()) {
        status_message = "Invalid or unmapped address.";
        return false;
    }
    return perform_row_jump(controller, state, *row, status_message);
}

bool DiffPane::jump_to_segment(
    DiffController& controller,
    DiffPaneState& state,
    std::string& status_message) {
    if (!controller.session().ready()) {
        status_message = "Load both sides before jumping to a section.";
        return false;
    }

    const auto& segments = controller.segments();
    if (segments.empty()) {
        status_message = "No executable sections found.";
        return false;
    }
    if (state.goto_segment < 0 || static_cast<std::size_t>(state.goto_segment) >= segments.size()) {
        status_message = "Selected section is out of range.";
        return false;
    }

    const auto row = controller.jump_to_segment(static_cast<std::size_t>(state.goto_segment));
    if (!row.has_value()) {
        status_message = "Unable to jump to the selected section.";
        return false;
    }
    return perform_row_jump(controller, state, *row, status_message);
}

bool DiffPane::jump_to_comment(
    ProjectService& project,
    DiffController& controller,
    DiffPaneState& state,
    std::string& status_message) {
    if (!controller.session().ready()) {
        status_message = "Load both sides before jumping to a comment.";
        return false;
    }

    const auto comments = project.list_comments();
    if (comments.empty()) {
        status_message = "No comments in this project.";
        return false;
    }
    if (state.goto_comment < 0 || static_cast<std::size_t>(state.goto_comment) >= comments.size()) {
        status_message = "Selected comment is out of range.";
        return false;
    }

    const auto& entry = comments[static_cast<std::size_t>(state.goto_comment)];
    const auto address_text = fmt::format("0x{:016X}", entry.address);
    const auto row = controller.jump_to_address(address_text);
    if (!row.has_value()) {
        status_message = "Comment address is not present in the current diff.";
        return false;
    }
    return perform_row_jump(controller, state, *row, status_message);
}

void DiffPane::draw(
    ProjectService& project,
    DiffController& controller,
    DiffPaneState& state,
    std::string& status_message) {
    auto& session = controller.session();
    if (!session.left.has_value() && !session.right.has_value()) {
        ImGui::TextUnformatted("Open EBOOT.BIN or EBOOT.ELF files on the left and right to begin.");
        return;
    }

    const float line_height = ImGui::GetTextLineHeightWithSpacing();
    const std::size_t total_rows = session.total_rows();
    const std::size_t diff_count = controller.diff_count();

    if (session.ready() && diff_count > 0) {
        const bool prev_clicked = ImGui::Button("Previous Difference");
        ImGui::SameLine();
        const bool next_clicked = ImGui::Button("Next Difference");
        if (prev_clicked) {
            jump_to_prev_diff(controller, state, status_message);
        }
        if (next_clicked) {
            jump_to_next_diff(controller, state, status_message);
        }
        ImGui::SameLine();
        if (session.selected_row >= 0) {
            if (const auto position = controller.diff_position(static_cast<std::size_t>(session.selected_row))) {
                ImGui::TextDisabled("Difference %zu of %zu", *position, diff_count);
            } else {
                ImGui::TextDisabled("%zu differences", diff_count);
            }
        } else {
            ImGui::TextDisabled("%zu differences", diff_count);
        }

        if (ImGui::Shortcut(ImGuiKey_F3, ImGuiInputFlags_Repeat)) {
            jump_to_next_diff(controller, state, status_message);
        }
        if (ImGui::Shortcut(ImGuiMod_Shift | ImGuiKey_F3, ImGuiInputFlags_Repeat)) {
            jump_to_prev_diff(controller, state, status_message);
        }
    } else if (session.ready()) {
        ImGui::TextDisabled("No differences");
    }

    if (session.ready() && total_rows > 0) {
        if (state.focus_goto_address) {
            ImGui::SetKeyboardFocusHere();
            state.focus_goto_address = false;
        }

        ImGui::SetNextItemWidth(180.0f);
        const bool address_entered = ImGui::InputTextWithHint(
            "##goto_address",
            "0x10000000",
            state.goto_address,
            sizeof(state.goto_address),
            ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::SameLine();
        if (ImGui::Button("Go To Address") || address_entered) {
            jump_to_address(controller, state, status_message);
        }

        const auto& segments = controller.segments();
        if (!segments.empty()) {
            if (state.goto_segment < 0 || static_cast<std::size_t>(state.goto_segment) >= segments.size()) {
                state.goto_segment = 0;
            }

            ImGui::SameLine();
            ImGui::SetNextItemWidth(320.0f);
            if (ImGui::BeginCombo("##goto_segment", segments[static_cast<std::size_t>(state.goto_segment)].label.c_str())) {
                for (int index = 0; index < static_cast<int>(segments.size()); ++index) {
                    const bool selected = state.goto_segment == index;
                    if (ImGui::Selectable(segments[static_cast<std::size_t>(index)].label.c_str(), selected)) {
                        state.goto_segment = index;
                    }
                    if (selected) {
                        ImGui::SetItemDefaultFocus();
                    }
                }
                ImGui::EndCombo();
            }
            ImGui::SameLine();
            if (ImGui::Button("Go To Section")) {
                jump_to_segment(controller, state, status_message);
            }
        }

        const auto comments = project.list_comments();
        if (!comments.empty()) {
            if (state.goto_comment < 0 || static_cast<std::size_t>(state.goto_comment) >= comments.size()) {
                state.goto_comment = 0;
            }

            ImGui::SameLine();
            ImGui::SetNextItemWidth(360.0f);
            if (ImGui::BeginCombo(
                    "##goto_comment",
                    comments[static_cast<std::size_t>(state.goto_comment)].label.c_str())) {
                for (int index = 0; index < static_cast<int>(comments.size()); ++index) {
                    const bool selected = state.goto_comment == index;
                    if (ImGui::Selectable(comments[static_cast<std::size_t>(index)].label.c_str(), selected)) {
                        state.goto_comment = index;
                    }
                    if (selected) {
                        ImGui::SetItemDefaultFocus();
                    }
                }
                ImGui::EndCombo();
            }
            ImGui::SameLine();
            if (ImGui::Button("Go To Comment")) {
                jump_to_comment(project, controller, state, status_message);
            }
        }

        if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_G)) {
            state.focus_goto_address = true;
        }
    }

    const float spacing = ImGui::GetStyle().ItemSpacing.y;
    float bottom_reserved = line_height + spacing;
    if (session.selected_row >= 0) {
        bottom_reserved += line_height + spacing;
        bottom_reserved += ImGui::GetFrameHeightWithSpacing();
        bottom_reserved += ImGui::GetFrameHeightWithSpacing() + spacing;
    }
    const float available_height = std::max(100.0f, ImGui::GetContentRegionAvail().y - bottom_reserved);

    if (state.scroll_to_row >= 0) {
        controller.ensure_rows_loaded(
            static_cast<std::size_t>(state.scroll_to_row),
            static_cast<std::size_t>(state.scroll_to_row) + 1);
    }

    if (!ImGui::BeginTable(
            "diff_columns",
            3,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY,
            ImVec2{0.0f, available_height})) {
        return;
    }
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Left", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupColumn("Right", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupColumn("Comment", ImGuiTableColumnFlags_WidthFixed, 250.0f);
    ImGui::TableHeadersRow();

    if (total_rows == 0) {
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        ImGui::TextUnformatted("Load both sides to compute a diff.");
    } else {
        if (state.scroll_to_row >= 0) {
            ImGui::SetScrollY(static_cast<float>(state.scroll_to_row) * line_height);
        }

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(total_rows), line_height);
        if (state.scroll_to_row >= 0) {
            clipper.IncludeItemByIndex(state.scroll_to_row);
        }
        while (clipper.Step()) {
            controller.ensure_rows_loaded(
                static_cast<std::size_t>(clipper.DisplayStart),
                static_cast<std::size_t>(clipper.DisplayEnd));

            if (!controller.chunk_error().empty()) {
                status_message = std::string{controller.chunk_error()};
            }

            for (int row_index = clipper.DisplayStart; row_index < clipper.DisplayEnd; ++row_index) {
                const auto* row = controller.row_at(static_cast<std::size_t>(row_index));
                if (row == nullptr) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::TextUnformatted("Loading...");
                    continue;
                }

                const bool selected = session.selected_row == row_index;
                const std::uint64_t address = session.aligned_addresses[static_cast<std::size_t>(row_index)];

                ImGui::PushID(row_index);

                ImGui::TableNextRow();
                apply_row_highlight(row->kind);
                ImGui::TableSetColumnIndex(0);
                if (ImGui::Selectable("##left", selected && state.edit_left)) {
                    session.selected_row = row_index;
                    state.edit_left = true;
                    if (row->left) {
                        state.edit_buffer = row->left->mnemonic
                            + (row->left->operands.empty() ? "" : " " + row->left->operands);
                    }
                }

                if (ImGui::BeginPopupContextItem("left_ctx")) {
                    if (ImGui::MenuItem("Copy left -> right")) {
                        if (auto result = controller.copy_row(
                                CopyDirection::LeftToRight,
                                static_cast<std::size_t>(row_index));
                            !result) {
                            status_message = result.error().message;
                        }
                    }
                    ImGui::EndPopup();
                }

                ImGui::SameLine();
                draw_instruction_cell(row->left, row->kind);

                ImGui::TableSetColumnIndex(1);
                if (ImGui::Selectable("##right", selected && !state.edit_left)) {
                    session.selected_row = row_index;
                    state.edit_left = false;
                    if (row->right) {
                        state.edit_buffer = row->right->mnemonic
                            + (row->right->operands.empty() ? "" : " " + row->right->operands);
                    }
                }

                if (ImGui::BeginPopupContextItem("right_ctx")) {
                    if (ImGui::MenuItem("Copy right -> left")) {
                        if (auto result = controller.copy_row(
                                CopyDirection::RightToLeft,
                                static_cast<std::size_t>(row_index));
                            !result) {
                            status_message = result.error().message;
                        }
                    }
                    ImGui::EndPopup();
                }

                ImGui::SameLine();
                draw_instruction_cell(row->right, row->kind);

                ImGui::TableSetColumnIndex(2);
                draw_comment_cell(project, address);

                ImGui::PopID();
            }
        }

        if (state.scroll_to_row >= 0) {
            state.scroll_to_row = -1;
        }
    }

    ImGui::EndTable();

    if (total_rows > 0) {
        const auto& chunk = session.chunk;
        if (chunk.valid) {
            ImGui::TextDisabled(
                "Rows %zu-%zu loaded (%zu total)",
                chunk.row_begin + 1,
                chunk.row_end,
                total_rows);
        } else {
            ImGui::TextDisabled("%zu rows total", total_rows);
        }
    }

    if (session.selected_row >= 0) {
        controller.ensure_rows_loaded(
            static_cast<std::size_t>(session.selected_row),
            static_cast<std::size_t>(session.selected_row) + 1);

        ImGui::Text("Edit selected instruction:");
        char buffer[256]{};
        std::strncpy(buffer, state.edit_buffer.c_str(), sizeof(buffer) - 1);
        if (ImGui::InputText("##asm_edit", buffer, sizeof(buffer))) {
            state.edit_buffer = buffer;
        }
        if (ImGui::Button("Apply Assembly")) {
            if (auto result = controller.apply_assembly_edit(
                    state.edit_left,
                    static_cast<std::size_t>(session.selected_row),
                    state.edit_buffer);
                !result) {
                status_message = result.error().message;
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Copy Left -> Right")) {
            if (auto result = controller.copy_row(
                    CopyDirection::LeftToRight,
                    static_cast<std::size_t>(session.selected_row));
                !result) {
                status_message = result.error().message;
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Copy Right -> Left")) {
            if (auto result = controller.copy_row(
                    CopyDirection::RightToLeft,
                    static_cast<std::size_t>(session.selected_row));
                !result) {
                status_message = result.error().message;
            }
        }
    }
}

} // namespace eboot_diff
