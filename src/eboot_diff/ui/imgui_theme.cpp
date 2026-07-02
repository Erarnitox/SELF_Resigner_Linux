#include "imgui_theme.hpp"

#include <imgui.h>

namespace eboot_diff {

namespace {

ImVec4 rgba(const int r, const int g, const int b, const float a = 1.0f) {
    return ImVec4{
        static_cast<float>(r) / 255.0f,
        static_cast<float>(g) / 255.0f,
        static_cast<float>(b) / 255.0f,
        a};
}

} // namespace

void apply_modern_style() {
    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;

    style.WindowRounding = 8.0f;
    style.ChildRounding = 6.0f;
    style.FrameRounding = 6.0f;
    style.PopupRounding = 8.0f;
    style.ScrollbarRounding = 6.0f;
    style.GrabRounding = 4.0f;
    style.TabRounding = 6.0f;

    style.WindowPadding = ImVec2{14.0f, 12.0f};
    style.FramePadding = ImVec2{10.0f, 6.0f};
    style.CellPadding = ImVec2{10.0f, 6.0f};
    style.ItemSpacing = ImVec2{10.0f, 8.0f};
    style.ItemInnerSpacing = ImVec2{8.0f, 6.0f};
    style.IndentSpacing = 18.0f;
    style.ScrollbarSize = 14.0f;
    style.GrabMinSize = 12.0f;

    style.WindowBorderSize = 1.0f;
    style.ChildBorderSize = 1.0f;
    style.PopupBorderSize = 1.0f;
    style.FrameBorderSize = 0.0f;
    style.TabBorderSize = 0.0f;

    style.WindowTitleAlign = ImVec2{0.5f, 0.5f};
    style.ButtonTextAlign = ImVec2{0.5f, 0.5f};
    style.SelectableTextAlign = ImVec2{0.0f, 0.5f};
    style.AntiAliasedLines = true;
    style.AntiAliasedFill = true;
    style.AntiAliasedLinesUseTex = true;

    const ImVec4 background = rgba(17, 20, 28);
    const ImVec4 surface = rgba(24, 29, 39);
    const ImVec4 surface_alt = rgba(31, 38, 51);
    const ImVec4 border = rgba(52, 62, 82);
    const ImVec4 text = rgba(220, 227, 239);
    const ImVec4 text_muted = rgba(141, 153, 176);
    const ImVec4 accent = rgba(122, 162, 247);
    const ImVec4 accent_hover = rgba(152, 187, 255);
    const ImVec4 accent_active = rgba(96, 136, 220);

    colors[ImGuiCol_Text] = text;
    colors[ImGuiCol_TextDisabled] = text_muted;
    colors[ImGuiCol_WindowBg] = background;
    colors[ImGuiCol_ChildBg] = surface;
    colors[ImGuiCol_PopupBg] = surface;
    colors[ImGuiCol_Border] = border;
    colors[ImGuiCol_BorderShadow] = rgba(0, 0, 0, 0.0f);
    colors[ImGuiCol_FrameBg] = surface_alt;
    colors[ImGuiCol_FrameBgHovered] = rgba(39, 47, 63);
    colors[ImGuiCol_FrameBgActive] = rgba(47, 57, 76);
    colors[ImGuiCol_TitleBg] = surface;
    colors[ImGuiCol_TitleBgActive] = surface_alt;
    colors[ImGuiCol_TitleBgCollapsed] = rgba(24, 29, 39, 0.75f);
    colors[ImGuiCol_MenuBarBg] = surface;
    colors[ImGuiCol_ScrollbarBg] = rgba(17, 20, 28, 0.53f);
    colors[ImGuiCol_ScrollbarGrab] = rgba(62, 74, 96);
    colors[ImGuiCol_ScrollbarGrabHovered] = rgba(78, 92, 118);
    colors[ImGuiCol_ScrollbarGrabActive] = accent;
    colors[ImGuiCol_CheckMark] = accent;
    colors[ImGuiCol_SliderGrab] = accent;
    colors[ImGuiCol_SliderGrabActive] = accent_active;
    colors[ImGuiCol_Button] = rgba(43, 53, 72);
    colors[ImGuiCol_ButtonHovered] = rgba(56, 68, 92);
    colors[ImGuiCol_ButtonActive] = rgba(67, 81, 110);
    colors[ImGuiCol_Header] = rgba(43, 53, 72, 0.65f);
    colors[ImGuiCol_HeaderHovered] = rgba(56, 68, 92, 0.85f);
    colors[ImGuiCol_HeaderActive] = rgba(67, 81, 110, 0.95f);
    colors[ImGuiCol_Separator] = border;
    colors[ImGuiCol_SeparatorHovered] = accent_hover;
    colors[ImGuiCol_SeparatorActive] = accent;
    colors[ImGuiCol_ResizeGrip] = rgba(62, 74, 96, 0.25f);
    colors[ImGuiCol_ResizeGripHovered] = rgba(78, 92, 118, 0.67f);
    colors[ImGuiCol_ResizeGripActive] = accent;
    colors[ImGuiCol_Tab] = rgba(31, 38, 51, 0.86f);
    colors[ImGuiCol_TabHovered] = rgba(56, 68, 92, 0.95f);
    colors[ImGuiCol_TabActive] = rgba(43, 53, 72, 1.0f);
    colors[ImGuiCol_TabUnfocused] = rgba(24, 29, 39, 0.97f);
    colors[ImGuiCol_TabUnfocusedActive] = rgba(31, 38, 51, 1.0f);
    colors[ImGuiCol_PlotLines] = accent;
    colors[ImGuiCol_PlotLinesHovered] = accent_hover;
    colors[ImGuiCol_PlotHistogram] = accent;
    colors[ImGuiCol_PlotHistogramHovered] = accent_hover;
    colors[ImGuiCol_TableHeaderBg] = surface_alt;
    colors[ImGuiCol_TableBorderStrong] = border;
    colors[ImGuiCol_TableBorderLight] = rgba(52, 62, 82, 0.55f);
    colors[ImGuiCol_TableRowBg] = rgba(0, 0, 0, 0.0f);
    colors[ImGuiCol_TableRowBgAlt] = rgba(255, 255, 255, 0.02f);
    colors[ImGuiCol_TextSelectedBg] = rgba(122, 162, 247, 0.35f);
    colors[ImGuiCol_DragDropTarget] = rgba(122, 162, 247, 0.90f);
    colors[ImGuiCol_NavHighlight] = accent;
    colors[ImGuiCol_NavWindowingHighlight] = rgba(255, 255, 255, 0.70f);
    colors[ImGuiCol_NavWindowingDimBg] = rgba(0, 0, 0, 0.20f);
    colors[ImGuiCol_ModalWindowDimBg] = rgba(0, 0, 0, 0.55f);
}

} // namespace eboot_diff
