#pragma once

#include "domain/project.hpp"

#include <string>

namespace eboot_diff {

inline constexpr const char* kAppName = "Erarnitox's Awesome EBOOT Patcher";
inline constexpr const char* kStar = "\xe2\x98\x85";

inline std::string window_title(const DiffProject& project) {
    std::string title = kStar;
    title += " ";
    title += kAppName;
    title += " ";
    title += kStar;
    title += " — ";
    if (project.dirty) {
        title += "* ";
    }
    title += project.display_name();
    return title;
}

} // namespace eboot_diff
