#include "project.hpp"

#include "project.hpp"

namespace eboot_diff {

void DiffProject::clear() {
    left_path.reset();
    right_path.reset();
    comments.clear();
    project_path.reset();
    dirty = false;
}

std::string DiffProject::display_name() const {
    if (!project_path.has_value()) {
        return "Unsaved project";
    }
    return project_path->filename().string();
}

} // namespace eboot_diff
