#pragma once

#include "domain/error.hpp"
#include "domain/project.hpp"
#include "domain/types.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace eboot_diff {

class DiffController;

struct ProjectCommentEntry {
    std::uint64_t address{0};
    std::string text;
    std::string label;
};

class ProjectService {
public:
    [[nodiscard]] DiffProject& project() { return project_; }
    [[nodiscard]] const DiffProject& project() const { return project_; }

    void new_project();
    [[nodiscard]] Result<void> load(const std::filesystem::path& path);
    [[nodiscard]] Result<void> save(const std::filesystem::path& path);
    [[nodiscard]] Result<void> save_if_dirty();
    [[nodiscard]] Result<void> try_restore_last_project(DiffController& controller);
    [[nodiscard]] Result<void> apply_to_controller(DiffController& controller, bool allow_partial = false) const;
    void sync_paths_from_session(const DiffController& controller);

    void mark_dirty();
    void clear_dirty();

    [[nodiscard]] std::string& comment_for(std::uint64_t address);
    void set_comment(std::uint64_t address, std::string_view text);
    [[nodiscard]] std::vector<ProjectCommentEntry> list_comments() const;

    void persist_last_project_path() const;
    [[nodiscard]] static std::optional<std::filesystem::path> read_last_project_path();

private:
    DiffProject project_;
};

} // namespace eboot_diff
