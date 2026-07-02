#include "project_service.hpp"

#include "services/diff_controller.hpp"
#include "util/app_paths.hpp"

#include <fmt/format.h>

#include <fstream>
#include <nlohmann/json.hpp>
#include <string_view>
#include <vector>

#include <algorithm>

namespace eboot_diff {

namespace {

std::string address_to_string(const std::uint64_t address) {
    return fmt::format("0x{:016X}", address);
}

std::optional<std::uint64_t> parse_address_key(const std::string& key) {
    std::string_view trimmed = key;
    int base = 10;
    if (trimmed.size() > 2 && trimmed[0] == '0' && (trimmed[1] == 'x' || trimmed[1] == 'X')) {
        trimmed.remove_prefix(2);
        base = 16;
    } else {
        base = 16;
    }
    if (trimmed.empty()) {
        return std::nullopt;
    }

    std::uint64_t value = 0;
    for (const char ch : trimmed) {
        int digit = -1;
        if (ch >= '0' && ch <= '9') {
            digit = ch - '0';
        } else if (ch >= 'a' && ch <= 'f') {
            digit = 10 + (ch - 'a');
        } else if (ch >= 'A' && ch <= 'F') {
            digit = 10 + (ch - 'A');
        } else {
            return std::nullopt;
        }
        if (digit >= base) {
            return std::nullopt;
        }
        value = value * static_cast<std::uint64_t>(base) + static_cast<std::uint64_t>(digit);
    }
    return value;
}

std::optional<std::filesystem::path> resolve_project_path(
    const std::filesystem::path& project_file,
    const std::optional<std::string>& stored_path) {
    if (!stored_path.has_value() || stored_path->empty()) {
        return std::nullopt;
    }

    std::filesystem::path candidate{*stored_path};
    if (candidate.is_absolute() && std::filesystem::exists(candidate)) {
        return candidate;
    }

    const auto relative_candidate = project_file.parent_path() / candidate;
    if (std::filesystem::exists(relative_candidate)) {
        return std::filesystem::weakly_canonical(relative_candidate);
    }

    if (std::filesystem::exists(candidate)) {
        return std::filesystem::weakly_canonical(candidate);
    }

    return candidate;
}

} // namespace

void ProjectService::new_project() {
    project_.clear();
}

Result<void> ProjectService::load(const std::filesystem::path& path) {
    std::ifstream input{path};
    if (!input) {
        return std::unexpected(AppError::from("Failed to open project file: " + path.string()));
    }

    nlohmann::json document;
    try {
        input >> document;
    } catch (const nlohmann::json::exception& error) {
        return std::unexpected(AppError::from(std::string{"Invalid project JSON: "} + error.what()));
    }

    DiffProject loaded{};
    if (document.contains("left") && document["left"].is_string()) {
        loaded.left_path = resolve_project_path(path, document["left"].get<std::string>());
    }
    if (document.contains("right") && document["right"].is_string()) {
        loaded.right_path = resolve_project_path(path, document["right"].get<std::string>());
    }
    if (document.contains("comments") && document["comments"].is_object()) {
        for (const auto& [key, value] : document["comments"].items()) {
            if (!value.is_string()) {
                continue;
            }
            const auto address = parse_address_key(key);
            if (!address.has_value()) {
                continue;
            }
            loaded.comments.emplace(*address, value.get<std::string>());
        }
    }

    loaded.project_path = path;
    loaded.dirty = false;
    project_ = std::move(loaded);
    persist_last_project_path();
    return {};
}

Result<void> ProjectService::save(const std::filesystem::path& path) {
    nlohmann::json document;
    document["version"] = 1;
    if (project_.left_path.has_value()) {
        document["left"] = std::filesystem::absolute(*project_.left_path).string();
    }
    if (project_.right_path.has_value()) {
        document["right"] = std::filesystem::absolute(*project_.right_path).string();
    }

    nlohmann::json comments = nlohmann::json::object();
    for (const auto& [address, text] : project_.comments) {
        if (!text.empty()) {
            comments[address_to_string(address)] = text;
        }
    }
    document["comments"] = std::move(comments);

    std::ofstream output{path};
    if (!output) {
        return std::unexpected(AppError::from("Failed to write project file: " + path.string()));
    }
    output << document.dump(2) << '\n';
    if (!output) {
        return std::unexpected(AppError::from("Failed to write project file: " + path.string()));
    }

    project_.project_path = path;
    project_.dirty = false;
    persist_last_project_path();
    return {};
}

Result<void> ProjectService::save_if_dirty() {
    if (!project_.dirty || !project_.project_path.has_value()) {
        return {};
    }
    return save(*project_.project_path);
}

Result<void> ProjectService::try_restore_last_project(DiffController& controller) {
    const auto last_project = read_last_project_path();
    if (!last_project.has_value() || !std::filesystem::exists(*last_project)) {
        return {};
    }

    if (auto loaded = load(*last_project); !loaded) {
        return loaded;
    }
    return apply_to_controller(controller, true);
}

void ProjectService::mark_dirty() {
    project_.dirty = true;
}

void ProjectService::clear_dirty() {
    project_.dirty = false;
}

std::string& ProjectService::comment_for(const std::uint64_t address) {
    return project_.comments[address];
}

void ProjectService::set_comment(const std::uint64_t address, const std::string_view text) {
    const std::string new_text{text};
    const auto existing = project_.comments.find(address);
    if (existing != project_.comments.end() && existing->second == new_text) {
        return;
    }
    if (new_text.empty()) {
        if (existing != project_.comments.end()) {
            project_.comments.erase(existing);
            mark_dirty();
        }
        return;
    }
    project_.comments[address] = new_text;
    mark_dirty();
}

std::vector<ProjectCommentEntry> ProjectService::list_comments() const {
    std::vector<std::pair<std::uint64_t, std::string>> items;
    items.reserve(project_.comments.size());
    for (const auto& [address, text] : project_.comments) {
        if (!text.empty()) {
            items.emplace_back(address, text);
        }
    }

    std::sort(items.begin(), items.end(), [](const auto& left, const auto& right) {
        return left.first < right.first;
    });

    std::vector<ProjectCommentEntry> entries;
    entries.reserve(items.size());
    for (const auto& [address, text] : items) {
        ProjectCommentEntry entry{};
        entry.address = address;
        entry.text = text;
        std::string label = fmt::format("0x{:016X} — {}", address, text);
        if (label.size() > 96) {
            label.resize(93);
            label += "...";
        }
        entry.label = std::move(label);
        entries.push_back(std::move(entry));
    }
    return entries;
}

void ProjectService::persist_last_project_path() const {
    if (!project_.project_path.has_value()) {
        return;
    }

    const auto config_dir = AppPaths::config_directory();
    std::error_code error;
    std::filesystem::create_directories(config_dir, error);

    std::ofstream output{AppPaths::last_project_file()};
    if (!output) {
        return;
    }
    output << project_.project_path->string() << '\n';
}

std::optional<std::filesystem::path> ProjectService::read_last_project_path() {
    const auto last_project_file = AppPaths::last_project_file();
    if (!std::filesystem::exists(last_project_file)) {
        return std::nullopt;
    }

    std::ifstream input{last_project_file};
    if (!input) {
        return std::nullopt;
    }

    std::string path;
    std::getline(input, path);
    if (path.empty()) {
        return std::nullopt;
    }
    return std::filesystem::path{path};
}

Result<void> ProjectService::apply_to_controller(DiffController& controller, const bool allow_partial) const {
    controller.session().clear();

    std::string errors;
    if (project_.left_path.has_value()) {
        if (auto result = controller.open_left(*project_.left_path); !result) {
            if (!allow_partial) {
                return result;
            }
            errors = result.error().message;
        }
    }
    if (project_.right_path.has_value()) {
        if (auto result = controller.open_right(*project_.right_path); !result) {
            if (!allow_partial) {
                return result;
            }
            if (!errors.empty()) {
                errors += "; ";
            }
            errors += result.error().message;
        }
    }

    if (!errors.empty()) {
        return std::unexpected(AppError::from(errors));
    }
    return {};
}

void ProjectService::sync_paths_from_session(const DiffController& controller) {
    if (controller.session().left.has_value()) {
        project_.left_path = controller.session().left->source_path;
    }
    if (controller.session().right.has_value()) {
        project_.right_path = controller.session().right->source_path;
    }
    mark_dirty();
}

} // namespace eboot_diff
