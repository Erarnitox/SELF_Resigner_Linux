#include "filesystem.hpp"

#include <array>
#include <algorithm>
#include <cctype>

namespace resigner {

void FileSystem::ensure_workspace() {
    namespace fs = std::filesystem;
    if (!fs::exists(paths::kSelfDir)) {
        fs::create_directory(paths::kSelfDir);
    }
    if (!fs::exists(paths::kRapsDir)) {
        fs::create_directory(paths::kRapsDir);
    }
    if (!fs::exists(paths::kToolDir)) {
        fs::create_directory(paths::kToolDir);
    }
}

void FileSystem::cleanup_tool_artifacts() {
    namespace fs = std::filesystem;
    const fs::path tool{paths::kToolDir};
    const std::array artifacts{
        tool / "selfinfo.txt",
        tool / "selflist.txt",
    };
    for (const auto& artifact : artifacts) {
        if (fs::exists(artifact)) {
            fs::remove(artifact);
        }
    }
}

bool FileSystem::ends_with_ignore_case(const std::string_view value, const std::string_view suffix) {
    if (suffix.size() > value.size()) {
        return false;
    }
    const auto value_tail = value.substr(value.size() - suffix.size());
    return std::equal(
        value_tail.begin(),
        value_tail.end(),
        suffix.begin(),
        suffix.end(),
        [](const char a, const char b) {
            return std::tolower(static_cast<unsigned char>(a))
                == std::tolower(static_cast<unsigned char>(b));
        });
}

std::vector<std::filesystem::path> FileSystem::list_by_extensions(
    const std::filesystem::path& directory,
    const std::vector<std::string>& extensions) {
    namespace fs = std::filesystem;
    std::vector<fs::path> files;
    if (!fs::exists(directory) || !fs::is_directory(directory)) {
        return files;
    }

    for (const auto& entry : fs::directory_iterator(directory)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const auto filename = entry.path().filename().string();
        for (const auto& extension : extensions) {
            if (ends_with_ignore_case(filename, extension)) {
                files.push_back(entry.path().filename());
                break;
            }
        }
    }

    std::ranges::sort(files);
    return files;
}

bool FileSystem::backup_file(const std::filesystem::path& path) {
    namespace fs = std::filesystem;
    if (!fs::exists(path)) {
        return false;
    }
    const auto backup = fs::path{path.string() + ".BAK"};
    if (fs::exists(backup)) {
        fs::remove(backup);
    }
    fs::rename(path, backup);
    return true;
}

} // namespace resigner
