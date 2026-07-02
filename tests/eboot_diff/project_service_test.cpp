#include <catch2/catch_test_macros.hpp>

#include "eboot_diff/services/project_service.hpp"
#include "eboot_diff/util/app_paths.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

namespace {

std::filesystem::path make_temp_dir() {
    const auto base = std::filesystem::temp_directory_path()
        / ("eboot_diff_project_test_" + std::to_string(std::rand()));
    std::filesystem::create_directories(base);
    return base;
}

void write_text_file(const std::filesystem::path& path, const std::string& contents) {
    std::ofstream output{path};
    REQUIRE(output);
    output << contents;
}

} // namespace

TEST_CASE("ProjectService save and load roundtrip", "[project]") {
    const auto temp_dir = make_temp_dir();
    const auto left_elf = temp_dir / "left.elf";
    const auto right_elf = temp_dir / "right.elf";
    write_text_file(left_elf, "left");
    write_text_file(right_elf, "right");

    eboot_diff::ProjectService service;
    service.project().left_path = std::filesystem::absolute(left_elf);
    service.project().right_path = std::filesystem::absolute(right_elf);
    service.set_comment(0x000000000010230ULL, "patch hook here");
    service.set_comment(0x000000001c9d740ULL, "entry area note");

    const auto project_path = temp_dir / "sample.ebootdiff";
    REQUIRE(service.save(project_path).has_value());

    eboot_diff::ProjectService loaded;
    REQUIRE(loaded.load(project_path).has_value());
    REQUIRE(loaded.project().left_path.has_value());
    REQUIRE(loaded.project().right_path.has_value());
    REQUIRE(*loaded.project().left_path == std::filesystem::absolute(left_elf));
    REQUIRE(*loaded.project().right_path == std::filesystem::absolute(right_elf));
    REQUIRE(loaded.comment_for(0x000000000010230ULL) == "patch hook here");
    REQUIRE(loaded.comment_for(0x000000001c9d740ULL) == "entry area note");
    REQUIRE_FALSE(loaded.project().dirty);
}

TEST_CASE("ProjectService resolves relative paths from project directory", "[project]") {
    const auto temp_dir = make_temp_dir();
    const auto left_elf = temp_dir / "left.elf";
    const auto right_elf = temp_dir / "right.elf";
    write_text_file(left_elf, "left");
    write_text_file(right_elf, "right");

    const auto project_path = temp_dir / "relative.ebootdiff";
    nlohmann::json document;
    document["version"] = 1;
    document["left"] = "left.elf";
    document["right"] = "right.elf";
    document["comments"] = nlohmann::json::object();
    {
        std::ofstream output{project_path};
        REQUIRE(output);
        output << document.dump(2);
    }

    eboot_diff::ProjectService service;
    REQUIRE(service.load(project_path).has_value());
    REQUIRE(service.project().left_path.has_value());
    REQUIRE(service.project().right_path.has_value());
    REQUIRE(*service.project().left_path == std::filesystem::weakly_canonical(left_elf));
    REQUIRE(*service.project().right_path == std::filesystem::weakly_canonical(right_elf));
}

TEST_CASE("ProjectService persists last project path", "[project]") {
    const auto temp_dir = make_temp_dir();
    const auto config_dir = temp_dir / "config";
    setenv("XDG_CONFIG_HOME", config_dir.c_str(), 1);

    const auto project_path = temp_dir / "last.ebootdiff";
    write_text_file(project_path, R"({"version":1,"comments":{}})");

    eboot_diff::ProjectService service;
    REQUIRE(service.load(project_path).has_value());

    const auto last_project_file = eboot_diff::AppPaths::last_project_file();
    REQUIRE(std::filesystem::exists(last_project_file));

    const auto restored = eboot_diff::ProjectService::read_last_project_path();
    REQUIRE(restored.has_value());
    REQUIRE(*restored == project_path);
}

TEST_CASE("ProjectService escapes comments with quotes and newlines", "[project]") {
    const auto temp_dir = make_temp_dir();
    eboot_diff::ProjectService service;
    service.set_comment(0x1000ULL, "note with \"quotes\" and\nnewline");

    const auto project_path = temp_dir / "escaped.ebootdiff";
    REQUIRE(service.save(project_path).has_value());

    eboot_diff::ProjectService loaded;
    REQUIRE(loaded.load(project_path).has_value());
    REQUIRE(loaded.comment_for(0x1000ULL) == "note with \"quotes\" and\nnewline");
}
