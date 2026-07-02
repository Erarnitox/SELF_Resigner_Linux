#pragma once

#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace ps3::np {

class KlicenseBruteforcer {
public:
    using TrialDecrypt = std::function<bool(const std::string& klicensee_hex)>;

    struct Result {
        bool found{false};
        std::string klicensee;
        std::string message;
    };

    [[nodiscard]] static bool is_valid_klicensee(std::string_view value);

    [[nodiscard]] static std::vector<std::string> load_candidates(
        const std::filesystem::path& candidate_file);

    [[nodiscard]] static std::vector<std::string> load_default_pools();

    [[nodiscard]] static Result search_candidates(
        const std::vector<std::string>& candidates,
        const TrialDecrypt& trial);
};

} // namespace ps3::np
