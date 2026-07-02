#include "klicense_bruteforce.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <string_view>

namespace ps3::np {

namespace {

std::string normalize_hex(std::string_view value) {
    std::string normalized;
    normalized.reserve(value.size());
    for (const char c : value) {
        if (std::isxdigit(static_cast<unsigned char>(c)) != 0) {
            normalized.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
        }
    }
    return normalized;
}

} // namespace

bool KlicenseBruteforcer::is_valid_klicensee(const std::string_view value) {
    if (value.size() != 32) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](const char c) {
        return std::isxdigit(static_cast<unsigned char>(c)) != 0;
    });
}

std::vector<std::string> KlicenseBruteforcer::load_candidates(
    const std::filesystem::path& candidate_file) {
    std::vector<std::string> candidates;
    std::ifstream input{candidate_file};
    if (!input) {
        return candidates;
    }

    std::string line;
    while (std::getline(input, line)) {
        const auto candidate = normalize_hex(line);
        if (is_valid_klicensee(candidate)) {
            candidates.push_back(candidate);
        }
    }

    std::sort(candidates.begin(), candidates.end());
    candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());
    return candidates;
}

std::vector<std::string> KlicenseBruteforcer::load_default_pools() {
    std::vector<std::string> candidates;
    const std::array pool_paths{
        std::filesystem::path{"tool"} / "klicpool.txt",
        std::filesystem::path{"res"} / "klicpool.txt",
    };

    for (const auto& pool_path : pool_paths) {
        auto from_file = load_candidates(pool_path);
        candidates.insert(candidates.end(), from_file.begin(), from_file.end());
    }

    std::sort(candidates.begin(), candidates.end());
    candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());
    return candidates;
}

KlicenseBruteforcer::Result KlicenseBruteforcer::search_candidates(
    const std::vector<std::string>& candidates,
    const TrialDecrypt& trial) {
    for (const auto& candidate : candidates) {
        if (trial(candidate)) {
            return Result{
                .found = true,
                .klicensee = candidate,
                .message = "[*] Found key! Klicensee is " + candidate,
            };
        }
    }

    return Result{
        .found = false,
        .message = "[*] not found in key pool.",
    };
}

} // namespace ps3::np
