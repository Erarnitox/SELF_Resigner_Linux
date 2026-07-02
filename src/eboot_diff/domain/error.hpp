#pragma once

#include <string>

namespace eboot_diff {

struct AppError {
    std::string message;

    [[nodiscard]] static AppError from(std::string message) {
        return AppError{.message = std::move(message)};
    }
};

} // namespace eboot_diff
