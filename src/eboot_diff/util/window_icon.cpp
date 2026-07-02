#define STB_IMAGE_IMPLEMENTATION
#include <stb_image.h>
#define STB_IMAGE_RESIZE_IMPLEMENTATION
#include <stb_image_resize2.h>

#include "window_icon.hpp"

#include "util/app_paths.hpp"

#include <GLFW/glfw3.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <vector>

namespace eboot_diff {

namespace {

std::optional<std::filesystem::path> find_app_icon_path() {
    const std::vector<std::filesystem::path> relative_candidates{
        std::filesystem::path{"data/icons/app_icon.png"},
        std::filesystem::path{"../res/icons/app_icon.png"},
    };

    if (const auto executable_dir = AppPaths::executable_directory()) {
        for (const auto& relative : relative_candidates) {
            const auto candidate = *executable_dir / relative;
            if (std::filesystem::exists(candidate)) {
                return candidate;
            }
        }
    }

    for (const auto& candidate : relative_candidates) {
        if (std::filesystem::exists(candidate)) {
            return candidate;
        }
    }

    return std::nullopt;
}

} // namespace

bool set_window_icon(GLFWwindow* window) {
    if (window == nullptr) {
        return false;
    }

    const auto icon_path = find_app_icon_path();
    if (!icon_path.has_value()) {
        return false;
    }

    int width = 0;
    int height = 0;
    unsigned char* pixels = stbi_load(icon_path->string().c_str(), &width, &height, nullptr, STBI_rgb_alpha);
    if (pixels == nullptr || width <= 0 || height <= 0) {
        stbi_image_free(pixels);
        return false;
    }

    constexpr int kIconSizes[] = {256, 128, 64, 32};
    std::vector<GLFWimage> images;
    std::vector<std::vector<unsigned char>> buffers;
    images.reserve(std::size(kIconSizes));
    buffers.reserve(std::size(kIconSizes));

    for (const int icon_size : kIconSizes) {
        std::vector<unsigned char> resized(static_cast<std::size_t>(icon_size) * static_cast<std::size_t>(icon_size) * 4);
        if (!stbir_resize_uint8_linear(
                pixels,
                width,
                height,
                0,
                resized.data(),
                icon_size,
                icon_size,
                0,
                STBIR_RGBA)) {
            continue;
        }

        buffers.push_back(std::move(resized));
        images.push_back(GLFWimage{
            icon_size,
            icon_size,
            buffers.back().data(),
        });
    }

    stbi_image_free(pixels);

    if (images.empty()) {
        return false;
    }

    glfwSetWindowIcon(window, static_cast<int>(images.size()), images.data());
    return true;
}

} // namespace eboot_diff
