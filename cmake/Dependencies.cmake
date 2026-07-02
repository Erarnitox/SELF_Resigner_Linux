include(${CMAKE_SOURCE_DIR}/cmake/CPM.cmake)

CPMAddPackage(
    NAME fmt
    GITHUB_REPOSITORY fmtlib/fmt
    GIT_TAG 10.2.1
    OPTIONS "FMT_INSTALL OFF"
)

CPMAddPackage(
    NAME nlohmann_json
    GITHUB_REPOSITORY nlohmann/json
    GIT_TAG v3.11.3
    OPTIONS "JSON_Install OFF"
)

if(BUILD_TESTING)
    CPMAddPackage(
        NAME Catch2
        GITHUB_REPOSITORY catchorg/Catch2
        GIT_TAG v3.5.4
        OPTIONS
            "CATCH_INSTALL_DOCS OFF"
            "CATCH_INSTALL_EXTRAS OFF"
    )
endif()

CPMAddPackage(
    NAME capstone
    GITHUB_REPOSITORY capstone-engine/capstone
    GIT_TAG 5.0.1
    OPTIONS
        "BUILD_SHARED_LIBS OFF"
        "CAPSTONE_BUILD_TESTS OFF"
        "CAPSTONE_BUILD_CSTOOL OFF"
        "CAPSTONE_BUILD_DIET OFF"
        "CAPSTONE_INSTALL OFF"
)

include(${CMAKE_SOURCE_DIR}/cmake/Keystone.cmake)

CPMAddPackage(
    NAME glfw
    GITHUB_REPOSITORY glfw/glfw
    GIT_TAG 3.4
    OPTIONS
        "GLFW_BUILD_EXAMPLES OFF"
        "GLFW_BUILD_TESTS OFF"
        "GLFW_BUILD_DOCS OFF"
        "GLFW_INSTALL OFF"
        "GLFW_BUILD_WAYLAND OFF"
)

CPMAddPackage(
    NAME imgui
    GITHUB_REPOSITORY ocornut/imgui
    GIT_TAG v1.90.8
    DOWNLOAD_ONLY YES
)

if(NOT TARGET imgui_lib)
    add_library(imgui_lib STATIC
        ${imgui_SOURCE_DIR}/imgui.cpp
        ${imgui_SOURCE_DIR}/imgui_draw.cpp
        ${imgui_SOURCE_DIR}/imgui_tables.cpp
        ${imgui_SOURCE_DIR}/imgui_widgets.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
    )
    target_include_directories(imgui_lib PUBLIC
        ${imgui_SOURCE_DIR}
        ${imgui_SOURCE_DIR}/backends
    )
    target_link_libraries(imgui_lib PUBLIC glfw)
    target_compile_definitions(imgui_lib PUBLIC GLFW_INCLUDE_NONE)
    if(MSVC)
        target_compile_options(imgui_lib PRIVATE "/FIwindows.h")
    endif()
endif()

CPMAddPackage(
    NAME portable_file_dialogs
    GITHUB_REPOSITORY samhocevar/portable-file-dialogs
    GIT_TAG 0.1.0
    DOWNLOAD_ONLY YES
)

if(NOT TARGET portable_file_dialogs_lib)
    add_library(portable_file_dialogs_lib INTERFACE)
    target_include_directories(portable_file_dialogs_lib INTERFACE
        ${portable_file_dialogs_SOURCE_DIR}
    )
endif()

if(NOT TARGET stb_lib)
    add_library(stb_lib INTERFACE)
    target_include_directories(stb_lib INTERFACE
        ${CMAKE_SOURCE_DIR}/cmake/third_party/stb
    )
endif()
