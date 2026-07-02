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

if(DEFINED VCPKG_INSTALLED_DIR AND VCPKG_TARGET_TRIPLET)
    set(_vcpkg_triplet_root "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
    if(EXISTS "${_vcpkg_triplet_root}/lib/pkgconfig")
        if(WIN32)
            set(ENV{PKG_CONFIG_PATH} "${_vcpkg_triplet_root}/lib/pkgconfig;$ENV{PKG_CONFIG_PATH}")
        else()
            set(ENV{PKG_CONFIG_PATH} "${_vcpkg_triplet_root}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
        endif()
    endif()
endif()

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(KEYSTONE QUIET IMPORTED_TARGET keystone)
endif()

if(TARGET PkgConfig::KEYSTONE)
    add_library(keystone ALIAS PkgConfig::KEYSTONE)
elseif(TARGET keystone::keystone)
    add_library(keystone ALIAS keystone::keystone)
else()
    find_package(keystone CONFIG QUIET)
    if(TARGET keystone::keystone)
        add_library(keystone ALIAS keystone::keystone)
    else()
        set(_keystone_include_hints)
        set(_keystone_library_hints)
        if(DEFINED _vcpkg_triplet_root)
            list(APPEND _keystone_include_hints "${_vcpkg_triplet_root}/include")
            list(APPEND _keystone_library_hints
                "${_vcpkg_triplet_root}/lib"
                "${_vcpkg_triplet_root}/debug/lib"
            )
        endif()

        find_path(KEYSTONE_INCLUDE_DIR NAMES keystone/keystone.h
            HINTS ${_keystone_include_hints}
        )
        find_library(KEYSTONE_LIBRARY NAMES keystone libkeystone
            HINTS ${_keystone_library_hints}
        )
        if(KEYSTONE_INCLUDE_DIR AND KEYSTONE_LIBRARY)
            add_library(keystone UNKNOWN IMPORTED)
            set_target_properties(keystone PROPERTIES
                IMPORTED_LOCATION "${KEYSTONE_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${KEYSTONE_INCLUDE_DIR}"
            )
        else()
            message(FATAL_ERROR
                "Keystone is required. Install libkeystone-dev (Linux) or use vcpkg (Windows).\n"
                "  KEYSTONE_INCLUDE_DIR=${KEYSTONE_INCLUDE_DIR}\n"
                "  KEYSTONE_LIBRARY=${KEYSTONE_LIBRARY}"
            )
        endif()
    endif()
endif()

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
