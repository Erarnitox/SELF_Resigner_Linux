cmake_minimum_required(VERSION 3.25)

project(ps3_tools VERSION 0.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_TESTING "Build unit tests" ON)

if(BUILD_TESTING)
    include(CTest)
endif()

find_package(ZLIB REQUIRED)
find_package(OpenGL REQUIRED)

add_library(aes OBJECT src/tool/scetool_source/aes.c)
add_library(aes_omac OBJECT src/tool/scetool_source/aes_omac.cpp)
add_library(bn OBJECT src/tool/scetool_source/bn.cpp)
add_library(ec OBJECT src/tool/scetool_source/ec.cpp)
add_library(ecdsa OBJECT src/tool/scetool_source/ecdsa.cpp)
add_library(getopt OBJECT src/tool/scetool_source/getopt.c)
add_library(keys OBJECT src/tool/scetool_source/keys.cpp)
add_library(list OBJECT src/tool/scetool_source/list.cpp)
add_library(mt19937 OBJECT src/tool/scetool_source/mt19937.cpp)
add_library(np OBJECT src/tool/scetool_source/np.cpp)
add_library(rvk OBJECT src/tool/scetool_source/rvk.cpp)
add_library(sce OBJECT src/tool/scetool_source/sce.cpp)
target_link_libraries(sce PRIVATE ZLIB::ZLIB)
add_library(self OBJECT src/tool/scetool_source/self.cpp)
add_library(sha1 OBJECT src/tool/scetool_source/sha1.c)
add_library(tables OBJECT src/tool/scetool_source/tables.cpp)
add_library(util OBJECT src/tool/scetool_source/util.cpp)
target_link_libraries(util PRIVATE ZLIB::ZLIB)
add_library(spp OBJECT src/tool/scetool_source/spp.cpp)
add_library(frontend OBJECT src/tool/scetool_source/frontend.cpp)

add_library(ps3 STATIC
    src/ps3/elf/patcher.cpp
    src/ps3/elf/image.cpp
    src/ps3/fself/builder.cpp
    src/ps3/fself/extractor.cpp
    src/ps3/np/klicense_bruteforce.cpp
)
target_include_directories(ps3 PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(ps3 PUBLIC ZLIB::ZLIB)

add_library(scetool STATIC
    src/tool/scetool_source/scetool.cpp
    src/tool/scetool_source/scetool_api.cpp
)
target_link_libraries(scetool PRIVATE ZLIB::ZLIB)
target_link_libraries(scetool PRIVATE
    aes aes_omac bn ec ecdsa frontend getopt keys
    list mt19937 np rvk sce self sha1 tables util spp
)
target_include_directories(scetool PUBLIC ${CMAKE_SOURCE_DIR}/src)

add_library(resigner_core STATIC
    src/resigner/settings.cpp
    src/resigner/sce_operations.cpp
)
target_include_directories(resigner_core PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(resigner_core PUBLIC scetool ps3)

add_library(resigner_lib STATIC
    src/resigner/console.cpp
    src/resigner/filesystem.cpp
    src/resigner/klicense_service.cpp
    src/resigner/eboot_service.cpp
    src/resigner/self_service.cpp
    src/resigner/menu.cpp
    src/resigner/application.cpp
)
target_include_directories(resigner_lib PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(resigner_lib PUBLIC resigner_core)

add_executable(resigner src/resigner.cpp)
target_link_libraries(resigner PRIVATE resigner_lib)

add_custom_target(resigner_data ALL
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/res/data
        ${CMAKE_BINARY_DIR}/bin/data
    COMMAND ${CMAKE_COMMAND} -E make_directory
        ${CMAKE_BINARY_DIR}/bin/data/icons
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/res/icons/app_icon.png
        ${CMAKE_BINARY_DIR}/bin/data/icons/app_icon.png
    COMMENT "Staging runtime data/ assets"
)

set(EBOOT_DIFF_ICON_PATH "${CMAKE_BINARY_DIR}/bin/data/icons/app_icon.png")
configure_file(
    ${CMAKE_SOURCE_DIR}/res/eboot_diff.desktop.in
    ${CMAKE_BINARY_DIR}/bin/eboot_diff.desktop
    @ONLY
)
add_dependencies(resigner resigner_data)

set_target_properties(resigner scetool ps3 resigner_core resigner_lib
    PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON
)
set_target_properties(resigner PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# --- eboot_diff ---
if(UNIX AND NOT APPLE)
    set(GLFW_BUILD_WAYLAND OFF CACHE BOOL "Use X11 only; avoids wayland-scanner in CI" FORCE)
endif()
include(${CMAKE_SOURCE_DIR}/cmake/Dependencies.cmake)

add_library(eboot_diff_lib STATIC
    src/eboot_diff/domain/types.cpp
    src/eboot_diff/domain/project.cpp
    src/eboot_diff/util/logger.cpp
    src/eboot_diff/util/app_paths.cpp
    src/eboot_diff/util/window_icon.cpp
    src/eboot_diff/services/eboot_loader.cpp
    src/eboot_diff/services/address_index.cpp
    src/eboot_diff/services/disassembler.cpp
    src/eboot_diff/services/diff_engine.cpp
    src/eboot_diff/services/patch_service.cpp
    src/eboot_diff/services/assembler.cpp
    src/eboot_diff/services/export_service.cpp
    src/eboot_diff/services/diff_controller.cpp
    src/eboot_diff/services/project_service.cpp
    src/eboot_diff/ui/file_dialogs.cpp
    src/eboot_diff/ui/imgui_theme.cpp
    src/eboot_diff/ui/diff_pane.cpp
    src/eboot_diff/ui/main_window.cpp
    src/eboot_diff/application.cpp
)
target_include_directories(eboot_diff_lib PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/eboot_diff
)
target_link_libraries(eboot_diff_lib PUBLIC
    resigner_core
    fmt::fmt
    nlohmann_json::nlohmann_json
    stb_lib
    capstone
    keystone
    imgui_lib
    portable_file_dialogs_lib
    OpenGL::GL
)

add_executable(eboot_diff src/eboot_diff/main.cpp)
target_link_libraries(eboot_diff PRIVATE eboot_diff_lib)
set_target_properties(eboot_diff PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
add_dependencies(eboot_diff resigner_data)

if(BUILD_TESTING)
    add_executable(eboot_diff_tests
        tests/eboot_diff/diff_engine_test.cpp
        tests/eboot_diff/address_index_test.cpp
        tests/eboot_diff/disasm_real_test.cpp
        tests/eboot_diff/elf_image_test.cpp
        tests/eboot_diff/disasm_test.cpp
        tests/eboot_diff/asm_roundtrip_test.cpp
        tests/eboot_diff/patch_service_test.cpp
        tests/eboot_diff/project_service_test.cpp
    )
    target_link_libraries(eboot_diff_tests PRIVATE eboot_diff_lib Catch2::Catch2WithMain)
    target_include_directories(eboot_diff_tests PRIVATE ${CMAKE_SOURCE_DIR}/tests/eboot_diff)
    set_target_properties(eboot_diff_tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

    include(${Catch2_SOURCE_DIR}/extras/Catch.cmake)
    catch_discover_tests(eboot_diff_tests)

    add_executable(eboot_profile tests/eboot_diff/profile_load.cpp)
    target_link_libraries(eboot_profile PRIVATE eboot_diff_lib)
    target_include_directories(eboot_profile PRIVATE ${CMAKE_SOURCE_DIR}/tests/eboot_diff)
    set_target_properties(eboot_profile PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    add_dependencies(eboot_profile resigner_data)
endif()

include(${CMAKE_SOURCE_DIR}/cmake/Install.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/CPack.cmake)
