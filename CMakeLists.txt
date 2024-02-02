cmake_minimum_required(VERSION 3.25)

project(ps3_tools)

add_executable(resigner
   src/resigner.cpp
)

set_target_properties(resigner
  PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_library(aes OBJECT
    src/tool/scetool_source/aes.c
)

add_library(aes_omac OBJECT
    src/tool/scetool_source/aes_omac.cpp
)

add_library(bn OBJECT
    src/tool/scetool_source/bn.cpp
)

add_library(ec OBJECT
    src/tool/scetool_source/ec.cpp
)

add_library(ecdsa OBJECT
    src/tool/scetool_source/ecdsa.cpp
)

add_library(getopt OBJECT
    src/tool/scetool_source/getopt.c
)

add_library(keys OBJECT
    src/tool/scetool_source/keys.cpp
)

add_library(list OBJECT
    src/tool/scetool_source/list.cpp
)

add_library(mt19937 OBJECT
    src/tool/scetool_source/mt19937.cpp
)

add_library(np OBJECT
    src/tool/scetool_source/np.cpp
)

add_library(rvk OBJECT
    src/tool/scetool_source/rvk.cpp
)

add_library(sce OBJECT
    src/tool/scetool_source/sce.cpp
)

add_library(self OBJECT
    src/tool/scetool_source/self.cpp
)

add_library(sha1 OBJECT
    src/tool/scetool_source/sha1.c
)

add_library(tables OBJECT
    src/tool/scetool_source/tables.cpp
)

add_library(util OBJECT
    src/tool/scetool_source/util.cpp
)

add_library(spp OBJECT
    src/tool/scetool_source/spp.cpp
)

add_library(frontend OBJECT
    src/tool/scetool_source/frontend.cpp
)

add_library(fix_elf STATIC
    src/tool/FixELF.cpp
)

target_link_libraries(resigner PRIVATE
    fix_elf
)

add_executable(scetool
    src/tool/scetool_source/main.cpp
)

set_target_properties(scetool
  PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/tool"
)

find_package(ZLIB REQUIRED)
target_link_libraries(scetool PRIVATE ZLIB::ZLIB)

target_link_libraries(scetool PRIVATE 
    aes aes_omac bn ec ecdsa frontend getopt keys
    list mt19937 np rvk sce self sha1 tables util
    spp
)

add_custom_command(TARGET scetool PRE_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_SOURCE_DIR}/res/data ${CMAKE_BINARY_DIR}/bin/data)
