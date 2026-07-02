set(_keystone_vcpkg_root "")
if(VCPKG_INSTALLED_DIR AND VCPKG_TARGET_TRIPLET)
    set(_keystone_vcpkg_root "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
elseif(VCPKG_TARGET_TRIPLET)
    foreach(_candidate
        "${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}"
        "${CMAKE_SOURCE_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}"
    )
        if(EXISTS "${_candidate}/include/keystone/keystone.h")
            set(_keystone_vcpkg_root "${_candidate}")
            break()
        endif()
    endforeach()
endif()

if(_keystone_vcpkg_root AND EXISTS "${_keystone_vcpkg_root}/lib/pkgconfig")
    if(WIN32)
        set(ENV{PKG_CONFIG_PATH} "${_keystone_vcpkg_root}/lib/pkgconfig;$ENV{PKG_CONFIG_PATH}")
    else()
        set(ENV{PKG_CONFIG_PATH} "${_keystone_vcpkg_root}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
    endif()
endif()

if(NOT TARGET keystone)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(KEYSTONE QUIET IMPORTED_TARGET keystone)
    endif()
endif()

if(NOT TARGET keystone AND TARGET PkgConfig::KEYSTONE)
    add_library(keystone ALIAS PkgConfig::KEYSTONE)
endif()

if(NOT TARGET keystone)
    find_package(keystone CONFIG QUIET)
    if(TARGET keystone::keystone)
        add_library(keystone ALIAS keystone::keystone)
    endif()
endif()

if(NOT TARGET keystone)
    set(_keystone_include_hints)
    set(_keystone_library_hints)
    if(_keystone_vcpkg_root)
        list(APPEND _keystone_include_hints "${_keystone_vcpkg_root}/include")
        list(APPEND _keystone_library_hints
            "${_keystone_vcpkg_root}/lib"
            "${_keystone_vcpkg_root}/debug/lib"
        )
    endif()

    find_path(KEYSTONE_INCLUDE_DIR NAMES keystone/keystone.h
        HINTS ${_keystone_include_hints}
    )
    find_library(KEYSTONE_LIBRARY NAMES keystone libkeystone
        HINTS ${_keystone_library_hints}
    )

    if(NOT KEYSTONE_LIBRARY AND _keystone_vcpkg_root)
        file(GLOB _keystone_lib_candidates
            "${_keystone_vcpkg_root}/lib/keystone.lib"
            "${_keystone_vcpkg_root}/lib/libkeystone.a"
            "${_keystone_vcpkg_root}/lib/keystone.dll.lib"
        )
        if(_keystone_lib_candidates)
            list(GET _keystone_lib_candidates 0 KEYSTONE_LIBRARY)
        endif()
    endif()

    if(NOT KEYSTONE_INCLUDE_DIR AND _keystone_vcpkg_root)
        if(EXISTS "${_keystone_vcpkg_root}/include/keystone/keystone.h")
            set(KEYSTONE_INCLUDE_DIR "${_keystone_vcpkg_root}/include")
        endif()
    endif()

    if(KEYSTONE_INCLUDE_DIR AND KEYSTONE_LIBRARY)
        add_library(keystone UNKNOWN IMPORTED)
        set_target_properties(keystone PROPERTIES
            IMPORTED_LOCATION "${KEYSTONE_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${KEYSTONE_INCLUDE_DIR}"
        )
    endif()
endif()

if(NOT TARGET keystone)
    message(FATAL_ERROR
        "Keystone is required. Install libkeystone-dev (Linux) or use vcpkg (Windows).\n"
        "  VCPKG_INSTALLED_DIR=${VCPKG_INSTALLED_DIR}\n"
        "  VCPKG_TARGET_TRIPLET=${VCPKG_TARGET_TRIPLET}\n"
        "  _keystone_vcpkg_root=${_keystone_vcpkg_root}\n"
        "  KEYSTONE_INCLUDE_DIR=${KEYSTONE_INCLUDE_DIR}\n"
        "  KEYSTONE_LIBRARY=${KEYSTONE_LIBRARY}"
    )
endif()
