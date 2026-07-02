# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file LICENSE.rst or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "/home/me/Projects/CPP/SELF_Resigner_Linux/build-asan/_deps/portable_file_dialogs-src")
  file(MAKE_DIRECTORY "/home/me/Projects/CPP/SELF_Resigner_Linux/build-asan/_deps/portable_file_dialogs-src")
endif()
file(MAKE_DIRECTORY
  "/home/me/Projects/CPP/SELF_Resigner_Linux/build-asan/_deps/portable_file_dialogs-build"
  "/home/me/Projects/CPP/SELF_Resigner_Linux/build-asan/_deps/portable_file_dialogs-subbuild/portable_file_dialogs-populate-prefix"
  "/home/me/Projects/CPP/SELF_Resigner_Linux/build-asan/_deps/portable_file_dialogs-subbuild/portable_file_dialogs-populate-prefix/tmp"
  "/home/me/Projects/CPP/SELF_Resigner_Linux/build-asan/_deps/portable_file_dialogs-subbuild/portable_file_dialogs-populate-prefix/src/portable_file_dialogs-populate-stamp"
  "/home/me/Projects/CPP/SELF_Resigner_Linux/build-asan/_deps/portable_file_dialogs-subbuild/portable_file_dialogs-populate-prefix/src"
  "/home/me/Projects/CPP/SELF_Resigner_Linux/build-asan/_deps/portable_file_dialogs-subbuild/portable_file_dialogs-populate-prefix/src/portable_file_dialogs-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/me/Projects/CPP/SELF_Resigner_Linux/build-asan/_deps/portable_file_dialogs-subbuild/portable_file_dialogs-populate-prefix/src/portable_file_dialogs-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/me/Projects/CPP/SELF_Resigner_Linux/build-asan/_deps/portable_file_dialogs-subbuild/portable_file_dialogs-populate-prefix/src/portable_file_dialogs-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
