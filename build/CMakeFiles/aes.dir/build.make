# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.28

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/me/Documents/shared/PS3/EBOOTs/resigner_source

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/me/Documents/shared/PS3/EBOOTs/resigner_source/build

# Include any dependencies generated for this target.
include CMakeFiles/aes.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/aes.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/aes.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/aes.dir/flags.make

CMakeFiles/aes.dir/src/tool/scetool_source/aes.c.o: CMakeFiles/aes.dir/flags.make
CMakeFiles/aes.dir/src/tool/scetool_source/aes.c.o: /home/me/Documents/shared/PS3/EBOOTs/resigner_source/src/tool/scetool_source/aes.c
CMakeFiles/aes.dir/src/tool/scetool_source/aes.c.o: CMakeFiles/aes.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/me/Documents/shared/PS3/EBOOTs/resigner_source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/aes.dir/src/tool/scetool_source/aes.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/aes.dir/src/tool/scetool_source/aes.c.o -MF CMakeFiles/aes.dir/src/tool/scetool_source/aes.c.o.d -o CMakeFiles/aes.dir/src/tool/scetool_source/aes.c.o -c /home/me/Documents/shared/PS3/EBOOTs/resigner_source/src/tool/scetool_source/aes.c

CMakeFiles/aes.dir/src/tool/scetool_source/aes.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/aes.dir/src/tool/scetool_source/aes.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/me/Documents/shared/PS3/EBOOTs/resigner_source/src/tool/scetool_source/aes.c > CMakeFiles/aes.dir/src/tool/scetool_source/aes.c.i

CMakeFiles/aes.dir/src/tool/scetool_source/aes.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/aes.dir/src/tool/scetool_source/aes.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/me/Documents/shared/PS3/EBOOTs/resigner_source/src/tool/scetool_source/aes.c -o CMakeFiles/aes.dir/src/tool/scetool_source/aes.c.s

aes: CMakeFiles/aes.dir/src/tool/scetool_source/aes.c.o
aes: CMakeFiles/aes.dir/build.make
.PHONY : aes

# Rule to build all files generated by this target.
CMakeFiles/aes.dir/build: aes
.PHONY : CMakeFiles/aes.dir/build

CMakeFiles/aes.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/aes.dir/cmake_clean.cmake
.PHONY : CMakeFiles/aes.dir/clean

CMakeFiles/aes.dir/depend:
	cd /home/me/Documents/shared/PS3/EBOOTs/resigner_source/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/me/Documents/shared/PS3/EBOOTs/resigner_source /home/me/Documents/shared/PS3/EBOOTs/resigner_source /home/me/Documents/shared/PS3/EBOOTs/resigner_source/build /home/me/Documents/shared/PS3/EBOOTs/resigner_source/build /home/me/Documents/shared/PS3/EBOOTs/resigner_source/build/CMakeFiles/aes.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/aes.dir/depend

