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
include CMakeFiles/mt19937.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/mt19937.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/mt19937.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/mt19937.dir/flags.make

CMakeFiles/mt19937.dir/src/tool/scetool_source/mt19937.cpp.o: CMakeFiles/mt19937.dir/flags.make
CMakeFiles/mt19937.dir/src/tool/scetool_source/mt19937.cpp.o: /home/me/Documents/shared/PS3/EBOOTs/resigner_source/src/tool/scetool_source/mt19937.cpp
CMakeFiles/mt19937.dir/src/tool/scetool_source/mt19937.cpp.o: CMakeFiles/mt19937.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/me/Documents/shared/PS3/EBOOTs/resigner_source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/mt19937.dir/src/tool/scetool_source/mt19937.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/mt19937.dir/src/tool/scetool_source/mt19937.cpp.o -MF CMakeFiles/mt19937.dir/src/tool/scetool_source/mt19937.cpp.o.d -o CMakeFiles/mt19937.dir/src/tool/scetool_source/mt19937.cpp.o -c /home/me/Documents/shared/PS3/EBOOTs/resigner_source/src/tool/scetool_source/mt19937.cpp

CMakeFiles/mt19937.dir/src/tool/scetool_source/mt19937.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/mt19937.dir/src/tool/scetool_source/mt19937.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/me/Documents/shared/PS3/EBOOTs/resigner_source/src/tool/scetool_source/mt19937.cpp > CMakeFiles/mt19937.dir/src/tool/scetool_source/mt19937.cpp.i

CMakeFiles/mt19937.dir/src/tool/scetool_source/mt19937.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/mt19937.dir/src/tool/scetool_source/mt19937.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/me/Documents/shared/PS3/EBOOTs/resigner_source/src/tool/scetool_source/mt19937.cpp -o CMakeFiles/mt19937.dir/src/tool/scetool_source/mt19937.cpp.s

mt19937: CMakeFiles/mt19937.dir/src/tool/scetool_source/mt19937.cpp.o
mt19937: CMakeFiles/mt19937.dir/build.make
.PHONY : mt19937

# Rule to build all files generated by this target.
CMakeFiles/mt19937.dir/build: mt19937
.PHONY : CMakeFiles/mt19937.dir/build

CMakeFiles/mt19937.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/mt19937.dir/cmake_clean.cmake
.PHONY : CMakeFiles/mt19937.dir/clean

CMakeFiles/mt19937.dir/depend:
	cd /home/me/Documents/shared/PS3/EBOOTs/resigner_source/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/me/Documents/shared/PS3/EBOOTs/resigner_source /home/me/Documents/shared/PS3/EBOOTs/resigner_source /home/me/Documents/shared/PS3/EBOOTs/resigner_source/build /home/me/Documents/shared/PS3/EBOOTs/resigner_source/build /home/me/Documents/shared/PS3/EBOOTs/resigner_source/build/CMakeFiles/mt19937.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/mt19937.dir/depend

