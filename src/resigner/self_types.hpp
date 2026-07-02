#pragma once

#include <filesystem>
#include <string>

namespace resigner {

struct SelfEntry {
    std::filesystem::path filename;
    std::string short_name;
    std::string suffix;
    std::string elf_extension;
    std::string backup_extension;
};

} // namespace resigner
