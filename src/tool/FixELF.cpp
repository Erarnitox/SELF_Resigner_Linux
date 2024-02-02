#include "FixELF.hpp"
#include <filesystem>

namespace fs = std::filesystem;

void fix_elf(const std::string& file, const std::string& elf_sdk) {
    using byte = unsigned char;

    char sdk_int = std::stoi(elf_sdk, nullptr, 16);
    byte foundValue = 0;
    std::vector<byte> fileContent;
    std::vector<byte> pattern { 0x24, 0x13, 0xbc, 0xc5, 0xf6, 0x00, 0x33, 0x00, 0x00, 0x00 };

    // Open file for reading
    fs::path filePath(file);

    if (fs::exists(filePath) && fs::is_regular_file(filePath)) {
        std::ifstream inputFileStream(filePath, std::ios::binary);

        if (inputFileStream.is_open()) {
            // Read file content into a vector
            fileContent.reserve(fs::file_size(filePath));
            fileContent.assign(std::istreambuf_iterator<char>(inputFileStream), std::istreambuf_iterator<char>());

            // Find the pattern in the file content
            auto it = std::search(fileContent.begin(), fileContent.end(), std::begin(pattern), std::end(pattern));

            // If the pattern is found, update foundValue
            if (it != fileContent.end()) {
                foundValue = *(it + pattern.size());
            }

            std::cout << "Found Value: " << std::hex << foundValue << std::endl;

            // Close the file
            inputFileStream.close();

            // Check a condition based on the found value
            if (foundValue > 50) {
                // Open file for writing
                std::fstream fileStream(filePath, std::ios::binary | std::ios::in | std::ios::out );

                if (fileStream.is_open()) {
                    // Set the write position in the file
                    fileStream.seekp(std::distance(fileContent.begin(), it + 10));

                    // Write a value to the file
                    fileStream.write(&sdk_int, 1);

                    // Close the file
                    fileStream.close();
                }
            }
        }
    }
}