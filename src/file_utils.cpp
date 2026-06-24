#include "aestool/file_utils.hpp"

#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace aestool {

std::vector<uint8_t> read_binary_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot open input file: " + path);
    }

    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    if (size < 0) {
        throw std::runtime_error("cannot determine file size: " + path);
    }

    std::vector<uint8_t> data(static_cast<size_t>(size));
    in.seekg(0, std::ios::beg);

    if (!data.empty()) {
        in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!in) {
            throw std::runtime_error("failed while reading file: " + path);
        }
    }

    return data;
}

void write_binary_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("cannot open output file: " + path);
    }

    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!out) {
            throw std::runtime_error("failed while writing file: " + path);
        }
    }
}

bool file_exists(const std::string& path) {
    return std::filesystem::exists(path);
}

uint64_t file_size(const std::string& path) {
    if (!std::filesystem::exists(path)) {
        throw std::runtime_error("file does not exist: " + path);
    }

    return static_cast<uint64_t>(std::filesystem::file_size(path));
}

} // namespace aestool
