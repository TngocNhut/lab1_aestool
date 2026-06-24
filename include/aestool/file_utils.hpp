#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aestool {

std::vector<uint8_t> read_binary_file(const std::string& path);
void write_binary_file(const std::string& path, const std::vector<uint8_t>& data);
bool file_exists(const std::string& path);
uint64_t file_size(const std::string& path);

} // namespace aestool
