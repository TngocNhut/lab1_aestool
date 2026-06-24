#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aestool {

std::string to_hex(const std::vector<uint8_t>& data);
std::vector<uint8_t> from_hex(const std::string& hex);

} // namespace aestool
