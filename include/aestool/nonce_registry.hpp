#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aestool {

std::string sha256_hex(const std::vector<uint8_t>& data);

void check_and_record_nonce_or_throw(
    const std::string& registry_path,
    const std::string& mode,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce
);

} // namespace aestool
