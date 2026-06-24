#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aestool {

void write_cbc_sidecar(
    const std::string& meta_path,
    const std::string& ciphertext_file,
    const std::vector<uint8_t>& iv,
    size_t key_bits
);

std::vector<uint8_t> read_iv_from_sidecar(const std::string& meta_path);

} // namespace aestool
