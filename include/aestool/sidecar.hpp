#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aestool {

void write_mode_sidecar(
    const std::string& meta_path,
    const std::string& ciphertext_file,
    const std::string& mode,
    const std::vector<uint8_t>& iv,
    size_t key_bits
);

void write_gcm_sidecar(
    const std::string& meta_path,
    const std::string& ciphertext_file,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& tag,
    const std::vector<uint8_t>& aad,
    size_t key_bits
);

std::vector<uint8_t> read_iv_from_sidecar(
    const std::string& meta_path,
    const std::string& expected_mode
);

std::vector<uint8_t> read_tag_from_sidecar(
    const std::string& meta_path,
    const std::string& expected_mode
);

std::vector<uint8_t> read_aad_from_sidecar(
    const std::string& meta_path,
    const std::string& expected_mode
);

void write_cbc_sidecar(
    const std::string& meta_path,
    const std::string& ciphertext_file,
    const std::vector<uint8_t>& iv,
    size_t key_bits
);

} // namespace aestool
