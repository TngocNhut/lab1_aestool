#pragma once

#include <cstdint>
#include <vector>

namespace aestool {

struct IvModeEncryptResult {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> iv;
};

std::vector<uint8_t> aes_ecb_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key
);

std::vector<uint8_t> aes_ecb_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key
);

IvModeEncryptResult aes_cfb_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& optional_iv
);

std::vector<uint8_t> aes_cfb_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv
);

IvModeEncryptResult aes_ofb_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& optional_iv
);

std::vector<uint8_t> aes_ofb_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv
);

void validate_aes_block_iv_or_throw(const std::vector<uint8_t>& iv);

} // namespace aestool
