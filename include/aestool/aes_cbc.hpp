#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aestool {

struct CbcEncryptResult {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> iv;
};

CbcEncryptResult aes_cbc_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key
);

std::vector<uint8_t> aes_cbc_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv
);

void validate_aes_key_or_throw(const std::vector<uint8_t>& key);
void validate_aes_iv_or_throw(const std::vector<uint8_t>& iv);

} // namespace aestool
