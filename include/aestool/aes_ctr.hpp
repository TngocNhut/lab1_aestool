#pragma once

#include <cstdint>
#include <vector>

namespace aestool {

struct CtrCryptResult {
    std::vector<uint8_t> output;
    std::vector<uint8_t> iv;
};

CtrCryptResult aes_ctr_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& optional_iv
);

std::vector<uint8_t> aes_ctr_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv
);

void validate_aes_ctr_iv_or_throw(const std::vector<uint8_t>& iv);

} // namespace aestool
