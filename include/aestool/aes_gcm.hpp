#pragma once

#include <cstdint>
#include <vector>

namespace aestool {

struct GcmEncryptResult {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> tag;
};

GcmEncryptResult aes_gcm_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& optional_iv
);

std::vector<uint8_t> aes_gcm_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& tag
);

void validate_aes_gcm_iv_or_throw(const std::vector<uint8_t>& iv);
void validate_aes_gcm_tag_or_throw(const std::vector<uint8_t>& tag);

} // namespace aestool
