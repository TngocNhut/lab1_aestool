#include "aestool/aes_ctr.hpp"
#include "aestool/aes_cbc.hpp"

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

#include <stdexcept>
#include <string>

namespace aestool {

void validate_aes_ctr_iv_or_throw(const std::vector<uint8_t>& iv) {
    if (iv.size() != CryptoPP::AES::BLOCKSIZE) {
        throw std::runtime_error("invalid AES-CTR IV length: expected 16 bytes");
    }
}

CtrCryptResult aes_ctr_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& optional_iv
) {
    validate_aes_key_or_throw(key);

    CtrCryptResult result;

    if (optional_iv.empty()) {
        result.iv.resize(CryptoPP::AES::BLOCKSIZE);
        CryptoPP::AutoSeededRandomPool rng;
        rng.GenerateBlock(result.iv.data(), result.iv.size());
    } else {
        result.iv = optional_iv;
        validate_aes_ctr_iv_or_throw(result.iv);
    }

    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), result.iv.data(), result.iv.size());

    std::string plain_str(
        reinterpret_cast<const char*>(plaintext.data()),
        plaintext.size()
    );

    std::string cipher_str;

    CryptoPP::StringSource ss(
        plain_str,
        true,
        new CryptoPP::StreamTransformationFilter(
            enc,
            new CryptoPP::StringSink(cipher_str),
            CryptoPP::StreamTransformationFilter::NO_PADDING
        )
    );

    result.output.assign(cipher_str.begin(), cipher_str.end());
    return result;
}

std::vector<uint8_t> aes_ctr_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv
) {
    validate_aes_key_or_throw(key);
    validate_aes_ctr_iv_or_throw(iv);

    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    std::string cipher_str(
        reinterpret_cast<const char*>(ciphertext.data()),
        ciphertext.size()
    );

    std::string recovered;

    CryptoPP::StringSource ss(
        cipher_str,
        true,
        new CryptoPP::StreamTransformationFilter(
            dec,
            new CryptoPP::StringSink(recovered),
            CryptoPP::StreamTransformationFilter::NO_PADDING
        )
    );

    return std::vector<uint8_t>(recovered.begin(), recovered.end());
}

} // namespace aestool
