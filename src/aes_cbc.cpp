#include "aestool/aes_cbc.hpp"

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

#include <stdexcept>
#include <string>

namespace aestool {

void validate_aes_key_or_throw(const std::vector<uint8_t>& key) {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        throw std::runtime_error(
            "invalid AES key length: expected 16, 24, or 32 bytes"
        );
    }
}

void validate_aes_iv_or_throw(const std::vector<uint8_t>& iv) {
    if (iv.size() != CryptoPP::AES::BLOCKSIZE) {
        throw std::runtime_error("invalid AES-CBC IV length: expected 16 bytes");
    }
}

CbcEncryptResult aes_cbc_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key
) {
    validate_aes_key_or_throw(key);

    CbcEncryptResult result;
    result.iv.resize(CryptoPP::AES::BLOCKSIZE);

    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(result.iv.data(), result.iv.size());

    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
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
            CryptoPP::StreamTransformationFilter::PKCS_PADDING
        )
    );

    result.ciphertext.assign(cipher_str.begin(), cipher_str.end());
    return result;
}

std::vector<uint8_t> aes_cbc_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv
) {
    validate_aes_key_or_throw(key);
    validate_aes_iv_or_throw(iv);

    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
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
            CryptoPP::StreamTransformationFilter::PKCS_PADDING
        )
    );

    return std::vector<uint8_t>(recovered.begin(), recovered.end());
}

} // namespace aestool
