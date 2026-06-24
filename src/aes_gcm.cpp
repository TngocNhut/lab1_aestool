#include "aestool/aes_gcm.hpp"
#include "aestool/aes_cbc.hpp"

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>

#include <stdexcept>
#include <string>

namespace aestool {

namespace {
constexpr size_t GCM_IV_SIZE = 12;
constexpr size_t GCM_TAG_SIZE = 16;
}

void validate_aes_gcm_iv_or_throw(const std::vector<uint8_t>& iv) {
    if (iv.size() != GCM_IV_SIZE) {
        throw std::runtime_error("invalid AES-GCM IV length: expected 12 bytes");
    }
}

void validate_aes_gcm_tag_or_throw(const std::vector<uint8_t>& tag) {
    if (tag.size() != GCM_TAG_SIZE) {
        throw std::runtime_error("invalid AES-GCM tag length: expected 16 bytes");
    }
}

GcmEncryptResult aes_gcm_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& optional_iv
) {
    validate_aes_key_or_throw(key);

    GcmEncryptResult result;

    if (optional_iv.empty()) {
        result.iv.resize(GCM_IV_SIZE);
        CryptoPP::AutoSeededRandomPool rng;
        rng.GenerateBlock(result.iv.data(), result.iv.size());
    } else {
        result.iv = optional_iv;
        validate_aes_gcm_iv_or_throw(result.iv);
    }

    CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), result.iv.data(), result.iv.size());

    std::string cipher_and_tag;

    CryptoPP::AuthenticatedEncryptionFilter ef(
        enc,
        new CryptoPP::StringSink(cipher_and_tag),
        false,
        GCM_TAG_SIZE
    );

    if (!aad.empty()) {
        ef.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
    }
    ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);

    if (!plaintext.empty()) {
        ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, plaintext.data(), plaintext.size());
    }
    ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

    if (cipher_and_tag.size() < GCM_TAG_SIZE) {
        throw std::runtime_error("GCM internal error: output shorter than tag");
    }

    const size_t cipher_size = cipher_and_tag.size() - GCM_TAG_SIZE;

    result.ciphertext.assign(
        cipher_and_tag.begin(),
        cipher_and_tag.begin() + static_cast<std::ptrdiff_t>(cipher_size)
    );

    result.tag.assign(
        cipher_and_tag.begin() + static_cast<std::ptrdiff_t>(cipher_size),
        cipher_and_tag.end()
    );

    return result;
}

std::vector<uint8_t> aes_gcm_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& tag
) {
    validate_aes_key_or_throw(key);
    validate_aes_gcm_iv_or_throw(iv);
    validate_aes_gcm_tag_or_throw(tag);

    CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    std::string recovered;

    CryptoPP::AuthenticatedDecryptionFilter df(
        dec,
        new CryptoPP::StringSink(recovered),
        CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
        tag.size()
    );

    if (!aad.empty()) {
        df.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
    }
    df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);

    if (!ciphertext.empty()) {
        df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, ciphertext.data(), ciphertext.size());
    }

    if (!tag.empty()) {
        df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, tag.data(), tag.size());
    }

    df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

    return std::vector<uint8_t>(recovered.begin(), recovered.end());
}

} // namespace aestool
