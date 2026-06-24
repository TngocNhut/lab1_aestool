#include "aestool/aes_cbc.hpp"
#include "aestool/aes_ctr.hpp"
#include "aestool/aes_extra_modes.hpp"
#include "aestool/aes_gcm.hpp"
#include "aestool/benchmark.hpp"
#include "aestool/encoding.hpp"
#include "aestool/file_utils.hpp"
#include "aestool/nonce_registry.hpp"
#include "aestool/sidecar.hpp"

#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>

#include <cstdint>
#include <exception>
#include <iostream>
#include <string>
#include <vector>

namespace {

constexpr size_t ECB_DEFAULT_MAX_BYTES = 16 * 1024;

void print_help() {
    std::cout
        << "aestool - Lab 1 Symmetric Encryption Tool using Crypto++\n\n"
        << "Usage:\n"
        << "  aestool --help\n"
        << "  aestool version\n"
        << "  aestool selftest\n"
        << "  aestool keygen --out key.bin --bits 128|192|256\n"
        << "  aestool keyinfo --key key.bin\n"
        << "  aestool encrypt --mode ecb|cbc|cfb|ofb|ctr|gcm --key key.bin --in msg.txt --out ct.bin [--iv-hex HEX] [--aad-text TEXT] [--allow-ecb]\n"
        << "  aestool decrypt --mode ecb|cbc|cfb|ofb|ctr|gcm --key key.bin --in ct.bin --meta ct.bin.json --out msg.txt\n"
        << "  aestool bench --mode cbc|cfb|ofb|ctr|gcm --key key.bin --out result.csv\n\n";
}

std::string get_arg(int argc, char* argv[], const std::string& name) {
    for (int i = 0; i < argc - 1; ++i) {
        if (argv[i] == name) {
            return argv[i + 1];
        }
    }
    return {};
}

bool has_arg(int argc, char* argv[], const std::string& name) {
    for (int i = 0; i < argc; ++i) {
        if (argv[i] == name) {
            return true;
        }
    }
    return false;
}

bool is_supported_mode(const std::string& mode) {
    return mode == "ecb" || mode == "cbc" || mode == "cfb" ||
           mode == "ofb" || mode == "ctr" || mode == "gcm";
}

std::vector<uint8_t> string_to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

int run_selftest() {
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    std::cout << "[OK] Crypto++ AutoSeededRandomPool works\n";
    std::cout << "[OK] AES block size: " << CryptoPP::AES::BLOCKSIZE << " bytes\n";
    std::cout << "[OK] AES default key length: " << CryptoPP::AES::DEFAULT_KEYLENGTH << " bytes\n";
    std::cout << "[OK] Generated random test key: " << key.size() << " bytes\n";

    return 0;
}

int run_keygen(int argc, char* argv[]) {
    const std::string out_path = get_arg(argc, argv, "--out");
    const std::string bits_str = get_arg(argc, argv, "--bits");

    if (out_path.empty()) {
        std::cerr << "ERROR: keygen requires --out key.bin\n";
        return 1;
    }

    if (bits_str.empty()) {
        std::cerr << "ERROR: keygen requires --bits 128|192|256\n";
        return 1;
    }

    int bits = 0;
    try {
        bits = std::stoi(bits_str);
    } catch (...) {
        std::cerr << "ERROR: invalid --bits value\n";
        return 1;
    }

    if (bits != 128 && bits != 192 && bits != 256) {
        std::cerr << "ERROR: AES key size must be 128, 192, or 256 bits\n";
        return 1;
    }

    std::vector<uint8_t> key(static_cast<size_t>(bits / 8));

    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(key.data(), key.size());

    aestool::write_binary_file(out_path, key);

    std::cout << "[OK] Generated AES-" << bits << " key\n";
    std::cout << "[OK] Output file: " << out_path << "\n";
    std::cout << "[OK] Key size: " << key.size() << " bytes\n";
    std::cout << "[INFO] Key hex: " << aestool::to_hex(key) << "\n";

    return 0;
}

int run_keyinfo(int argc, char* argv[]) {
    const std::string key_path = get_arg(argc, argv, "--key");

    if (key_path.empty()) {
        std::cerr << "ERROR: keyinfo requires --key key.bin\n";
        return 1;
    }

    const std::vector<uint8_t> key = aestool::read_binary_file(key_path);

    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        std::cerr << "ERROR: invalid AES key length: " << key.size() << " bytes\n";
        std::cerr << "Expected 16, 24, or 32 bytes\n";
        return 1;
    }

    std::cout << "[OK] Key file: " << key_path << "\n";
    std::cout << "[OK] Key size: " << key.size() << " bytes / " << key.size() * 8 << " bits\n";
    std::cout << "[INFO] Key hex: " << aestool::to_hex(key) << "\n";

    return 0;
}

int run_encrypt(int argc, char* argv[]) {
    const std::string mode = get_arg(argc, argv, "--mode");
    const std::string key_path = get_arg(argc, argv, "--key");
    const std::string in_path = get_arg(argc, argv, "--in");
    const std::string out_path = get_arg(argc, argv, "--out");
    const std::string iv_hex = get_arg(argc, argv, "--iv-hex");
    const std::string aad_text = get_arg(argc, argv, "--aad-text");
    const bool allow_ecb = has_arg(argc, argv, "--allow-ecb");

    if (!is_supported_mode(mode)) {
        std::cerr << "ERROR: encrypt supports --mode ecb|cbc|cfb|ofb|ctr|gcm\n";
        return 1;
    }

    if (key_path.empty() || in_path.empty() || out_path.empty()) {
        std::cerr << "ERROR: encrypt requires --mode MODE --key key.bin --in msg.txt --out ct.bin\n";
        return 1;
    }

    const std::vector<uint8_t> key = aestool::read_binary_file(key_path);
    const std::vector<uint8_t> plaintext = aestool::read_binary_file(in_path);

    std::vector<uint8_t> iv;
    if (!iv_hex.empty()) {
        iv = aestool::from_hex(iv_hex);
    }

    const std::vector<uint8_t> aad = string_to_bytes(aad_text);

    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> used_iv;
    std::vector<uint8_t> tag;

    if (mode == "ecb") {
        std::cerr << "WARNING: ECB mode is insecure because identical plaintext blocks produce identical ciphertext blocks.\n";

        if (!iv.empty()) {
            std::cerr << "ERROR: ECB does not use IV\n";
            return 1;
        }

        if (plaintext.size() > ECB_DEFAULT_MAX_BYTES && !allow_ecb) {
            std::cerr << "ERROR: ECB is blocked for files larger than 16 KiB by default. Use --allow-ecb only for controlled lab demonstration.\n";
            return 1;
        }

        ciphertext = aestool::aes_ecb_encrypt(plaintext, key);
    } else if (mode == "cbc") {
        if (!iv.empty()) {
            std::cerr << "ERROR: this checkpoint auto-generates CBC IV; --iv-hex is enabled for CFB/OFB/CTR/GCM\n";
            return 1;
        }

        const aestool::CbcEncryptResult result = aestool::aes_cbc_encrypt(plaintext, key);
        ciphertext = result.ciphertext;
        used_iv = result.iv;
    } else if (mode == "cfb") {
        const aestool::IvModeEncryptResult result = aestool::aes_cfb_encrypt(plaintext, key, iv);
        ciphertext = result.ciphertext;
        used_iv = result.iv;
    } else if (mode == "ofb") {
        const aestool::IvModeEncryptResult result = aestool::aes_ofb_encrypt(plaintext, key, iv);
        ciphertext = result.ciphertext;
        used_iv = result.iv;
    } else if (mode == "ctr") {
        const aestool::CtrCryptResult result = aestool::aes_ctr_encrypt(plaintext, key, iv);
        ciphertext = result.output;
        used_iv = result.iv;
    } else {
        const aestool::GcmEncryptResult result = aestool::aes_gcm_encrypt(plaintext, key, aad, iv);
        ciphertext = result.ciphertext;
        used_iv = result.iv;
        tag = result.tag;
    }

    if (mode == "ctr" || mode == "gcm") {
        const std::string registry_path = "artifacts/windows/nonce_registry.json";
        aestool::check_and_record_nonce_or_throw(registry_path, mode, key, used_iv);
        std::cout << "[OK] Nonce registry updated: " << registry_path << "\n";
    }

    if (mode == "ctr" || mode == "gcm") {
        const std::string registry_path = "artifacts/windows/nonce_registry.json";
        aestool::check_and_record_nonce_or_throw(registry_path, mode, key, used_iv);
        std::cout << "[OK] Nonce registry updated: " << registry_path << "\n";
    }

    aestool::write_binary_file(out_path, ciphertext);

    const std::string meta_path = out_path + ".json";
    if (mode == "gcm") {
        aestool::write_gcm_sidecar(meta_path, out_path, used_iv, tag, aad, key.size() * 8);
    } else {
        aestool::write_mode_sidecar(meta_path, out_path, mode, used_iv, key.size() * 8);
    }

    std::cout << "[OK] AES-" << mode << " encryption completed\n";
    std::cout << "[OK] Plaintext file: " << in_path << "\n";
    std::cout << "[OK] Ciphertext file: " << out_path << "\n";
    std::cout << "[OK] Sidecar JSON: " << meta_path << "\n";
    std::cout << "[OK] Key size: " << key.size() * 8 << " bits\n";

    if (!used_iv.empty()) {
        std::cout << "[OK] IV: " << aestool::to_hex(used_iv) << "\n";
    }

    if (mode == "gcm") {
        std::cout << "[OK] Tag: " << aestool::to_hex(tag) << "\n";
        std::cout << "[OK] AAD hex: " << aestool::to_hex(aad) << "\n";
    }

    std::cout << "[OK] Ciphertext size: " << ciphertext.size() << " bytes\n";

    return 0;
}


int run_bench(int argc, char* argv[]) {
    const std::string mode = get_arg(argc, argv, "--mode");
    const std::string key_path = get_arg(argc, argv, "--key");
    const std::string out_path = get_arg(argc, argv, "--out");

    if (mode.empty() || key_path.empty() || out_path.empty()) {
        std::cerr << "ERROR: bench requires --mode cbc|cfb|ofb|ctr|gcm --key key.bin --out result.csv\n";
        return 1;
    }

    const std::vector<uint8_t> key = aestool::read_binary_file(key_path);

    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        std::cerr << "ERROR: invalid AES key length for benchmark\n";
        return 1;
    }

    aestool::run_benchmark_csv(mode, key, out_path);
    return 0;
}

int run_decrypt(int argc, char* argv[]) {
    const std::string mode = get_arg(argc, argv, "--mode");
    const std::string key_path = get_arg(argc, argv, "--key");
    const std::string in_path = get_arg(argc, argv, "--in");
    const std::string meta_path = get_arg(argc, argv, "--meta");
    const std::string out_path = get_arg(argc, argv, "--out");

    if (!is_supported_mode(mode)) {
        std::cerr << "ERROR: decrypt supports --mode ecb|cbc|cfb|ofb|ctr|gcm\n";
        return 1;
    }

    if (key_path.empty() || in_path.empty() || meta_path.empty() || out_path.empty()) {
        std::cerr << "ERROR: decrypt requires --mode MODE --key key.bin --in ct.bin --meta ct.bin.json --out msg.txt\n";
        return 1;
    }

    const std::vector<uint8_t> key = aestool::read_binary_file(key_path);
    const std::vector<uint8_t> ciphertext = aestool::read_binary_file(in_path);

    std::vector<uint8_t> plaintext;

    if (mode == "ecb") {
        plaintext = aestool::aes_ecb_decrypt(ciphertext, key);
    } else {
        const std::vector<uint8_t> iv = aestool::read_iv_from_sidecar(meta_path, mode);

        if (mode == "cbc") {
            plaintext = aestool::aes_cbc_decrypt(ciphertext, key, iv);
        } else if (mode == "cfb") {
            plaintext = aestool::aes_cfb_decrypt(ciphertext, key, iv);
        } else if (mode == "ofb") {
            plaintext = aestool::aes_ofb_decrypt(ciphertext, key, iv);
        } else if (mode == "ctr") {
            plaintext = aestool::aes_ctr_decrypt(ciphertext, key, iv);
        } else {
            const std::vector<uint8_t> tag = aestool::read_tag_from_sidecar(meta_path, mode);
            const std::vector<uint8_t> aad = aestool::read_aad_from_sidecar(meta_path, mode);
            plaintext = aestool::aes_gcm_decrypt(ciphertext, key, iv, aad, tag);
        }
    }

    aestool::write_binary_file(out_path, plaintext);

    std::cout << "[OK] AES-" << mode << " decryption completed\n";
    std::cout << "[OK] Ciphertext file: " << in_path << "\n";
    std::cout << "[OK] Sidecar JSON: " << meta_path << "\n";
    std::cout << "[OK] Output plaintext: " << out_path << "\n";
    std::cout << "[OK] Plaintext size: " << plaintext.size() << " bytes\n";

    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        if (argc <= 1) {
            print_help();
            return 0;
        }

        const std::string command = argv[1];

        if (command == "--help" || command == "-h") {
            print_help();
            return 0;
        }

        if (command == "version") {
            std::cout << "aestool 1.0.0\n";
            std::cout << "Crypto++ AES block size: " << CryptoPP::AES::BLOCKSIZE << " bytes\n";
            return 0;
        }

        if (command == "selftest") {
            return run_selftest();
        }

        if (command == "keygen") {
            return run_keygen(argc, argv);
        }

        if (command == "keyinfo") {
            return run_keyinfo(argc, argv);
        }

        if (command == "encrypt") {
            return run_encrypt(argc, argv);
        }

        if (command == "decrypt") {
            return run_decrypt(argc, argv);
        }

        if (command == "bench") {
            return run_bench(argc, argv);
        }

        std::cerr << "ERROR: unknown command: " << command << "\n";
        std::cerr << "Run: aestool --help\n";
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << "\n";
        return 1;
    }
}
