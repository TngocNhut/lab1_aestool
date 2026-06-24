#include "aestool/aes_cbc.hpp"
#include "aestool/aes_ctr.hpp"
#include "aestool/encoding.hpp"
#include "aestool/file_utils.hpp"
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

void print_help() {
    std::cout
        << "aestool - Lab 1 Symmetric Encryption Tool using Crypto++\n\n"
        << "Usage:\n"
        << "  aestool --help\n"
        << "  aestool version\n"
        << "  aestool selftest\n"
        << "  aestool keygen --out key.bin --bits 128|192|256\n"
        << "  aestool keyinfo --key key.bin\n"
        << "  aestool encrypt --mode cbc|ctr --key key.bin --in msg.txt --out ct.bin [--iv-hex HEX]\n"
        << "  aestool decrypt --mode cbc|ctr --key key.bin --in ct.bin --meta ct.bin.json --out msg.txt\n\n";
}

std::string get_arg(int argc, char* argv[], const std::string& name) {
    for (int i = 0; i < argc - 1; ++i) {
        if (argv[i] == name) {
            return argv[i + 1];
        }
    }

    return {};
}

int run_selftest() {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
        rng.GenerateBlock(key, key.size());

        std::cout << "[OK] Crypto++ AutoSeededRandomPool works\n";
        std::cout << "[OK] AES block size: " << CryptoPP::AES::BLOCKSIZE << " bytes\n";
        std::cout << "[OK] AES default key length: " << CryptoPP::AES::DEFAULT_KEYLENGTH << " bytes\n";
        std::cout << "[OK] Generated random test key: " << key.size() << " bytes\n";

        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[FAIL] Selftest failed: " << ex.what() << "\n";
        return 1;
    }
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

    const size_t key_bytes = static_cast<size_t>(bits / 8);
    std::vector<uint8_t> key(key_bytes);

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

    if (mode != "cbc" && mode != "ctr") {
        std::cerr << "ERROR: encrypt currently supports --mode cbc|ctr\n";
        return 1;
    }

    if (key_path.empty() || in_path.empty() || out_path.empty()) {
        std::cerr << "ERROR: encrypt requires --mode cbc|ctr --key key.bin --in msg.txt --out ct.bin\n";
        return 1;
    }

    const std::vector<uint8_t> key = aestool::read_binary_file(key_path);
    const std::vector<uint8_t> plaintext = aestool::read_binary_file(in_path);

    std::vector<uint8_t> iv;
    if (!iv_hex.empty()) {
        iv = aestool::from_hex(iv_hex);
    }

    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> used_iv;

    if (mode == "cbc") {
        if (!iv.empty()) {
            std::cerr << "ERROR: this checkpoint auto-generates CBC IV; --iv-hex is only enabled for CTR\n";
            return 1;
        }

        const aestool::CbcEncryptResult result = aestool::aes_cbc_encrypt(plaintext, key);
        ciphertext = result.ciphertext;
        used_iv = result.iv;
    } else {
        const aestool::CtrCryptResult result = aestool::aes_ctr_encrypt(plaintext, key, iv);
        ciphertext = result.output;
        used_iv = result.iv;
    }

    aestool::write_binary_file(out_path, ciphertext);

    const std::string meta_path = out_path + ".json";
    aestool::write_mode_sidecar(meta_path, out_path, mode, used_iv, key.size() * 8);

    std::cout << "[OK] AES-" << mode << " encryption completed\n";
    std::cout << "[OK] Plaintext file: " << in_path << "\n";
    std::cout << "[OK] Ciphertext file: " << out_path << "\n";
    std::cout << "[OK] Sidecar JSON: " << meta_path << "\n";
    std::cout << "[OK] Key size: " << key.size() * 8 << " bits\n";
    std::cout << "[OK] IV: " << aestool::to_hex(used_iv) << "\n";
    std::cout << "[OK] Ciphertext size: " << ciphertext.size() << " bytes\n";

    return 0;
}

int run_decrypt(int argc, char* argv[]) {
    const std::string mode = get_arg(argc, argv, "--mode");
    const std::string key_path = get_arg(argc, argv, "--key");
    const std::string in_path = get_arg(argc, argv, "--in");
    const std::string meta_path = get_arg(argc, argv, "--meta");
    const std::string out_path = get_arg(argc, argv, "--out");

    if (mode != "cbc" && mode != "ctr") {
        std::cerr << "ERROR: decrypt currently supports --mode cbc|ctr\n";
        return 1;
    }

    if (key_path.empty() || in_path.empty() || meta_path.empty() || out_path.empty()) {
        std::cerr << "ERROR: decrypt requires --mode cbc|ctr --key key.bin --in ct.bin --meta ct.bin.json --out msg.txt\n";
        return 1;
    }

    const std::vector<uint8_t> key = aestool::read_binary_file(key_path);
    const std::vector<uint8_t> ciphertext = aestool::read_binary_file(in_path);
    const std::vector<uint8_t> iv = aestool::read_iv_from_sidecar(meta_path, mode);

    std::vector<uint8_t> plaintext;

    if (mode == "cbc") {
        plaintext = aestool::aes_cbc_decrypt(ciphertext, key, iv);
    } else {
        plaintext = aestool::aes_ctr_decrypt(ciphertext, key, iv);
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

        std::cerr << "ERROR: unknown command: " << command << "\n";
        std::cerr << "Run: aestool --help\n";
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << "\n";
        return 1;
    }
}
