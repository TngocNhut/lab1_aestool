#include "aestool/sidecar.hpp"

#include "aestool/encoding.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <stdexcept>

namespace aestool {

void write_cbc_sidecar(
    const std::string& meta_path,
    const std::string& ciphertext_file,
    const std::vector<uint8_t>& iv,
    size_t key_bits
) {
    nlohmann::json j;
    j["created_by"] = "aestool";
    j["version"] = "1.0";
    j["alg"] = "AES-" + std::to_string(key_bits) + "-CBC";
    j["mode"] = "cbc";
    j["key_bits"] = key_bits;
    j["iv"] = to_hex(iv);
    j["ciphertext_file"] = ciphertext_file;
    j["encoding"] = "raw";
    j["padding"] = "PKCS#7";

    std::ofstream out(meta_path);
    if (!out) {
        throw std::runtime_error("cannot write sidecar JSON: " + meta_path);
    }

    out << j.dump(4) << "\n";
}

std::vector<uint8_t> read_iv_from_sidecar(const std::string& meta_path) {
    std::ifstream in(meta_path);
    if (!in) {
        throw std::runtime_error("cannot open sidecar JSON: " + meta_path);
    }

    nlohmann::json j;
    in >> j;

    if (!j.contains("mode") || j["mode"] != "cbc") {
        throw std::runtime_error("sidecar JSON is not AES-CBC metadata");
    }

    if (!j.contains("iv") || !j["iv"].is_string()) {
        throw std::runtime_error("sidecar JSON missing IV");
    }

    return from_hex(j["iv"].get<std::string>());
}

} // namespace aestool
