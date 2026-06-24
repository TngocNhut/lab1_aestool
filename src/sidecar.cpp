#include "aestool/sidecar.hpp"

#include "aestool/encoding.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <stdexcept>

namespace aestool {

namespace {

nlohmann::json read_json_or_throw(const std::string& meta_path) {
    std::ifstream in(meta_path);
    if (!in) {
        throw std::runtime_error("cannot open sidecar JSON: " + meta_path);
    }

    nlohmann::json j;
    in >> j;
    return j;
}

void validate_mode_or_throw(const nlohmann::json& j, const std::string& expected_mode) {
    if (!j.contains("mode") || j["mode"] != expected_mode) {
        throw std::runtime_error("sidecar JSON mode mismatch");
    }
}

} // namespace

void write_mode_sidecar(
    const std::string& meta_path,
    const std::string& ciphertext_file,
    const std::string& mode,
    const std::vector<uint8_t>& iv,
    size_t key_bits
) {
    nlohmann::json j;
    j["created_by"] = "aestool";
    j["version"] = "1.0";
    j["alg"] = "AES-" + std::to_string(key_bits) + "-" + mode;
    j["mode"] = mode;
    j["key_bits"] = key_bits;
    j["iv"] = to_hex(iv);
    j["ciphertext_file"] = ciphertext_file;
    j["encoding"] = "raw";

    if (mode == "cbc") {
        j["padding"] = "PKCS#7";
    } else {
        j["padding"] = "none";
    }

    std::ofstream out(meta_path);
    if (!out) {
        throw std::runtime_error("cannot write sidecar JSON: " + meta_path);
    }

    out << j.dump(4) << "\n";
}

void write_gcm_sidecar(
    const std::string& meta_path,
    const std::string& ciphertext_file,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& tag,
    const std::vector<uint8_t>& aad,
    size_t key_bits
) {
    nlohmann::json j;
    j["created_by"] = "aestool";
    j["version"] = "1.0";
    j["alg"] = "AES-" + std::to_string(key_bits) + "-GCM";
    j["mode"] = "gcm";
    j["key_bits"] = key_bits;
    j["iv"] = to_hex(iv);
    j["tag"] = to_hex(tag);
    j["aad"] = to_hex(aad);
    j["ciphertext_file"] = ciphertext_file;
    j["encoding"] = "raw";
    j["padding"] = "none";
    j["aead"] = true;

    std::ofstream out(meta_path);
    if (!out) {
        throw std::runtime_error("cannot write sidecar JSON: " + meta_path);
    }

    out << j.dump(4) << "\n";
}

std::vector<uint8_t> read_iv_from_sidecar(
    const std::string& meta_path,
    const std::string& expected_mode
) {
    const nlohmann::json j = read_json_or_throw(meta_path);
    validate_mode_or_throw(j, expected_mode);

    if (!j.contains("iv") || !j["iv"].is_string()) {
        throw std::runtime_error("sidecar JSON missing IV");
    }

    return from_hex(j["iv"].get<std::string>());
}

std::vector<uint8_t> read_tag_from_sidecar(
    const std::string& meta_path,
    const std::string& expected_mode
) {
    const nlohmann::json j = read_json_or_throw(meta_path);
    validate_mode_or_throw(j, expected_mode);

    if (!j.contains("tag") || !j["tag"].is_string()) {
        throw std::runtime_error("sidecar JSON missing authentication tag");
    }

    return from_hex(j["tag"].get<std::string>());
}

std::vector<uint8_t> read_aad_from_sidecar(
    const std::string& meta_path,
    const std::string& expected_mode
) {
    const nlohmann::json j = read_json_or_throw(meta_path);
    validate_mode_or_throw(j, expected_mode);

    if (!j.contains("aad")) {
        return {};
    }

    if (!j["aad"].is_string()) {
        throw std::runtime_error("sidecar JSON AAD must be hex string");
    }

    const std::string aad_hex = j["aad"].get<std::string>();
    if (aad_hex.empty()) {
        return {};
    }

    return from_hex(aad_hex);
}

void write_cbc_sidecar(
    const std::string& meta_path,
    const std::string& ciphertext_file,
    const std::vector<uint8_t>& iv,
    size_t key_bits
) {
    write_mode_sidecar(meta_path, ciphertext_file, "cbc", iv, key_bits);
}

} // namespace aestool
