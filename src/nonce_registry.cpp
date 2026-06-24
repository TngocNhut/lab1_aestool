#include "aestool/nonce_registry.hpp"

#include "aestool/encoding.hpp"

#include <cryptopp/filters.h>
#include <cryptopp/sha.h>

#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

namespace aestool {

std::string sha256_hex(const std::vector<uint8_t>& data) {
    CryptoPP::SHA256 hash;
    std::string digest;

    CryptoPP::StringSource ss(
        reinterpret_cast<const CryptoPP::byte*>(data.data()),
        data.size(),
        true,
        new CryptoPP::HashFilter(
            hash,
            new CryptoPP::StringSink(digest)
        )
    );

    std::vector<uint8_t> digest_bytes(digest.begin(), digest.end());
    return to_hex(digest_bytes);
}

void check_and_record_nonce_or_throw(
    const std::string& registry_path,
    const std::string& mode,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce
) {
    const std::string key_hash = sha256_hex(key);
    const std::string nonce_hex = to_hex(nonce);

    nlohmann::json registry;

    if (std::filesystem::exists(registry_path)) {
        std::ifstream in(registry_path);
        if (!in) {
            throw std::runtime_error("cannot open nonce registry: " + registry_path);
        }
        in >> registry;
    } else {
        registry = nlohmann::json::object();
        registry["version"] = "1.0";
        registry["entries"] = nlohmann::json::array();
    }

    if (!registry.contains("entries") || !registry["entries"].is_array()) {
        throw std::runtime_error("nonce registry is malformed");
    }

    for (const auto& entry : registry["entries"]) {
        if (!entry.contains("mode") || !entry.contains("key_hash") || !entry.contains("nonce")) {
            continue;
        }

        if (entry["mode"] == mode &&
            entry["key_hash"] == key_hash &&
            entry["nonce"] == nonce_hex) {
            throw std::runtime_error(
                "nonce/IV reuse detected for mode " + mode +
                " with the same key; operation rejected"
            );
        }
    }

    nlohmann::json new_entry;
    new_entry["mode"] = mode;
    new_entry["key_hash"] = key_hash;
    new_entry["nonce"] = nonce_hex;

    registry["entries"].push_back(new_entry);

    std::ofstream out(registry_path);
    if (!out) {
        throw std::runtime_error("cannot write nonce registry: " + registry_path);
    }

    out << registry.dump(4) << "\n";
}

} // namespace aestool
