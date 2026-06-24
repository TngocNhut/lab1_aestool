#include "aestool/encoding.hpp"

#include <cctype>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace aestool {

std::string to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (uint8_t byte : data) {
        oss << std::setw(2) << static_cast<int>(byte);
    }

    return oss.str();
}

static uint8_t hex_value(char c) {
    const unsigned char uc = static_cast<unsigned char>(c);

    if (uc >= '0' && uc <= '9') {
        return static_cast<uint8_t>(uc - '0');
    }

    if (uc >= 'a' && uc <= 'f') {
        return static_cast<uint8_t>(uc - 'a' + 10);
    }

    if (uc >= 'A' && uc <= 'F') {
        return static_cast<uint8_t>(uc - 'A' + 10);
    }

    throw std::runtime_error("invalid hex character");
}

std::vector<uint8_t> from_hex(const std::string& hex) {
    std::string cleaned;
    cleaned.reserve(hex.size());

    for (char c : hex) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            cleaned.push_back(c);
        }
    }

    if (cleaned.size() % 2 != 0) {
        throw std::runtime_error("hex string length must be even");
    }

    std::vector<uint8_t> out;
    out.reserve(cleaned.size() / 2);

    for (size_t i = 0; i < cleaned.size(); i += 2) {
        const uint8_t hi = hex_value(cleaned[i]);
        const uint8_t lo = hex_value(cleaned[i + 1]);
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }

    return out;
}

} // namespace aestool
