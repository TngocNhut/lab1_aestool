#include "aestool/benchmark.hpp"

#include "aestool/aes_cbc.hpp"
#include "aestool/aes_ctr.hpp"
#include "aestool/aes_extra_modes.hpp"
#include "aestool/aes_gcm.hpp"

#include <cryptopp/osrng.h>

#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace aestool {

namespace {

bool is_bench_mode_supported(const std::string& mode) {
    return mode == "cbc" || mode == "cfb" || mode == "ofb" ||
           mode == "ctr" || mode == "gcm";
}

std::vector<uint8_t> random_bytes(size_t n) {
    std::vector<uint8_t> data(n);
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(data.data(), data.size());
    return data;
}

void encrypt_once_for_bench(
    const std::string& mode,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& plaintext
) {
    if (mode == "cbc") {
        volatile auto result = aes_cbc_encrypt(plaintext, key);
        (void)result;
    } else if (mode == "cfb") {
        volatile auto result = aes_cfb_encrypt(plaintext, key, {});
        (void)result;
    } else if (mode == "ofb") {
        volatile auto result = aes_ofb_encrypt(plaintext, key, {});
        (void)result;
    } else if (mode == "ctr") {
        volatile auto result = aes_ctr_encrypt(plaintext, key, {});
        (void)result;
    } else if (mode == "gcm") {
        const std::vector<uint8_t> aad = {'l', 'a', 'b', '1'};
        volatile auto result = aes_gcm_encrypt(plaintext, key, aad, {});
        (void)result;
    } else {
        throw std::runtime_error("unsupported benchmark mode: " + mode);
    }
}

} // namespace

void run_benchmark_csv(
    const std::string& mode,
    const std::vector<uint8_t>& key,
    const std::string& out_csv
) {
    if (!is_bench_mode_supported(mode)) {
        throw std::runtime_error("bench supports only cbc|cfb|ofb|ctr|gcm");
    }

    const std::vector<size_t> sizes = {
        1024,
        4096,
        16384,
        262144,
        1048576,
        8388608
    };

    std::ofstream out(out_csv);
    if (!out) {
        throw std::runtime_error("cannot open benchmark CSV for writing: " + out_csv);
    }

    out << "mode,size_bytes,iterations,total_ms,avg_ms,throughput_mib_s\n";

    std::cout << "[INFO] Benchmark mode: " << mode << "\n";
    std::cout << "[INFO] Output CSV: " << out_csv << "\n";

    for (size_t size : sizes) {
        const std::vector<uint8_t> plaintext = random_bytes(size);

        size_t iterations = 1000;
        if (size >= 262144) {
            iterations = 200;
        }
        if (size >= 1048576) {
            iterations = 50;
        }
        if (size >= 8388608) {
            iterations = 10;
        }

        for (size_t i = 0; i < 10; ++i) {
            encrypt_once_for_bench(mode, key, plaintext);
        }

        const auto start = std::chrono::steady_clock::now();

        for (size_t i = 0; i < iterations; ++i) {
            encrypt_once_for_bench(mode, key, plaintext);
        }

        const auto end = std::chrono::steady_clock::now();

        const double total_ms =
            std::chrono::duration<double, std::milli>(end - start).count();

        const double avg_ms = total_ms / static_cast<double>(iterations);
        const double total_mib =
            (static_cast<double>(size) * static_cast<double>(iterations)) /
            (1024.0 * 1024.0);
        const double throughput_mib_s = total_mib / (total_ms / 1000.0);

        out << mode << ","
            << size << ","
            << iterations << ","
            << std::fixed << std::setprecision(6)
            << total_ms << ","
            << avg_ms << ","
            << throughput_mib_s << "\n";

        std::cout << "[OK] size=" << size
                  << " bytes, iterations=" << iterations
                  << ", avg_ms=" << avg_ms
                  << ", throughput=" << throughput_mib_s
                  << " MiB/s\n";
    }

    std::cout << "[OK] Benchmark completed\n";
}

} // namespace aestool
