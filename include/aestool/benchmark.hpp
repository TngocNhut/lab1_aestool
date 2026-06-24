#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aestool {

void run_benchmark_csv(
    const std::string& mode,
    const std::vector<uint8_t>& key,
    const std::string& out_csv
);

} // namespace aestool
