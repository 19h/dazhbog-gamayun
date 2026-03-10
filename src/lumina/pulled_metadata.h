#pragma once

#include "lumina/metadata.h"

#include <cstdint>
#include <string>
#include <vector>

namespace lumina {

struct PullCacheEntry {
    bool have = false;
    FunctionMetadata metadata;
    uint32_t popularity = 0;
    uint32_t len = 0;
    std::string remoteName;
    std::vector<uint8_t> raw;
};

FunctionMetadata parsePulledMetadata(const std::vector<uint8_t>& raw, uint64_t address);
std::string formatPulledMetadataReport(uint64_t address, const PullCacheEntry& cache);

}  // namespace lumina
