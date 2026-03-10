#pragma once

#include "lumina/protocol.h"

#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace lumina {

extern "C" {
    char* BNGetVersionString(void);
    uint32_t BNGetBuildId(void);
    uint32_t BNGetCurrentCoreABIVersion(void);
    void BNFreeString(char*);
}

inline std::string build_client_key_string()
{
    char* versionString = BNGetVersionString();
    const uint32_t buildId = BNGetBuildId();
    const uint32_t abiVersion = BNGetCurrentCoreABIVersion();

    std::string version = versionString != nullptr ? versionString : "unknown";
    if (versionString != nullptr)
        BNFreeString(versionString);

    return "BINARYNINJA-" + version + "." + std::to_string(buildId) + "-" + std::to_string(abiVersion);
}

inline std::vector<uint8_t> build_client_key_bytes()
{
    const std::string key = build_client_key_string();
    return std::vector<uint8_t>(key.begin(), key.end());
}

inline std::array<uint8_t, 6> build_client_license_id()
{
    // Sentinel read-only license ID for the dazhbog server.
    return {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00};
}

inline HelloRequest build_hello_request(uint32_t protocolVersion = kProtocolVersion)
{
    HelloRequest request;
    request.clientVersion = protocolVersion;
    request.key = build_client_key_bytes();
    request.licenseId = build_client_license_id();
    return request;
}

inline PullMetadataRequest build_pull_request(
    uint32_t flags,
    const std::vector<std::array<uint8_t, kMd5HashSize>>& hashes,
    const std::vector<uint32_t>& keys = {})
{
    PullMetadataRequest request;
    request.flags = flags;
    request.keys = keys;
    request.patternIds.reserve(hashes.size());
    for (const auto& hash : hashes)
        request.patternIds.push_back(PatternId::fromHash(hash));
    return request;
}

}  // namespace lumina
