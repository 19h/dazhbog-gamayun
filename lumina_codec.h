#pragma once

#include "lumina_protocol.h"

#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace lumina {

struct EncodedFunction {
    std::string name;
    uint32_t func_len = 0;
    std::vector<uint8_t> func_data;
    std::array<uint8_t, kMd5HashSize> hash{};
    uint64_t address = 0;
};

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
    return {};
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

inline PushMetadataRequest build_push_request(
    uint32_t flags,
    const std::string& idbPath,
    const std::string& filePath,
    const std::array<uint8_t, kMd5HashSize>& md5OfBinary,
    const std::string& hostName,
    const std::vector<EncodedFunction>& funcs)
{
    PushMetadataRequest request;
    request.flags = flags;
    request.idb = idbPath;
    request.input.path = filePath;
    request.input.md5 = md5OfBinary;
    request.hostname = hostName;
    request.contents.reserve(funcs.size());
    request.ea64s.reserve(funcs.size());

    for (const auto& func : funcs)
    {
        FunctionInfoAndPattern entry;
        entry.info.name = func.name;
        entry.info.size = func.func_len;
        entry.info.metadata = func.func_data;
        entry.patternId = PatternId::fromHash(func.hash);
        request.contents.push_back(std::move(entry));
        request.ea64s.push_back(func.address);
    }

    return request;
}

}  // namespace lumina
