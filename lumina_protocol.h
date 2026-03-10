#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace lumina {

constexpr uint32_t kProtocolVersion = 6;
constexpr size_t kMd5HashSize = 16;
constexpr size_t kMaxPacketPayloadSize = 32 * 1024 * 1024;

enum class PacketType : uint8_t {
    RpcOk = 0x0a,
    RpcFail = 0x0b,
    RpcNotify = 0x0c,
    Hello = 0x0d,
    PullMetadata = 0x0e,
    PullMetadataResult = 0x0f,
    HelloResult = 0x31,
};

enum class PatternType : uint32_t {
    Unknown = 0,
    Md5 = 1,
};

enum class OperationResult : int32_t {
    BadPattern = -3,
    NotFound = -2,
    Error = -1,
    Ok = 0,
};

enum class MetadataKey : uint32_t {
    None = 0,
    Type = 1,
    VdElapsed = 2,
    FunctionComment = 3,
    RepeatableFunctionComment = 4,
    InstructionComments = 5,
    RepeatableInstructionComments = 6,
    ExtraComments = 7,
    UserStackPoints = 8,
    FrameDescription = 9,
    OperandRepresentations = 10,
    OperandRepresentationsEx = 11,
};

bool pack_dd_into(std::vector<uint8_t>& out, uint32_t value);
std::vector<uint8_t> pack_dd(uint32_t value);
void pack_dq_into(std::vector<uint8_t>& out, uint64_t value);
std::vector<uint8_t> pack_dq(uint64_t value);
void pack_ea64_into(std::vector<uint8_t>& out, uint64_t value);
void pack_var_bytes(std::vector<uint8_t>& out, const uint8_t* data, size_t len);
void pack_cstr(std::vector<uint8_t>& out, const std::string& value);

bool unpack_dw(const uint8_t* data, size_t size, uint16_t& value, size_t& consumed);
bool unpack_dd(const uint8_t* data, size_t size, uint32_t& value, size_t& consumed);
bool unpack_dq(const uint8_t* data, size_t size, uint64_t& value, size_t& consumed);
bool unpack_ea64(const uint8_t* data, size_t size, uint64_t& value, size_t& consumed);
bool unpack_cstr(const uint8_t* data, size_t size, std::string& value, size_t& consumed);
bool unpack_var_bytes(
    const uint8_t* data,
    size_t size,
    const uint8_t** bytes,
    size_t& len,
    size_t& consumed);

struct PatternId {
    PatternType type = PatternType::Unknown;
    std::vector<uint8_t> data;

    void serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const uint8_t*& ptr, const uint8_t* end);

    static PatternId fromHash(const std::array<uint8_t, kMd5HashSize>& hash);
};

struct FunctionInfo {
    std::string name;
    uint32_t size = 0;
    std::vector<uint8_t> metadata;

    void serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const uint8_t*& ptr, const uint8_t* end);
};

struct FunctionInfoAndFrequency {
    FunctionInfo info;
    uint32_t frequency = 0;

    void serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const uint8_t*& ptr, const uint8_t* end);
};

struct UserLicenseInfo {
    std::string id;
    std::string name;
    std::string email;

    void serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const uint8_t*& ptr, const uint8_t* end);
};

struct LuminaUser {
    UserLicenseInfo licenseInfo;
    std::string name;
    int32_t karma = 0;
    uint64_t lastActive = 0;
    uint32_t features = 0;

    void serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const uint8_t*& ptr, const uint8_t* end);
};

struct RpcFail {
    int32_t result = 0;
    std::string error;

    void serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const uint8_t*& ptr, const uint8_t* end);
};

struct HelloRequest {
    uint32_t clientVersion = kProtocolVersion;
    std::vector<uint8_t> key;
    std::array<uint8_t, 6> licenseId{};
    bool recordConversation = false;
    std::string username;
    std::string password;

    void serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const uint8_t*& ptr, const uint8_t* end);
};

struct HelloResult {
    LuminaUser user;

    void serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const uint8_t*& ptr, const uint8_t* end);
};

struct PullMetadataRequest {
    uint32_t flags = 0;
    std::vector<uint32_t> keys;
    std::vector<PatternId> patternIds;

    void serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const uint8_t*& ptr, const uint8_t* end);
};

struct PullMetadataResult {
    std::vector<OperationResult> codes;
    std::vector<FunctionInfoAndFrequency> results;

    void serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const uint8_t*& ptr, const uint8_t* end);
};

template <typename T>
std::vector<uint8_t> serialize_payload(const T& value)
{
    std::vector<uint8_t> out;
    value.serialize(out);
    return out;
}

template <typename T>
bool deserialize_payload(const std::vector<uint8_t>& payload, T* value)
{
    static const uint8_t empty = 0;
    const uint8_t* ptr = payload.empty() ? &empty : payload.data();
    const uint8_t* end = ptr + payload.size();
    return value != nullptr && value->deserialize(ptr, end) && ptr == end;
}

}  // namespace lumina
