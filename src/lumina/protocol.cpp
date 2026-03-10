#include "lumina/protocol.h"

#include <algorithm>

namespace lumina {

namespace {

bool read_exact(const uint8_t*& ptr, const uint8_t* end, void* out, size_t size)
{
    if (ptr > end || static_cast<size_t>(end - ptr) < size)
        return false;
    std::copy_n(ptr, size, static_cast<uint8_t*>(out));
    ptr += size;
    return true;
}

bool unpack_dd_ptr(uint32_t& value, const uint8_t*& ptr, const uint8_t* end)
{
    size_t consumed = 0;
    if (!unpack_dd(ptr, static_cast<size_t>(end - ptr), value, consumed) || consumed == 0)
        return false;
    ptr += consumed;
    return true;
}

bool unpack_dq_ptr(uint64_t& value, const uint8_t*& ptr, const uint8_t* end)
{
    size_t consumed = 0;
    if (!unpack_dq(ptr, static_cast<size_t>(end - ptr), value, consumed) || consumed == 0)
        return false;
    ptr += consumed;
    return true;
}

bool unpack_cstr_ptr(std::string& value, const uint8_t*& ptr, const uint8_t* end)
{
    size_t consumed = 0;
    if (!unpack_cstr(ptr, static_cast<size_t>(end - ptr), value, consumed) || consumed == 0)
        return false;
    ptr += consumed;
    return true;
}

bool unpack_var_bytes_ptr(
    const uint8_t*& bytes,
    size_t& len,
    const uint8_t*& ptr,
    const uint8_t* end)
{
    size_t consumed = 0;
    if (!unpack_var_bytes(ptr, static_cast<size_t>(end - ptr), &bytes, len, consumed) || consumed == 0)
        return false;
    ptr += consumed;
    return true;
}

OperationResult decode_operation_result(uint32_t raw)
{
    return static_cast<OperationResult>(static_cast<int32_t>(raw));
}

void serialize_operation_results(std::vector<uint8_t>& out, const std::vector<OperationResult>& codes)
{
    pack_dd_into(out, static_cast<uint32_t>(codes.size()));
    for (OperationResult code : codes)
        pack_dd_into(out, static_cast<uint32_t>(static_cast<int32_t>(code)));
}

bool deserialize_operation_results(
    std::vector<OperationResult>& codes,
    const uint8_t*& ptr,
    const uint8_t* end)
{
    uint32_t count = 0;
    if (!unpack_dd_ptr(count, ptr, end))
        return false;

    codes.clear();
    codes.reserve(count);
    for (uint32_t i = 0; i < count; ++i)
    {
        uint32_t raw = 0;
        if (!unpack_dd_ptr(raw, ptr, end))
            return false;
        codes.push_back(decode_operation_result(raw));
    }
    return true;
}

}  // namespace

bool pack_dd_into(std::vector<uint8_t>& out, uint32_t value)
{
    if (value <= 0x7F)
    {
        out.push_back(static_cast<uint8_t>(value));
        return true;
    }

    if (value <= 0x3FFF)
    {
        out.push_back(static_cast<uint8_t>(0x80 | ((value >> 8) & 0x3F)));
        out.push_back(static_cast<uint8_t>(value & 0xFF));
        return true;
    }

    if (value <= 0x1FFFFFFF)
    {
        out.push_back(static_cast<uint8_t>(0xC0 | ((value >> 24) & 0x1F)));
        out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(value & 0xFF));
        return true;
    }

    out.push_back(0xFF);
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    return true;
}

std::vector<uint8_t> pack_dd(uint32_t value)
{
    std::vector<uint8_t> out;
    out.reserve(5);
    pack_dd_into(out, value);
    return out;
}

void pack_dq_into(std::vector<uint8_t>& out, uint64_t value)
{
    pack_dd_into(out, static_cast<uint32_t>(value & 0xFFFFFFFFULL));
    pack_dd_into(out, static_cast<uint32_t>(value >> 32));
}

std::vector<uint8_t> pack_dq(uint64_t value)
{
    std::vector<uint8_t> out;
    out.reserve(10);
    pack_dq_into(out, value);
    return out;
}

void pack_ea64_into(std::vector<uint8_t>& out, uint64_t value)
{
    pack_dq_into(out, value + 1);
}

void pack_var_bytes(std::vector<uint8_t>& out, const uint8_t* data, size_t len)
{
    pack_dd_into(out, static_cast<uint32_t>(len));
    if (len != 0)
        out.insert(out.end(), data, data + len);
}

void pack_cstr(std::vector<uint8_t>& out, const std::string& value)
{
    out.insert(out.end(), value.begin(), value.end());
    out.push_back(0);
}

bool unpack_dw(const uint8_t* data, size_t size, uint16_t& value, size_t& consumed)
{
    consumed = 0;
    if (size == 0)
        return false;

    uint16_t current = data[0];
    consumed = 1;
    if ((current & 0x80) != 0)
    {
        if ((current & 0xC0) == 0xC0)
        {
            if (size < 3)
            {
                consumed = 0;
                return false;
            }
            current = static_cast<uint16_t>((static_cast<uint16_t>(data[1]) << 8) | data[2]);
            consumed = 3;
        }
        else
        {
            if (size < 2)
            {
                consumed = 0;
                return false;
            }
            current = static_cast<uint16_t>(((current << 8) | data[1]) & ~0x8000U);
            consumed = 2;
        }
    }

    value = current;
    return true;
}

bool unpack_dd(const uint8_t* data, size_t size, uint32_t& value, size_t& consumed)
{
    consumed = 0;
    if (size == 0)
        return false;

    const uint8_t b0 = data[0];
    if ((b0 & 0x80U) == 0)
    {
        value = b0;
        consumed = 1;
        return true;
    }

    if ((b0 & 0xC0U) == 0x80U)
    {
        if (size < 2)
            return false;
        value = (static_cast<uint32_t>(b0 & 0x3FU) << 8) | static_cast<uint32_t>(data[1]);
        consumed = 2;
        return true;
    }

    if ((b0 & 0xE0U) == 0xC0U)
    {
        if (size < 4)
            return false;
        value = static_cast<uint32_t>(data[3])
              | (static_cast<uint32_t>(data[2]) << 8)
              | (static_cast<uint32_t>(data[1]) << 16)
              | (static_cast<uint32_t>(b0 & 0x1FU) << 24);
        consumed = 4;
        return true;
    }

    if (b0 == 0xFFU)
    {
        if (size < 5)
            return false;
        value = (static_cast<uint32_t>(data[1]) << 24)
              | (static_cast<uint32_t>(data[2]) << 16)
              | (static_cast<uint32_t>(data[3]) << 8)
              | static_cast<uint32_t>(data[4]);
        consumed = 5;
        return true;
    }

    if (size < 4)
        return false;

    value = (static_cast<uint32_t>(b0 & 0x1FU) << 24)
          | (static_cast<uint32_t>(data[1]) << 16)
          | (static_cast<uint32_t>(data[2]) << 8)
          | static_cast<uint32_t>(data[3]);
    consumed = 4;
    return true;
}

bool unpack_dq(const uint8_t* data, size_t size, uint64_t& value, size_t& consumed)
{
    consumed = 0;

    uint32_t low = 0;
    size_t lowConsumed = 0;
    if (!unpack_dd(data, size, low, lowConsumed) || lowConsumed == 0)
        return false;

    uint32_t high = 0;
    size_t highConsumed = 0;
    if (!unpack_dd(data + lowConsumed, size - lowConsumed, high, highConsumed) || highConsumed == 0)
        return false;

    value = (static_cast<uint64_t>(high) << 32) | static_cast<uint64_t>(low);
    consumed = lowConsumed + highConsumed;
    return true;
}

bool unpack_ea64(const uint8_t* data, size_t size, uint64_t& value, size_t& consumed)
{
    uint64_t packed = 0;
    if (!unpack_dq(data, size, packed, consumed) || consumed == 0)
        return false;
    value = packed - 1;
    return true;
}

bool unpack_cstr(const uint8_t* data, size_t size, std::string& value, size_t& consumed)
{
    consumed = 0;
    size_t index = 0;
    while (index < size && data[index] != 0)
        ++index;

    if (index >= size)
        return false;

    value.assign(reinterpret_cast<const char*>(data), index);
    consumed = index + 1;
    return true;
}

bool unpack_var_bytes(
    const uint8_t* data,
    size_t size,
    const uint8_t** bytes,
    size_t& len,
    size_t& consumed)
{
    consumed = 0;
    len = 0;
    if (bytes != nullptr)
        *bytes = nullptr;

    uint32_t packedLen = 0;
    size_t headerSize = 0;
    if (!unpack_dd(data, size, packedLen, headerSize) || headerSize == 0)
        return false;

    if (size < headerSize + packedLen)
        return false;

    if (bytes != nullptr)
        *bytes = data + headerSize;
    len = packedLen;
    consumed = headerSize + packedLen;
    return true;
}

void PatternId::serialize(std::vector<uint8_t>& out) const
{
    pack_dd_into(out, static_cast<uint32_t>(type));
    pack_var_bytes(out, data.data(), data.size());
}

bool PatternId::deserialize(const uint8_t*& ptr, const uint8_t* end)
{
    uint32_t rawType = 0;
    if (!unpack_dd_ptr(rawType, ptr, end))
        return false;
    type = static_cast<PatternType>(rawType);

    const uint8_t* bytes = nullptr;
    size_t len = 0;
    if (!unpack_var_bytes_ptr(bytes, len, ptr, end))
        return false;

    data.assign(bytes, bytes + len);
    return true;
}

PatternId PatternId::fromHash(const std::array<uint8_t, kMd5HashSize>& hash)
{
    PatternId out;
    out.type = PatternType::Md5;
    out.data.assign(hash.begin(), hash.end());
    return out;
}

void FunctionInfo::serialize(std::vector<uint8_t>& out) const
{
    pack_cstr(out, name);
    pack_dd_into(out, size);
    pack_var_bytes(out, metadata.data(), metadata.size());
}

bool FunctionInfo::deserialize(const uint8_t*& ptr, const uint8_t* end)
{
    if (!unpack_cstr_ptr(name, ptr, end))
        return false;
    if (!unpack_dd_ptr(size, ptr, end))
        return false;

    const uint8_t* bytes = nullptr;
    size_t len = 0;
    if (!unpack_var_bytes_ptr(bytes, len, ptr, end))
        return false;

    metadata.assign(bytes, bytes + len);
    return true;
}

void FunctionInfoAndFrequency::serialize(std::vector<uint8_t>& out) const
{
    info.serialize(out);
    pack_dd_into(out, frequency);
}

bool FunctionInfoAndFrequency::deserialize(const uint8_t*& ptr, const uint8_t* end)
{
    return info.deserialize(ptr, end) && unpack_dd_ptr(frequency, ptr, end);
}

void UserLicenseInfo::serialize(std::vector<uint8_t>& out) const
{
    pack_cstr(out, id);
    pack_cstr(out, name);
    pack_cstr(out, email);
}

bool UserLicenseInfo::deserialize(const uint8_t*& ptr, const uint8_t* end)
{
    return unpack_cstr_ptr(id, ptr, end)
        && unpack_cstr_ptr(name, ptr, end)
        && unpack_cstr_ptr(email, ptr, end);
}

void LuminaUser::serialize(std::vector<uint8_t>& out) const
{
    licenseInfo.serialize(out);
    pack_cstr(out, name);
    pack_dd_into(out, static_cast<uint32_t>(karma));
    pack_dq_into(out, lastActive);
    pack_dd_into(out, features);
}

bool LuminaUser::deserialize(const uint8_t*& ptr, const uint8_t* end)
{
    if (!licenseInfo.deserialize(ptr, end))
        return false;
    if (!unpack_cstr_ptr(name, ptr, end))
        return false;

    uint32_t packedKarma = 0;
    if (!unpack_dd_ptr(packedKarma, ptr, end))
        return false;
    karma = static_cast<int32_t>(packedKarma);

    return unpack_dq_ptr(lastActive, ptr, end)
        && unpack_dd_ptr(features, ptr, end);
}

void RpcFail::serialize(std::vector<uint8_t>& out) const
{
    pack_dd_into(out, static_cast<uint32_t>(result));
    pack_cstr(out, error);
}

bool RpcFail::deserialize(const uint8_t*& ptr, const uint8_t* end)
{
    uint32_t packedResult = 0;
    if (!unpack_dd_ptr(packedResult, ptr, end))
        return false;
    result = static_cast<int32_t>(packedResult);
    return unpack_cstr_ptr(error, ptr, end);
}

void HelloRequest::serialize(std::vector<uint8_t>& out) const
{
    pack_dd_into(out, clientVersion);
    pack_var_bytes(out, key.data(), key.size());
    out.insert(out.end(), licenseId.begin(), licenseId.end());
    pack_dd_into(out, recordConversation ? 1U : 0U);
    if (clientVersion >= 3)
    {
        pack_cstr(out, username);
        pack_cstr(out, password);
    }
}

bool HelloRequest::deserialize(const uint8_t*& ptr, const uint8_t* end)
{
    if (!unpack_dd_ptr(clientVersion, ptr, end))
        return false;

    const uint8_t* bytes = nullptr;
    size_t len = 0;
    if (!unpack_var_bytes_ptr(bytes, len, ptr, end))
        return false;
    key.assign(bytes, bytes + len);

    if (!read_exact(ptr, end, licenseId.data(), licenseId.size()))
        return false;

    uint32_t record = 0;
    if (!unpack_dd_ptr(record, ptr, end))
        return false;
    recordConversation = record != 0;

    if (clientVersion >= 3)
    {
        if (!unpack_cstr_ptr(username, ptr, end))
            return false;
        if (!unpack_cstr_ptr(password, ptr, end))
            return false;
    }
    else
    {
        username.clear();
        password.clear();
    }

    return true;
}

void HelloResult::serialize(std::vector<uint8_t>& out) const
{
    user.serialize(out);
}

bool HelloResult::deserialize(const uint8_t*& ptr, const uint8_t* end)
{
    return user.deserialize(ptr, end);
}

void PullMetadataRequest::serialize(std::vector<uint8_t>& out) const
{
    pack_dd_into(out, flags);
    pack_dd_into(out, static_cast<uint32_t>(keys.size()));
    for (uint32_t key : keys)
        pack_dd_into(out, key);

    pack_dd_into(out, static_cast<uint32_t>(patternIds.size()));
    for (const auto& patternId : patternIds)
        patternId.serialize(out);
}

bool PullMetadataRequest::deserialize(const uint8_t*& ptr, const uint8_t* end)
{
    if (!unpack_dd_ptr(flags, ptr, end))
        return false;

    uint32_t keyCount = 0;
    if (!unpack_dd_ptr(keyCount, ptr, end))
        return false;
    keys.clear();
    keys.reserve(keyCount);
    for (uint32_t i = 0; i < keyCount; ++i)
    {
        uint32_t key = 0;
        if (!unpack_dd_ptr(key, ptr, end))
            return false;
        keys.push_back(key);
    }

    uint32_t patternCount = 0;
    if (!unpack_dd_ptr(patternCount, ptr, end))
        return false;
    patternIds.clear();
    patternIds.resize(patternCount);
    for (uint32_t i = 0; i < patternCount; ++i)
    {
        if (!patternIds[i].deserialize(ptr, end))
            return false;
    }
    return true;
}

void PullMetadataResult::serialize(std::vector<uint8_t>& out) const
{
    serialize_operation_results(out, codes);
    pack_dd_into(out, static_cast<uint32_t>(results.size()));
    for (const auto& result : results)
        result.serialize(out);
}

bool PullMetadataResult::deserialize(const uint8_t*& ptr, const uint8_t* end)
{
    if (!deserialize_operation_results(codes, ptr, end))
        return false;

    uint32_t resultCount = 0;
    if (!unpack_dd_ptr(resultCount, ptr, end))
        return false;

    results.clear();
    results.resize(resultCount);
    for (uint32_t i = 0; i < resultCount; ++i)
    {
        if (!results[i].deserialize(ptr, end))
            return false;
    }
    return true;
}

}  // namespace lumina
