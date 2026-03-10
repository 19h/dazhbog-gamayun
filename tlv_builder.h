#pragma once

#include "lumina_codec.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace lumina {

inline void tlv_emit(std::vector<uint8_t>& out, uint32_t tag, const std::vector<uint8_t>& value)
{
    pack_dd_into(out, tag);
    pack_var_bytes(out, value.data(), value.size());
}

struct ParsedTLV {
    bool hasNoReturn = false;
    bool noReturn = false;
    std::string comment;
    std::vector<std::string> varNames;
};

namespace detail {

class FrameReader {
public:
    FrameReader(const uint8_t* data, size_t size) : m_ptr(data), m_end(data + size) {}

    bool readByte(uint8_t& out)
    {
        if (m_ptr >= m_end)
            return false;
        out = *m_ptr++;
        return true;
    }

    bool readDw(uint16_t& out)
    {
        size_t consumed = 0;
        if (!unpack_dw(m_ptr, static_cast<size_t>(m_end - m_ptr), out, consumed) || consumed == 0)
            return false;
        m_ptr += consumed;
        return true;
    }

    bool readDd(uint32_t& out)
    {
        size_t consumed = 0;
        if (!unpack_dd(m_ptr, static_cast<size_t>(m_end - m_ptr), out, consumed) || consumed == 0)
            return false;
        m_ptr += consumed;
        return true;
    }

    bool readEa64(uint64_t& out)
    {
        size_t consumed = 0;
        if (!unpack_ea64(m_ptr, static_cast<size_t>(m_end - m_ptr), out, consumed) || consumed == 0)
            return false;
        m_ptr += consumed;
        return true;
    }

    bool readString(std::string& out)
    {
        size_t consumed = 0;
        if (!unpack_cstr(m_ptr, static_cast<size_t>(m_end - m_ptr), out, consumed) || consumed == 0)
            return false;
        m_ptr += consumed;
        return true;
    }

    bool skipSerializedTinfo()
    {
        return skipCStringBytes() && skipCStringBytes();
    }

    bool skipOpRepr()
    {
        uint8_t flags = 0;
        if (!readByte(flags))
            return false;
        if ((flags & 0x0F) == 0x05)
        {
            for (size_t i = 0; i < 7; ++i)
            {
                uint32_t ignored = 0;
                if (!readDd(ignored))
                    return false;
            }
        }
        return true;
    }

private:
    bool skipCStringBytes()
    {
        while (m_ptr < m_end && *m_ptr != 0)
            ++m_ptr;
        if (m_ptr >= m_end)
            return false;
        ++m_ptr;
        return true;
    }

    const uint8_t* m_ptr;
    const uint8_t* m_end;
};

inline bool parseFrameDescriptionNames(const uint8_t* data, size_t size, std::vector<std::string>* outNames)
{
    if (outNames == nullptr || data == nullptr || size == 0)
        return false;

    FrameReader reader(data, size);
    uint64_t ignoredEa = 0;
    uint16_t ignoredRegs = 0;
    uint32_t memberCount = 0;

    if (!reader.readEa64(ignoredEa)
        || !reader.readEa64(ignoredEa)
        || !reader.readDw(ignoredRegs)
        || !reader.readDd(memberCount))
    {
        return false;
    }

    outNames->clear();
    outNames->reserve(memberCount);
    for (uint32_t i = 0; i < memberCount; ++i)
    {
        uint8_t greedyBits = 0;
        if (!reader.readByte(greedyBits))
            return false;

        if ((greedyBits & (1U << 0)) != 0)
        {
            std::string name;
            if (!reader.readString(name))
                return false;
            if (!name.empty())
                outNames->push_back(std::move(name));
        }

        if ((greedyBits & (1U << 1)) != 0 && !reader.skipSerializedTinfo())
            return false;
        if ((greedyBits & (1U << 2)) != 0)
        {
            std::string ignored;
            if (!reader.readString(ignored))
                return false;
        }
        if ((greedyBits & (1U << 3)) != 0)
        {
            std::string ignored;
            if (!reader.readString(ignored))
                return false;
        }
        if ((greedyBits & (1U << 4)) != 0 && !reader.readEa64(ignoredEa))
            return false;
        if ((greedyBits & (1U << 5)) != 0 && !reader.skipOpRepr())
            return false;
        if ((greedyBits & (1U << 6)) != 0 && !reader.readEa64(ignoredEa))
            return false;
    }

    return true;
}

}  // namespace detail

inline std::vector<uint8_t> build_function_tlv(
    bool noReturn,
    const std::string& comment,
    const std::vector<std::string>& varNames)
{
    static_cast<void>(noReturn);
    static_cast<void>(varNames);

    std::vector<uint8_t> out;
    if (!comment.empty())
    {
        std::vector<uint8_t> value(comment.begin(), comment.end());
        tlv_emit(out, static_cast<uint32_t>(MetadataKey::FunctionComment), value);
    }
    return out;
}

inline bool parse_function_tlv(const std::vector<uint8_t>& data, ParsedTLV* out)
{
    if (out == nullptr)
        return false;

    out->hasNoReturn = false;
    out->noReturn = false;
    out->comment.clear();
    out->varNames.clear();

    const uint8_t* bytes = data.data();
    size_t offset = 0;
    while (offset < data.size())
    {
        uint32_t tag = 0;
        size_t consumed = 0;
        if (!unpack_dd(bytes + offset, data.size() - offset, tag, consumed) || consumed == 0)
            return false;
        offset += consumed;

        if (tag == static_cast<uint32_t>(MetadataKey::None))
            break;

        const uint8_t* chunk = nullptr;
        size_t chunkSize = 0;
        if (!unpack_var_bytes(bytes + offset, data.size() - offset, &chunk, chunkSize, consumed) || consumed == 0)
            return false;
        offset += consumed;

        switch (static_cast<MetadataKey>(tag))
        {
        case MetadataKey::FunctionComment:
            out->comment.assign(reinterpret_cast<const char*>(chunk), chunkSize);
            break;
        case MetadataKey::RepeatableFunctionComment:
            if (out->comment.empty())
                out->comment.assign(reinterpret_cast<const char*>(chunk), chunkSize);
            break;
        case MetadataKey::FrameDescription:
        {
            std::vector<std::string> names;
            if (detail::parseFrameDescriptionNames(chunk, chunkSize, &names))
                out->varNames = std::move(names);
            break;
        }
        default:
            break;
        }
    }

    return true;
}

}  // namespace lumina
