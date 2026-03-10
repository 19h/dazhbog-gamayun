#include "lumina_metadata.h"

#include "lumina_type_decoder.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <utility>

namespace lumina {

namespace {

std::string trimTrailingNuls(std::string value)
{
    while (!value.empty() && value.back() == '\0')
        value.pop_back();
    return value;
}

std::vector<std::string> extractPrintableTexts(const uint8_t* data, size_t size)
{
    std::vector<std::string> texts;
    std::string current;
    current.reserve(size);
    for (size_t i = 0; i < size; ++i)
    {
        const uint8_t byte = data[i];
        if (std::isgraph(byte) != 0 || byte == ' ')
        {
            current.push_back(static_cast<char>(byte));
        }
        else
        {
            if (current.size() >= 3)
                texts.push_back(current);
            current.clear();
        }
    }
    if (current.size() >= 3)
        texts.push_back(current);
    std::sort(texts.begin(), texts.end());
    texts.erase(std::unique(texts.begin(), texts.end()), texts.end());
    return texts;
}

struct FrameParser {
    const uint8_t* data = nullptr;
    size_t size = 0;
    size_t offset = 0;

    bool readByte(uint8_t& out)
    {
        if (offset >= size)
            return false;
        out = data[offset++];
        return true;
    }

    bool readDw(uint16_t& out)
    {
        size_t consumed = 0;
        if (!unpack_dw(data + offset, size - offset, out, consumed) || consumed == 0)
            return false;
        offset += consumed;
        return true;
    }

    bool readDd(uint32_t& out)
    {
        size_t consumed = 0;
        if (!unpack_dd(data + offset, size - offset, out, consumed) || consumed == 0)
            return false;
        offset += consumed;
        return true;
    }

    bool readEa64(uint64_t& out)
    {
        size_t consumed = 0;
        if (!unpack_ea64(data + offset, size - offset, out, consumed) || consumed == 0)
            return false;
        offset += consumed;
        return true;
    }

    bool readCstrBytes(std::vector<uint8_t>& out)
    {
        const size_t start = offset;
        while (offset < size && data[offset] != 0)
            ++offset;
        if (offset >= size)
            return false;
        out.assign(data + start, data + offset);
        ++offset;
        return true;
    }

    bool readString(std::string& out)
    {
        std::vector<uint8_t> bytes;
        if (!readCstrBytes(bytes))
            return false;
        out.assign(bytes.begin(), bytes.end());
        return true;
    }

    bool readSerializedTinfo(SerializedTinfo& out)
    {
        if (!readCstrBytes(out.typeBytes) || !readCstrBytes(out.fieldsBytes))
            return false;
        const TypeDeclResult decoded = decodeTinfoDecl(out.typeBytes, out.fieldsBytes);
        if (decoded.ok())
            out.declaration = decoded.declaration;
        else
            out.decodeError = decoded.error;
        return true;
    }

    bool skipOpRepr(std::vector<uint8_t>& out)
    {
        const size_t start = offset;
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
        out.assign(data + start, data + offset);
        return true;
    }

    bool readFrameMember(FrameMember& out)
    {
        uint8_t greedyBits = 0;
        if (!readByte(greedyBits))
            return false;

        if ((greedyBits & (1U << 0)) != 0)
        {
            std::string value;
            if (!readString(value))
                return false;
            out.name = value;
        }
        if ((greedyBits & (1U << 1)) != 0)
        {
            SerializedTinfo value;
            if (!readSerializedTinfo(value))
                return false;
            out.tinfo = std::move(value);
        }
        if ((greedyBits & (1U << 2)) != 0)
        {
            std::string value;
            if (!readString(value))
                return false;
            out.comment = value;
        }
        if ((greedyBits & (1U << 3)) != 0)
        {
            std::string value;
            if (!readString(value))
                return false;
            out.repeatableComment = value;
        }
        if ((greedyBits & (1U << 4)) != 0)
        {
            uint64_t value = 0;
            if (!readEa64(value))
                return false;
            out.offset = value;
        }
        if ((greedyBits & (1U << 5)) != 0)
        {
            std::vector<uint8_t> value;
            if (!skipOpRepr(value))
                return false;
            out.info = std::move(value);
        }
        if ((greedyBits & (1U << 6)) != 0)
        {
            uint64_t value = 0;
            if (!readEa64(value))
                return false;
            out.nbytes = value;
        }
        return true;
    }
};

std::optional<MdTypeParts> parseMdkType(const uint8_t* data, size_t size)
{
    if (size == 0)
        return std::nullopt;

    MdTypeParts out;
    out.userti = data[0] != 0;
    const uint8_t* rest = data + 1;
    const size_t restSize = size - 1;

    const uint8_t* nul = static_cast<const uint8_t*>(std::memchr(rest, 0, restSize));
    if (nul != nullptr)
    {
        out.typeBytes.assign(rest, nul);
        out.fieldsBytes.assign(nul + 1, rest + restSize);
        while (!out.fieldsBytes.empty() && out.fieldsBytes.back() == 0)
            out.fieldsBytes.pop_back();
    }
    else
    {
        out.typeBytes.assign(rest, rest + restSize);
    }

    const TypeDeclResult decoded = decodeTinfoDecl(out.typeBytes, out.fieldsBytes);
    if (decoded.ok())
        out.declaration = decoded.declaration;
    else
        out.decodeError = decoded.error;
    return out;
}

std::optional<FrameDescription> parseFrameDescription(const uint8_t* data, size_t size)
{
    FrameParser parser{data, size, 0};
    FrameDescription frame;
    uint32_t memberCount = 0;
    if (!parser.readEa64(frame.frameSize)
        || !parser.readEa64(frame.argumentSize)
        || !parser.readDw(frame.savedRegistersSize)
        || !parser.readDd(memberCount))
    {
        return std::nullopt;
    }

    if (memberCount > 10000)
        return std::nullopt;

    frame.members.reserve(memberCount);
    for (uint32_t i = 0; i < memberCount; ++i)
    {
        FrameMember member;
        if (!parser.readFrameMember(member))
            return std::nullopt;
        frame.members.push_back(std::move(member));
    }
    return frame;
}

std::optional<std::vector<InstructionComment>> parseInstructionComments(const uint8_t* data, size_t size)
{
    if (size == 0)
        return std::nullopt;

    size_t offset = 0;
    uint32_t functionChunkNumber = 0;
    size_t consumed = 0;
    if (!unpack_dd(data + offset, size - offset, functionChunkNumber, consumed) || consumed == 0)
        return std::nullopt;
    offset += consumed;

    uint32_t functionChunkOffset = 0;
    bool firstInChunk = true;
    std::vector<InstructionComment> out;
    while (offset < size)
    {
        uint32_t delta = 0;
        if (!unpack_dd(data + offset, size - offset, delta, consumed) || consumed == 0)
            break;
        offset += consumed;

        if (!firstInChunk && delta == 0)
        {
            uint32_t nextChunk = 0;
            if (!unpack_dd(data + offset, size - offset, nextChunk, consumed) || consumed == 0)
                break;
            offset += consumed;
            functionChunkNumber = nextChunk;
            functionChunkOffset = 0;
            firstInChunk = true;
            continue;
        }

        functionChunkOffset += delta;
        const uint8_t* bytes = nullptr;
        size_t len = 0;
        if (!unpack_var_bytes(data + offset, size - offset, &bytes, len, consumed) || consumed == 0 || len > 65536)
            return std::nullopt;
        offset += consumed;

        InstructionComment comment;
        comment.functionChunkNumber = functionChunkNumber;
        comment.functionChunkOffset = functionChunkOffset;
        comment.comment = trimTrailingNuls(std::string(reinterpret_cast<const char*>(bytes), len));
        out.push_back(std::move(comment));
        firstInChunk = false;
    }
    return out;
}

class MetadataParser {
public:
    explicit MetadataParser(const std::vector<uint8_t>& data) : m_data(data)
    {
        m_result.rawSize = data.size();
    }

    FunctionMetadata parse()
    {
        while (m_offset < m_data.size())
        {
            uint32_t rawKey = 0;
            if (!readDd(rawKey))
            {
                m_result.errors.push_back("Failed to read metadata key");
                break;
            }

            if (rawKey == static_cast<uint32_t>(MetadataKey::None))
                break;

            uint32_t length = 0;
            if (!readDd(length))
            {
                m_result.errors.push_back("Failed to read metadata chunk length");
                break;
            }

            if (m_offset + length > m_data.size())
            {
                m_result.errors.push_back("Chunk length exceeds payload size");
                break;
            }

            const uint8_t* chunk = m_data.data() + m_offset;
            m_offset += length;

            MetadataChunk stored;
            stored.rawKey = rawKey;
            stored.key = static_cast<MetadataKey>(rawKey);
            stored.data.assign(chunk, chunk + length);
            m_result.rawChunks.push_back(stored);

            switch (stored.key)
            {
            case MetadataKey::Type:
            {
                auto parsed = parseMdkType(chunk, length);
                if (parsed)
                    m_result.typeParts = std::move(*parsed);
                else
                    m_result.errors.push_back("Failed to parse MDK_TYPE");
                break;
            }
            case MetadataKey::VdElapsed:
            {
                uint64_t value = 0;
                size_t consumed = 0;
                if (unpack_dq(chunk, length, value, consumed) && consumed != 0)
                    m_result.vdElapsed = value;
                else
                    m_result.errors.push_back("Failed to parse MDK_VD_ELAPSED");
                break;
            }
            case MetadataKey::FunctionComment:
                m_result.functionComment = trimTrailingNuls(std::string(reinterpret_cast<const char*>(chunk), length));
                break;
            case MetadataKey::RepeatableFunctionComment:
                m_result.repeatableFunctionComment = trimTrailingNuls(std::string(reinterpret_cast<const char*>(chunk), length));
                break;
            case MetadataKey::InstructionComments:
            {
                auto parsed = parseInstructionComments(chunk, length);
                if (parsed)
                    m_result.instructionComments = std::move(*parsed);
                else
                    m_result.errors.push_back("Failed to parse MDK_CMTS");
                break;
            }
            case MetadataKey::RepeatableInstructionComments:
            {
                auto parsed = parseInstructionComments(chunk, length);
                if (parsed)
                    m_result.repeatableInstructionComments = std::move(*parsed);
                else
                    m_result.errors.push_back("Failed to parse MDK_RPTCMTS");
                break;
            }
            case MetadataKey::ExtraComments:
                m_result.extraComments = extractPrintableTexts(chunk, length);
                break;
            case MetadataKey::UserStackPoints:
                m_result.userStackPoints = OpaqueMetadataBlob{stored.data, extractPrintableTexts(chunk, length)};
                break;
            case MetadataKey::FrameDescription:
            {
                auto parsed = parseFrameDescription(chunk, length);
                if (parsed)
                    m_result.frameDescription = std::move(*parsed);
                else
                    m_result.errors.push_back("Failed to parse MDK_FRAME_DESC");
                break;
            }
            case MetadataKey::OperandRepresentations:
                m_result.operandRepresentations = OpaqueMetadataBlob{stored.data, extractPrintableTexts(chunk, length)};
                break;
            case MetadataKey::OperandRepresentationsEx:
                m_result.operandRepresentationsEx = OpaqueMetadataBlob{stored.data, extractPrintableTexts(chunk, length)};
                break;
            default:
                break;
            }
        }

        m_result.bytesParsed = m_offset;
        return m_result;
    }

private:
    bool readDd(uint32_t& out)
    {
        size_t consumed = 0;
        if (!unpack_dd(m_data.data() + m_offset, m_data.size() - m_offset, out, consumed) || consumed == 0)
            return false;
        m_offset += consumed;
        return true;
    }

    const std::vector<uint8_t>& m_data;
    size_t m_offset = 0;
    FunctionMetadata m_result;
};

}  // namespace

bool FunctionMetadata::ok() const
{
    return errors.empty();
}

size_t FunctionMetadata::componentCount() const
{
    size_t count = 0;
    if (typeParts)
        count += 1;
    if (frameDescription)
        count += 1 + frameDescription->members.size();
    if (functionComment)
        count += 1;
    if (repeatableFunctionComment)
        count += 1;
    count += instructionComments.size();
    count += repeatableInstructionComments.size();
    count += extraComments.size();
    if (userStackPoints)
        count += 1;
    if (operandRepresentations)
        count += 1;
    if (operandRepresentationsEx)
        count += 1;
    return count;
}

bool FunctionMetadata::hasChunk(MetadataKey key) const
{
    return std::any_of(rawChunks.begin(), rawChunks.end(), [key](const MetadataChunk& chunk) {
        return chunk.key == key;
    });
}

const MetadataChunk* FunctionMetadata::chunk(MetadataKey key) const
{
    auto it = std::find_if(rawChunks.begin(), rawChunks.end(), [key](const MetadataChunk& chunk) {
        return chunk.key == key;
    });
    return it == rawChunks.end() ? nullptr : &*it;
}

std::optional<std::string> FunctionMetadata::effectiveFunctionComment() const
{
    if (functionComment && !functionComment->empty())
        return functionComment;
    if (repeatableFunctionComment && !repeatableFunctionComment->empty())
        return repeatableFunctionComment;
    return std::nullopt;
}

FunctionMetadata parseFunctionMetadata(const std::vector<uint8_t>& data)
{
    return MetadataParser(data).parse();
}

std::vector<MetadataChunk> splitMetadataChunks(const std::vector<uint8_t>& data)
{
    return parseFunctionMetadata(data).rawChunks;
}

std::vector<uint8_t> serializeMetadataChunks(const std::vector<MetadataChunk>& chunks)
{
    std::vector<uint8_t> out;
    for (const auto& chunk : chunks)
    {
        if (chunk.rawKey == 0 || chunk.key == MetadataKey::None)
            continue;
        pack_dd_into(out, chunk.rawKey);
        pack_dd_into(out, static_cast<uint32_t>(chunk.data.size()));
        out.insert(out.end(), chunk.data.begin(), chunk.data.end());
    }
    return out;
}

std::string metadataKeyName(uint32_t rawKey)
{
    switch (static_cast<MetadataKey>(rawKey))
    {
    case MetadataKey::None: return "MDK_NONE";
    case MetadataKey::Type: return "MDK_TYPE";
    case MetadataKey::VdElapsed: return "MDK_VD_ELAPSED";
    case MetadataKey::FunctionComment: return "MDK_FCMT";
    case MetadataKey::RepeatableFunctionComment: return "MDK_FRPTCMT";
    case MetadataKey::InstructionComments: return "MDK_CMTS";
    case MetadataKey::RepeatableInstructionComments: return "MDK_RPTCMTS";
    case MetadataKey::ExtraComments: return "MDK_EXTRACMTS";
    case MetadataKey::UserStackPoints: return "MDK_USER_STKPNTS";
    case MetadataKey::FrameDescription: return "MDK_FRAME_DESC";
    case MetadataKey::OperandRepresentations: return "MDK_OPS";
    case MetadataKey::OperandRepresentationsEx: return "MDK_OPS_EX";
    default:
        return "MDK_" + std::to_string(rawKey);
    }
}

}  // namespace lumina
