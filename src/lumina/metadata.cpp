#include "lumina/metadata.h"

#include "lumina/type_decoder.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>

namespace lumina {

namespace {

constexpr int kLuminaMaxOperands = 8;
constexpr int kOperandFlagsShift = 20;
constexpr uint8_t kOperandTypeMask = 0x0F;

constexpr uint8_t kOpTypeVoid = 0x0;
constexpr uint8_t kOpTypeNumHex = 0x1;
constexpr uint8_t kOpTypeNumDec = 0x2;
constexpr uint8_t kOpTypeChar = 0x3;
constexpr uint8_t kOpTypeSeg = 0x4;
constexpr uint8_t kOpTypeOffset = 0x5;
constexpr uint8_t kOpTypeNumBin = 0x6;
constexpr uint8_t kOpTypeNumOct = 0x7;
constexpr uint8_t kOpTypeEnum = 0x8;
constexpr uint8_t kOpTypeForced = 0x9;
constexpr uint8_t kOpTypeStructOffset = 0xA;
constexpr uint8_t kOpTypeStackVar = 0xB;
constexpr uint8_t kOpTypeFloat = 0xC;
constexpr uint8_t kOpTypeCustom = 0xD;

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
        if (std::isgraph(static_cast<unsigned char>(byte)) != 0 || byte == ' ')
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

int64_t decodeSignedEa64Value(uint64_t raw)
{
    int64_t value = 0;
    static_assert(sizeof(value) == sizeof(raw), "signed/unsigned EA64 width mismatch");
    std::memcpy(&value, &raw, sizeof(value));
    return value;
}

int operandTypeShift(int operandIndex)
{
    return kOperandFlagsShift + (4 * (operandIndex + (operandIndex > 1 ? 1 : 0)));
}

uint8_t operandTypeBits(uint64_t flags, int operandIndex)
{
    if (operandIndex < 0 || operandIndex >= kLuminaMaxOperands)
        return 0;
    return static_cast<uint8_t>((flags >> operandTypeShift(operandIndex)) & kOperandTypeMask);
}

bool readOffsetReferenceInfo(
    const uint8_t* data,
    size_t size,
    size_t& offset,
    OffsetReferenceInfo& out)
{
    size_t consumed = 0;
    if (!unpack_ea64(data + offset, size - offset, out.target, consumed) || consumed == 0)
        return false;
    offset += consumed;

    if (!unpack_ea64(data + offset, size - offset, out.base, consumed) || consumed == 0)
        return false;
    offset += consumed;

    uint64_t encodedDelta = 0;
    if (!unpack_ea64(data + offset, size - offset, encodedDelta, consumed) || consumed == 0)
        return false;
    out.targetDelta = decodeSignedEa64Value(encodedDelta);
    offset += consumed;

    if (!unpack_dd(data + offset, size - offset, out.flags, consumed) || consumed == 0)
        return false;
    offset += consumed;
    return true;
}

bool readOperandEntries(
    const uint8_t* data,
    size_t size,
    size_t& offset,
    uint64_t flags,
    int operandStart,
    int operandEnd,
    std::vector<OperandRepresentationEntry>& out)
{
    for (int operandIndex = operandStart; operandIndex < operandEnd; ++operandIndex)
    {
        const uint8_t typeBits = operandTypeBits(flags, operandIndex);
        if (typeBits == kOpTypeVoid)
            continue;

        OperandRepresentationEntry entry;
        entry.operandIndex = operandIndex;
        entry.typeBits = typeBits;
        entry.typeName = operandTypeName(typeBits);

        if (typeBits == kOpTypeOffset)
        {
            OffsetReferenceInfo ref;
            if (!readOffsetReferenceInfo(data, size, offset, ref))
                return false;
            entry.offsetReference = std::move(ref);
        }

        out.push_back(std::move(entry));
    }

    return true;
}

bool parseSingleOperandRepresentation(
    const uint8_t* data,
    size_t size,
    OperandRepresentationSet& out)
{
    if (data == nullptr || size == 0)
        return false;

    size_t offset = 0;
    const uint8_t rawFlags = data[offset++];
    out.flags = static_cast<uint64_t>(rawFlags) << kOperandFlagsShift;
    out.operands.clear();
    return readOperandEntries(data, size, offset, out.flags, 0, 1, out.operands) && offset == size;
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

    bool readOpRepr(std::vector<uint8_t>& raw, OperandRepresentationSet& decoded)
    {
        const size_t start = offset;
        if (offset >= size)
            return false;

        ++offset;
        uint8_t typeBits = 0;
        if (start < size)
            typeBits = data[start] & kOperandTypeMask;
        if (typeBits == kOpTypeOffset)
        {
            OffsetReferenceInfo ignored;
            if (!readOffsetReferenceInfo(data, size, offset, ignored))
                return false;
        }

        raw.assign(data + start, data + offset);
        return parseSingleOperandRepresentation(raw.data(), raw.size(), decoded);
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
            std::vector<uint8_t> raw;
            OperandRepresentationSet decoded;
            if (!readOpRepr(raw, decoded))
                return false;
            out.info = std::move(raw);
            out.infoRepresentation = std::move(decoded);
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

std::optional<std::vector<ExtraComment>> parseExtraComments(const uint8_t* data, size_t size)
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
    std::vector<ExtraComment> out;
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

        const uint8_t* previousBytes = nullptr;
        size_t previousLength = 0;
        if (!unpack_var_bytes(data + offset, size - offset, &previousBytes, previousLength, consumed) || consumed == 0)
            return std::nullopt;
        offset += consumed;

        const uint8_t* nextBytes = nullptr;
        size_t nextLength = 0;
        if (!unpack_var_bytes(data + offset, size - offset, &nextBytes, nextLength, consumed) || consumed == 0)
            return std::nullopt;
        offset += consumed;

        ExtraComment comment;
        comment.functionChunkNumber = functionChunkNumber;
        comment.functionChunkOffset = functionChunkOffset;
        comment.previous = trimTrailingNuls(std::string(reinterpret_cast<const char*>(previousBytes), previousLength));
        comment.next = trimTrailingNuls(std::string(reinterpret_cast<const char*>(nextBytes), nextLength));
        out.push_back(std::move(comment));
        firstInChunk = false;
    }

    return out;
}

std::optional<std::vector<UserStackPoint>> parseUserStackPoints(const uint8_t* data, size_t size)
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
    std::vector<UserStackPoint> out;
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

        uint64_t encodedDelta = 0;
        if (!unpack_ea64(data + offset, size - offset, encodedDelta, consumed) || consumed == 0)
            return std::nullopt;
        offset += consumed;

        UserStackPoint point;
        point.functionChunkNumber = functionChunkNumber;
        point.functionChunkOffset = functionChunkOffset;
        point.delta = decodeSignedEa64Value(encodedDelta);
        out.push_back(std::move(point));
        firstInChunk = false;
    }

    return out;
}

std::optional<std::vector<InstructionOperandRepresentation>> parseInstructionOperandRepresentations(
    const OpaqueMetadataBlob* ops,
    const OpaqueMetadataBlob* opsEx)
{
    auto parseChunk = [](const uint8_t* data,
                         size_t size,
                         bool extended,
                         std::vector<InstructionOperandRepresentation>& out) -> bool
    {
        if (data == nullptr || size == 0)
            return true;

        size_t offset = 0;
        uint32_t functionChunkNumber = 0;
        size_t consumed = 0;
        if (!unpack_dd(data + offset, size - offset, functionChunkNumber, consumed) || consumed == 0)
            return false;
        offset += consumed;

        uint32_t functionChunkOffset = 0;
        bool firstInChunk = true;
        while (offset < size)
        {
            uint32_t delta = 0;
            if (!unpack_dd(data + offset, size - offset, delta, consumed) || consumed == 0)
                return false;
            offset += consumed;

            if (!firstInChunk && delta == 0)
            {
                uint32_t nextChunk = 0;
                if (!unpack_dd(data + offset, size - offset, nextChunk, consumed) || consumed == 0)
                    return false;
                offset += consumed;
                functionChunkNumber = nextChunk;
                functionChunkOffset = 0;
                firstInChunk = true;
                continue;
            }

            functionChunkOffset += delta;

            auto it = std::find_if(out.begin(), out.end(), [&](const InstructionOperandRepresentation& entry) {
                return entry.functionChunkNumber == functionChunkNumber
                    && entry.functionChunkOffset == functionChunkOffset;
            });
            if (it == out.end())
            {
                InstructionOperandRepresentation entry;
                entry.functionChunkNumber = functionChunkNumber;
                entry.functionChunkOffset = functionChunkOffset;
                out.push_back(std::move(entry));
                it = std::prev(out.end());
            }

            if (!extended)
            {
                if (offset >= size)
                    return false;
                const uint8_t rawFlags = data[offset++];
                it->representation.flags = static_cast<uint64_t>(rawFlags) << kOperandFlagsShift;
                if (!readOperandEntries(
                        data,
                        size,
                        offset,
                        it->representation.flags,
                        0,
                        2,
                        it->representation.operands))
                {
                    return false;
                }
            }
            else
            {
                uint32_t rawFlags = 0;
                if (!unpack_dd(data + offset, size - offset, rawFlags, consumed) || consumed == 0)
                    return false;
                offset += consumed;
                it->representation.flags |= static_cast<uint64_t>(rawFlags) << 32;
                if (!readOperandEntries(
                        data,
                        size,
                        offset,
                        it->representation.flags,
                        2,
                        kLuminaMaxOperands,
                        it->representation.operands))
                {
                    return false;
                }
            }

            firstInChunk = false;
        }

        return true;
    };

    std::vector<InstructionOperandRepresentation> out;
    if (ops != nullptr && !parseChunk(ops->raw.data(), ops->raw.size(), false, out))
        return std::nullopt;
    if (opsEx != nullptr && !parseChunk(opsEx->raw.data(), opsEx->raw.size(), true, out))
        return std::nullopt;

    std::sort(out.begin(), out.end(), [](const InstructionOperandRepresentation& left, const InstructionOperandRepresentation& right) {
        if (left.functionChunkNumber != right.functionChunkNumber)
            return left.functionChunkNumber < right.functionChunkNumber;
        if (left.functionChunkOffset != right.functionChunkOffset)
            return left.functionChunkOffset < right.functionChunkOffset;
        return left.representation.flags < right.representation.flags;
    });
    return out;
}

std::string hexPreview(const uint8_t* data, size_t size, size_t maxBytes = 64)
{
    std::ostringstream out;
    const size_t previewSize = std::min(size, maxBytes);
    out << std::hex << std::setfill('0');
    for (size_t i = 0; i < previewSize; ++i)
    {
        if (i != 0)
            out << ' ';
        out << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    if (size > previewSize)
        out << " ...";
    return out.str();
}

std::string formatChunkLocation(uint32_t functionChunkNumber, uint32_t functionChunkOffset)
{
    std::ostringstream out;
    out << "chunk=" << functionChunkNumber << ", off=0x" << std::hex << std::uppercase << functionChunkOffset;
    return out.str();
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
            {
                auto parsed = parseExtraComments(chunk, length);
                if (parsed)
                {
                    m_result.extraCommentEntries = std::move(*parsed);
                    m_result.extraComments.clear();
                    for (const auto& entry : m_result.extraCommentEntries)
                    {
                        if (!entry.previous.empty())
                            m_result.extraComments.push_back(entry.previous);
                        if (!entry.next.empty())
                            m_result.extraComments.push_back(entry.next);
                    }
                }
                else
                {
                    m_result.extraComments = extractPrintableTexts(chunk, length);
                    m_result.errors.push_back("Failed to parse MDK_EXTRACMTS");
                }
                break;
            }
            case MetadataKey::UserStackPoints:
            {
                m_result.userStackPoints = OpaqueMetadataBlob{stored.data, extractPrintableTexts(chunk, length)};
                auto parsed = parseUserStackPoints(chunk, length);
                if (parsed)
                    m_result.userStackPointEntries = std::move(*parsed);
                else
                    m_result.errors.push_back("Failed to parse MDK_USER_STKPNTS");
                break;
            }
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

        if (m_result.operandRepresentations || m_result.operandRepresentationsEx)
        {
            auto parsed = parseInstructionOperandRepresentations(
                m_result.operandRepresentations ? &*m_result.operandRepresentations : nullptr,
                m_result.operandRepresentationsEx ? &*m_result.operandRepresentationsEx : nullptr);
            if (parsed)
                m_result.instructionOperandRepresentations = std::move(*parsed);
            else
                m_result.errors.push_back("Failed to parse MDK_OPS / MDK_OPS_EX");
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
    count += extraCommentEntries.empty() ? extraComments.size() : extraCommentEntries.size();
    if (userStackPoints)
        count += std::max<size_t>(1, userStackPointEntries.size());
    if (operandRepresentations)
        count += std::max<size_t>(1, instructionOperandRepresentations.size());
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

std::string operandTypeName(uint8_t typeBits)
{
    switch (typeBits)
    {
    case kOpTypeVoid: return "void";
    case kOpTypeNumHex: return "hex";
    case kOpTypeNumDec: return "decimal";
    case kOpTypeChar: return "char";
    case kOpTypeSeg: return "segment";
    case kOpTypeOffset: return "offset";
    case kOpTypeNumBin: return "binary";
    case kOpTypeNumOct: return "octal";
    case kOpTypeEnum: return "enum";
    case kOpTypeForced: return "forced";
    case kOpTypeStructOffset: return "struct_offset";
    case kOpTypeStackVar: return "stack_var";
    case kOpTypeFloat: return "float";
    case kOpTypeCustom: return "custom";
    default:
        return "type_" + std::to_string(typeBits);
    }
}

std::string formatFunctionMetadata(const FunctionMetadata& metadata, bool includeRawChunks)
{
    auto appendIndented = [](std::ostringstream& out, int indent, const std::string& text) {
        out << std::string(static_cast<size_t>(indent) * 2, ' ') << text << '\n';
    };
    auto formatHex = [](uint64_t value) {
        std::ostringstream out;
        out << "0x" << std::hex << std::uppercase << value;
        return out.str();
    };
    auto formatSigned = [](int64_t value) {
        uint64_t magnitude = 0;
        if (value < 0)
            magnitude = static_cast<uint64_t>(-(value + 1)) + 1;
        else
            magnitude = static_cast<uint64_t>(value);
        std::ostringstream out;
        out << value << " (0x" << std::hex << std::uppercase
            << magnitude << (value < 0 ? ", negative" : "") << ')';
        return out.str();
    };

    std::ostringstream out;
    appendIndented(out, 0, "Overview");
    appendIndented(out, 1, "raw_size=" + std::to_string(metadata.rawSize));
    appendIndented(out, 1, "bytes_parsed=" + std::to_string(metadata.bytesParsed));
    appendIndented(out, 1, "component_count=" + std::to_string(metadata.componentCount()));
    appendIndented(out, 1, "chunk_count=" + std::to_string(metadata.rawChunks.size()));

    if (metadata.typeParts)
    {
        appendIndented(out, 0, "MDK_TYPE");
        appendIndented(out, 1, std::string("userti=") + (metadata.typeParts->userti ? "true" : "false"));
        if (metadata.typeParts->declaration)
            appendIndented(out, 1, "declaration=" + *metadata.typeParts->declaration);
        if (metadata.typeParts->decodeError)
            appendIndented(out, 1, "decode_error=" + *metadata.typeParts->decodeError);
        appendIndented(out, 1, "type_bytes=" + hexPreview(metadata.typeParts->typeBytes.data(), metadata.typeParts->typeBytes.size()));
        appendIndented(out, 1, "fields_bytes=" + hexPreview(metadata.typeParts->fieldsBytes.data(), metadata.typeParts->fieldsBytes.size()));
    }

    if (metadata.vdElapsed)
    {
        appendIndented(out, 0, "MDK_VD_ELAPSED");
        appendIndented(out, 1, std::to_string(*metadata.vdElapsed));
    }

    if (metadata.functionComment || metadata.repeatableFunctionComment)
    {
        appendIndented(out, 0, "Function Comments");
        if (metadata.functionComment)
            appendIndented(out, 1, "comment=" + *metadata.functionComment);
        if (metadata.repeatableFunctionComment)
            appendIndented(out, 1, "repeatable_comment=" + *metadata.repeatableFunctionComment);
    }

    if (!metadata.instructionComments.empty())
    {
        appendIndented(out, 0, "Instruction Comments");
        for (const auto& comment : metadata.instructionComments)
            appendIndented(out, 1, formatChunkLocation(comment.functionChunkNumber, comment.functionChunkOffset) + " -> " + comment.comment);
    }

    if (!metadata.repeatableInstructionComments.empty())
    {
        appendIndented(out, 0, "Repeatable Instruction Comments");
        for (const auto& comment : metadata.repeatableInstructionComments)
            appendIndented(out, 1, formatChunkLocation(comment.functionChunkNumber, comment.functionChunkOffset) + " -> " + comment.comment);
    }

    if (!metadata.extraCommentEntries.empty())
    {
        appendIndented(out, 0, "Extra Comments");
        for (const auto& comment : metadata.extraCommentEntries)
        {
            appendIndented(out, 1, formatChunkLocation(comment.functionChunkNumber, comment.functionChunkOffset));
            if (!comment.previous.empty())
                appendIndented(out, 2, "prev=" + comment.previous);
            if (!comment.next.empty())
                appendIndented(out, 2, "next=" + comment.next);
        }
    }
    else if (!metadata.extraComments.empty())
    {
        appendIndented(out, 0, "Extra Comments (Printable Fragments)");
        for (const auto& fragment : metadata.extraComments)
            appendIndented(out, 1, fragment);
    }

    if (metadata.frameDescription)
    {
        appendIndented(out, 0, "Frame Description");
        appendIndented(out, 1, "frame_size=" + std::to_string(metadata.frameDescription->frameSize));
        appendIndented(out, 1, "argument_size=" + std::to_string(metadata.frameDescription->argumentSize));
        appendIndented(out, 1, "saved_registers_size=" + std::to_string(metadata.frameDescription->savedRegistersSize));
        for (size_t i = 0; i < metadata.frameDescription->members.size(); ++i)
        {
            const auto& member = metadata.frameDescription->members[i];
            appendIndented(out, 1, "member[" + std::to_string(i) + "]");
            if (member.name)
                appendIndented(out, 2, "name=" + *member.name);
            if (member.offset)
                appendIndented(out, 2, "offset=" + std::to_string(*member.offset));
            if (member.nbytes)
                appendIndented(out, 2, "nbytes=" + std::to_string(*member.nbytes));
            if (member.comment)
                appendIndented(out, 2, "comment=" + *member.comment);
            if (member.repeatableComment)
                appendIndented(out, 2, "repeatable_comment=" + *member.repeatableComment);
            if (member.tinfo)
            {
                if (member.tinfo->declaration)
                    appendIndented(out, 2, "declaration=" + *member.tinfo->declaration);
                if (member.tinfo->decodeError)
                    appendIndented(out, 2, "decode_error=" + *member.tinfo->decodeError);
            }
            if (member.infoRepresentation)
            {
                appendIndented(out, 2, "format_flags=" + formatHex(member.infoRepresentation->flags));
                for (const auto& operand : member.infoRepresentation->operands)
                {
                    appendIndented(out, 3, "operand[" + std::to_string(operand.operandIndex) + "] type=" + operand.typeName);
                    if (operand.offsetReference)
                    {
                        appendIndented(out, 4, "target=" + formatHex(operand.offsetReference->target));
                        appendIndented(out, 4, "base=" + formatHex(operand.offsetReference->base));
                        appendIndented(out, 4, "tdelta=" + formatSigned(operand.offsetReference->targetDelta));
                        appendIndented(out, 4, "ri_flags=" + formatHex(operand.offsetReference->flags));
                    }
                }
            }
        }
    }

    if (!metadata.userStackPointEntries.empty())
    {
        appendIndented(out, 0, "User Stack Points");
        for (const auto& point : metadata.userStackPointEntries)
            appendIndented(out, 1, formatChunkLocation(point.functionChunkNumber, point.functionChunkOffset) + " -> delta=" + formatSigned(point.delta));
    }
    else if (metadata.userStackPoints && !metadata.userStackPoints->printableTexts.empty())
    {
        appendIndented(out, 0, "User Stack Points (Printable Fragments)");
        for (const auto& fragment : metadata.userStackPoints->printableTexts)
            appendIndented(out, 1, fragment);
    }

    if (!metadata.instructionOperandRepresentations.empty())
    {
        appendIndented(out, 0, "Operand Representations");
        for (const auto& entry : metadata.instructionOperandRepresentations)
        {
            appendIndented(out, 1, formatChunkLocation(entry.functionChunkNumber, entry.functionChunkOffset) + ", flags=" + formatHex(entry.representation.flags));
            for (const auto& operand : entry.representation.operands)
            {
                appendIndented(out, 2, "operand[" + std::to_string(operand.operandIndex) + "] type=" + operand.typeName + " (0x" + [&]() {
                    std::ostringstream hex;
                    hex << std::hex << std::uppercase << static_cast<unsigned int>(operand.typeBits);
                    return hex.str();
                }() + ")");
                if (operand.offsetReference)
                {
                    appendIndented(out, 3, "target=" + formatHex(operand.offsetReference->target));
                    appendIndented(out, 3, "base=" + formatHex(operand.offsetReference->base));
                    appendIndented(out, 3, "tdelta=" + formatSigned(operand.offsetReference->targetDelta));
                    appendIndented(out, 3, "ri_flags=" + formatHex(operand.offsetReference->flags));
                }
            }
        }
    }
    else
    {
        if (metadata.operandRepresentations && !metadata.operandRepresentations->printableTexts.empty())
        {
            appendIndented(out, 0, "MDK_OPS (Printable Fragments)");
            for (const auto& fragment : metadata.operandRepresentations->printableTexts)
                appendIndented(out, 1, fragment);
        }
        if (metadata.operandRepresentationsEx && !metadata.operandRepresentationsEx->printableTexts.empty())
        {
            appendIndented(out, 0, "MDK_OPS_EX (Printable Fragments)");
            for (const auto& fragment : metadata.operandRepresentationsEx->printableTexts)
                appendIndented(out, 1, fragment);
        }
    }

    if (!metadata.errors.empty())
    {
        appendIndented(out, 0, "Parse Errors");
        for (const auto& error : metadata.errors)
            appendIndented(out, 1, error);
    }

    if (includeRawChunks && !metadata.rawChunks.empty())
    {
        appendIndented(out, 0, "Raw Chunks");
        for (const auto& chunk : metadata.rawChunks)
        {
            appendIndented(out, 1, metadataKeyName(chunk.rawKey) + " size=" + std::to_string(chunk.data.size()));
            if (!chunk.data.empty())
                appendIndented(out, 2, hexPreview(chunk.data.data(), chunk.data.size()));
        }
    }

    return out.str();
}

}  // namespace lumina
