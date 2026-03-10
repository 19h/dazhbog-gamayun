#pragma once

#include "lumina_protocol.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace lumina {

struct MdTypeParts {
    bool userti = false;
    std::vector<uint8_t> typeBytes;
    std::vector<uint8_t> fieldsBytes;
    std::optional<std::string> declaration;
    std::optional<std::string> decodeError;
};

struct SerializedTinfo {
    std::vector<uint8_t> typeBytes;
    std::vector<uint8_t> fieldsBytes;
    std::optional<std::string> declaration;
    std::optional<std::string> decodeError;
};

struct FrameMember {
    std::optional<std::string> name;
    std::optional<SerializedTinfo> tinfo;
    std::optional<std::string> comment;
    std::optional<std::string> repeatableComment;
    std::optional<uint64_t> offset;
    std::optional<std::vector<uint8_t>> info;
    std::optional<uint64_t> nbytes;
};

struct FrameDescription {
    uint64_t frameSize = 0;
    uint64_t argumentSize = 0;
    uint16_t savedRegistersSize = 0;
    std::vector<FrameMember> members;
};

struct InstructionComment {
    uint32_t functionChunkNumber = 0;
    uint32_t functionChunkOffset = 0;
    std::string comment;
};

struct MetadataChunk {
    uint32_t rawKey = 0;
    MetadataKey key = MetadataKey::None;
    std::vector<uint8_t> data;
};

struct OpaqueMetadataBlob {
    std::vector<uint8_t> raw;
    std::vector<std::string> printableTexts;
};

struct FunctionMetadata {
    size_t rawSize = 0;
    std::vector<MetadataChunk> rawChunks;
    std::optional<MdTypeParts> typeParts;
    std::optional<FrameDescription> frameDescription;
    std::optional<uint64_t> vdElapsed;
    std::optional<std::string> functionComment;
    std::optional<std::string> repeatableFunctionComment;
    std::vector<InstructionComment> instructionComments;
    std::vector<InstructionComment> repeatableInstructionComments;
    std::vector<std::string> extraComments;
    std::optional<OpaqueMetadataBlob> userStackPoints;
    std::optional<OpaqueMetadataBlob> operandRepresentations;
    std::optional<OpaqueMetadataBlob> operandRepresentationsEx;
    size_t bytesParsed = 0;
    std::vector<std::string> errors;

    bool ok() const;
    size_t componentCount() const;
    bool hasChunk(MetadataKey key) const;
    const MetadataChunk* chunk(MetadataKey key) const;
    std::optional<std::string> effectiveFunctionComment() const;
};

FunctionMetadata parseFunctionMetadata(const std::vector<uint8_t>& data);
std::vector<MetadataChunk> splitMetadataChunks(const std::vector<uint8_t>& data);
std::vector<uint8_t> serializeMetadataChunks(const std::vector<MetadataChunk>& chunks);
std::string metadataKeyName(uint32_t rawKey);

}  // namespace lumina
