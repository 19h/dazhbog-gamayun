#include "lumina/apply.h"

#include "lumina/type_decoder.h"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <limits>
#include <map>
#include <optional>
#include <sstream>

using BinaryViewRef = BinaryNinja::Ref<BinaryNinja::BinaryView>;
using FunctionRef = lumina::FunctionRef;
using ApplyStats = lumina::ApplyStats;

namespace {

static int64_t reinterpretSignedUint64(uint64_t value)
{
	int64_t signedValue = 0;
	static_assert(sizeof(signedValue) == sizeof(value), "unexpected integer width mismatch");
	std::memcpy(&signedValue, &value, sizeof(signedValue));
	return signedValue;
}

static BinaryNinja::Ref<BinaryNinja::TagType> getOrCreateLuminaTagType(
	BinaryViewRef view,
	const std::string& name,
	const std::string& icon = "L")
{
	if (!view)
		return nullptr;

	auto tagType = view->GetTagTypeByName(name, UserTagType);
	if (tagType)
		return tagType;

	tagType = new BinaryNinja::TagType(view.GetPtr(), name, icon, true, UserTagType);
	view->AddTagType(tagType);
	return tagType;
}

static bool addLuminaFunctionTag(
	FunctionRef func,
	const std::string& tagTypeName,
	const std::string& data,
	ApplyStats& stats)
{
	if (!func || data.empty())
		return false;

	auto tagType = getOrCreateLuminaTagType(func->GetView(), tagTypeName);
	if (!tagType)
		return false;

	auto tag = func->CreateUserFunctionTag(tagType, data, true);
	if (!tag)
		return false;

	stats.tagsApplied++;
	return true;
}

static bool addLuminaAddressTag(
	FunctionRef func,
	uint64_t addr,
	const std::string& tagTypeName,
	const std::string& data,
	ApplyStats& stats)
{
	if (!func || data.empty())
		return false;

	auto arch = func->GetArchitecture();
	if (!arch)
		return false;

	auto tagType = getOrCreateLuminaTagType(func->GetView(), tagTypeName);
	if (!tagType)
		return false;

	auto tag = func->CreateUserAddressTag(arch.GetPtr(), addr, tagType, data, true);
	if (!tag)
		return false;

	stats.tagsApplied++;
	return true;
}

static std::optional<uint64_t> resolveLuminaChunkAddress(
	FunctionRef func,
	uint32_t functionChunkNumber,
	uint32_t functionChunkOffset)
{
	if (!func)
		return std::nullopt;

	auto ranges = func->GetAddressRanges();
	if (ranges.empty())
		return std::nullopt;

	std::sort(ranges.begin(), ranges.end(), [](const BNAddressRange& left, const BNAddressRange& right) {
		if (left.start != right.start)
			return left.start < right.start;
		return left.end < right.end;
	});

	const uint64_t funcStart = func->GetStart();
	auto entryIt = std::find_if(ranges.begin(), ranges.end(), [&](const BNAddressRange& range) {
		return funcStart >= range.start && funcStart < range.end;
	});
	if (entryIt != ranges.end() && entryIt != ranges.begin())
		std::rotate(ranges.begin(), entryIt, entryIt + 1);

	if (functionChunkNumber >= ranges.size())
		return std::nullopt;

	const BNAddressRange& range = ranges[functionChunkNumber];
	const uint64_t rangeSize = range.end > range.start ? (range.end - range.start) : 0;
	if (functionChunkOffset >= rangeSize)
		return std::nullopt;

	uint64_t addr = range.start + functionChunkOffset;
	auto arch = func->GetArchitecture();
	uint64_t instructionStart = addr;
	if (arch && func->GetInstructionContainingAddress(arch.GetPtr(), addr, &instructionStart))
		addr = instructionStart;
	return addr;
}

}  // namespace

std::string lumina::buildMergedFunctionComment(const FunctionMetadata& metadata)
{
	const std::string primary = metadata.functionComment.value_or(std::string());
	const std::string repeatable = metadata.repeatableFunctionComment.value_or(std::string());
	if (primary.empty())
		return repeatable;
	if (repeatable.empty() || repeatable == primary)
		return primary;

	return primary + "\n\n[Lumina Repeatable Comment]\n" + repeatable;
}

static std::string buildMergedAddressComment(
	const std::vector<std::string>& normalComments,
	const std::vector<std::string>& repeatableComments,
	const std::vector<std::string>& previousExtraComments,
	const std::vector<std::string>& nextExtraComments)
{
	if (repeatableComments.empty() && previousExtraComments.empty() && nextExtraComments.empty()
		&& normalComments.size() == 1)
	{
		return normalComments.front();
	}

	std::ostringstream out;
	auto appendSection = [&](const char* label, const std::vector<std::string>& lines) {
		if (lines.empty())
			return;
		if (out.tellp() > 0)
			out << "\n\n";
		out << '[' << label << "]\n";
		for (size_t i = 0; i < lines.size(); ++i)
		{
			if (i != 0)
				out << "\n";
			out << lines[i];
		}
	};

	appendSection("Lumina Comment", normalComments);
	appendSection("Lumina Repeatable Comment", repeatableComments);
	appendSection("Lumina Extra Previous", previousExtraComments);
	appendSection("Lumina Extra Next", nextExtraComments);
	return out.str();
}

static bool parseNamedTypeDeclaration(
	BinaryViewRef view,
	const std::string& declaration,
	BinaryNinja::Ref<BinaryNinja::Type>* outType,
	std::string* error)
{
	if (!view || outType == nullptr)
		return false;

	BinaryNinja::QualifiedNameAndType parsed;
	std::string parseErrors;
	if (!view->ParseTypeString(declaration, parsed, parseErrors))
	{
		if (error != nullptr)
			*error = parseErrors.empty() ? "Binary Ninja type parser rejected declaration" : parseErrors;
		return false;
	}

	*outType = parsed.type;
	return true;
}

static bool parseFunctionTypeFromMetadata(
	FunctionRef func,
	const lumina::MdTypeParts& typeParts,
	BinaryNinja::Ref<BinaryNinja::Type>* outType,
	std::string* error)
{
	const auto rendered = lumina::decodeTinfoDeclWithName(
		typeParts.typeBytes,
		typeParts.fieldsBytes,
		"__lumina_function");
	if (!rendered.ok())
	{
		if (error != nullptr)
			*error = rendered.error;
		return false;
	}
	return parseNamedTypeDeclaration(func->GetView(), rendered.declaration, outType, error);
}

static bool parseStackTypeFromMetadata(
	FunctionRef func,
	const lumina::SerializedTinfo& typeInfo,
	BinaryNinja::Ref<BinaryNinja::Type>* outType,
	std::string* error)
{
	const auto rendered = lumina::decodeTinfoDeclWithName(
		typeInfo.typeBytes,
		typeInfo.fieldsBytes,
		"__lumina_var");
	if (!rendered.ok())
	{
		if (error != nullptr)
			*error = rendered.error;
		return false;
	}
	return parseNamedTypeDeclaration(func->GetView(), rendered.declaration, outType, error);
}

static BinaryNinja::Ref<BinaryNinja::Symbol> buildFunctionRenameSymbol(
	FunctionRef func,
	const std::string& rawName)
{
	if (!func || rawName.empty())
		return nullptr;

	auto view = func->GetView();
	auto arch = view ? view->GetDefaultArchitecture() : nullptr;
	auto currentSymbol = func->GetSymbol();

	BNSymbolType symbolType = FunctionSymbol;
	BNSymbolBinding binding = NoBinding;
	BinaryNinja::NameSpace nameSpace;
	if (currentSymbol)
	{
		symbolType = currentSymbol->GetType();
		binding = currentSymbol->GetBinding();
		nameSpace = currentSymbol->GetNameSpace();
	}

	std::string shortName = rawName;
	std::string fullName = rawName;
	if (arch)
	{
		BinaryNinja::QualifiedName demangledName;
		BinaryNinja::Ref<BinaryNinja::Type> demangledType;
		if (BinaryNinja::DemangleGeneric(arch, rawName, demangledType, demangledName, view, true))
		{
			shortName = demangledName.GetString();
			fullName = shortName;
			if (demangledType)
				fullName += demangledType->GetStringAfterName();
		}
	}

	return new BinaryNinja::Symbol(symbolType, shortName, fullName, rawName, func->GetStart(), binding, nameSpace);
}

static std::vector<int64_t> candidateFrameOffsets(
	const lumina::FrameDescription& frame,
	const lumina::FrameMember& member,
	size_t addressSize)
{
	std::vector<int64_t> offsets;
	if (!member.offset)
		return offsets;

	auto addOffset = [&](int64_t value) {
		if (std::find(offsets.begin(), offsets.end(), value) == offsets.end())
			offsets.push_back(value);
	};

	const uint64_t rawOffset = *member.offset;
	const int64_t signedOffset = reinterpretSignedUint64(rawOffset);
	const int64_t frameSize = static_cast<int64_t>(frame.frameSize);
	const int64_t savedRegisters = static_cast<int64_t>(frame.savedRegistersSize);
	const int64_t pointerSize = static_cast<int64_t>(addressSize == 0 ? 8 : addressSize);
	const int64_t argumentSize = static_cast<int64_t>(frame.argumentSize);

	addOffset(signedOffset);
	if (rawOffset <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
		addOffset(static_cast<int64_t>(rawOffset));

	for (int64_t base : {frameSize, frameSize + savedRegisters, frameSize + savedRegisters + pointerSize,
		frameSize + savedRegisters + pointerSize + argumentSize})
	{
		addOffset(signedOffset - base);
		if (rawOffset <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
			addOffset(static_cast<int64_t>(rawOffset) - base);
	}

	return offsets;
}

static std::optional<int64_t> findBestStackOffset(
	FunctionRef func,
	const lumina::FrameDescription& frame,
	const lumina::FrameMember& member)
{
	if (!func)
		return std::nullopt;

	const auto layout = func->GetStackLayout();
	auto arch = func->GetArchitecture();
	const size_t addressSize = arch ? arch->GetAddressSize() : 8;
	const auto offsets = candidateFrameOffsets(frame, member, addressSize);

	std::optional<int64_t> bestOffset;
	int bestScore = std::numeric_limits<int>::min();
	for (int64_t candidate : offsets)
	{
		int score = 0;
		auto it = layout.find(candidate);
		if (it != layout.end())
			score += 100;

		if (member.offset)
		{
			if (*member.offset < frame.frameSize && candidate < 0)
				score += 10;
			if (*member.offset >= frame.frameSize && candidate >= 0)
				score += 10;
		}

		if (member.nbytes && it != layout.end())
		{
			for (const auto& existing : it->second)
			{
				auto existingType = existing.type.GetValue();
				if (existingType && existingType->GetWidth() == *member.nbytes)
				{
					score += 20;
					break;
				}
			}
		}

		if (score > bestScore)
		{
			bestScore = score;
			bestOffset = candidate;
		}
	}

	if (bestScore < 100)
		return std::nullopt;
	return bestOffset;
}

static std::string formatFrameMemberTagData(const lumina::FrameMember& member)
{
	std::ostringstream out;
	if (member.offset)
		out << "offset=" << *member.offset << "\n";
	if (member.name)
		out << "name=" << *member.name << "\n";
	if (member.nbytes)
		out << "nbytes=" << *member.nbytes << "\n";
	if (member.tinfo)
	{
		if (member.tinfo->declaration)
			out << "type=" << *member.tinfo->declaration << "\n";
		if (member.tinfo->decodeError)
			out << "type_decode_error=" << *member.tinfo->decodeError << "\n";
	}
	if (member.comment)
		out << "comment=" << *member.comment << "\n";
	if (member.repeatableComment)
		out << "repeatable_comment=" << *member.repeatableComment << "\n";
	if (member.infoRepresentation)
		out << "operand_repr_flags=0x" << std::hex << std::uppercase << member.infoRepresentation->flags << std::dec << "\n";
	return out.str();
}

static std::string formatOperandRepresentationTagData(const lumina::InstructionOperandRepresentation& entry)
{
	std::ostringstream out;
	out << "chunk=" << entry.functionChunkNumber << " off=0x" << std::hex << std::uppercase
		<< entry.functionChunkOffset << std::dec << '\n';
	out << "flags=0x" << std::hex << std::uppercase << entry.representation.flags << std::dec;
	for (const auto& operand : entry.representation.operands)
	{
		out << "\noperand[" << operand.operandIndex << "]=" << operand.typeName;
		if (operand.offsetReference)
		{
			out << " target=0x" << std::hex << std::uppercase << operand.offsetReference->target
				<< " base=0x" << operand.offsetReference->base
				<< std::dec << " tdelta=" << operand.offsetReference->targetDelta
				<< " ri_flags=0x" << std::hex << std::uppercase << operand.offsetReference->flags << std::dec;
		}
	}
	return out.str();
}

// Helper to apply Lumina metadata to a single function
// Returns true if any metadata was applied
bool lumina::applyMetadata(
	FunctionRef func,
	const PullCacheEntry& cache,
	ApplyStats& stats)
{
	bool applied = false;
	auto view = func->GetView();

	if (!func || !view)
		return false;

	// Apply function name if available and different from current
	if (!cache.remoteName.empty()) {
		std::string currentName = func->GetSymbol() ? func->GetSymbol()->GetShortName() : "";
		std::string currentRawName = func->GetSymbol() ? func->GetSymbol()->GetRawName() : "";
		// Only rename if current name is auto-generated (sub_*, func_*, etc.) or empty
		bool isAutoName = currentName.empty() ||
		                  currentName.find("sub_") == 0 ||
		                  currentName.find("func_") == 0 ||
		                  currentName.find("j_") == 0;
		if (isAutoName || currentRawName != cache.remoteName) {
			auto sym = buildFunctionRenameSymbol(func, cache.remoteName);
			if (sym)
			{
				view->DefineUserSymbol(sym);
				stats.namesApplied++;
				applied = true;
				BinaryNinja::LogInfo("[Lumina] Renamed 0x%llx: %s -> %s",
					(unsigned long long)func->GetStart(),
					currentName.c_str(), cache.remoteName.c_str());
			}
		}
	}

	const std::string remoteComment = buildMergedFunctionComment(cache.metadata);
	if (!remoteComment.empty()) {
		std::string currentComment = func->GetComment();
		if (currentComment != remoteComment) {
			func->SetComment(remoteComment);
			stats.functionCommentsApplied++;
			applied = true;
		}
	}

	if (cache.metadata.typeParts)
	{
		BinaryNinja::Ref<BinaryNinja::Type> parsedType;
		std::string typeError;
		if (parseFunctionTypeFromMetadata(func, *cache.metadata.typeParts, &parsedType, &typeError) && parsedType)
		{
			auto currentType = func->GetType();
			const std::string currentTypeString = currentType ? currentType->GetString() : std::string();
			const std::string parsedTypeString = parsedType->GetString();
			if (currentTypeString != parsedTypeString)
			{
				func->SetUserType(parsedType.GetPtr());
				stats.functionTypesApplied++;
				applied = true;
			}
		}
		else if (!typeError.empty())
		{
			std::string tagData = typeError;
			if (cache.metadata.typeParts->declaration)
				tagData += "\n\nDeclaration:\n" + *cache.metadata.typeParts->declaration;
			if (addLuminaFunctionTag(func, "Lumina Type", tagData, stats))
				applied = true;
		}
	}

	if (cache.metadata.vdElapsed)
	{
		std::string tagData = "vd_elapsed=" + std::to_string(*cache.metadata.vdElapsed);
		if (addLuminaFunctionTag(func, "Lumina Info", tagData, stats))
			applied = true;
	}

	if (cache.metadata.frameDescription)
	{
		const auto layout = func->GetStackLayout();
		for (const auto& member : cache.metadata.frameDescription->members)
		{
			bool memberApplied = false;
			auto stackOffset = findBestStackOffset(func, *cache.metadata.frameDescription, member);
			if (stackOffset)
			{
				auto existingIt = layout.find(*stackOffset);
				std::string variableName = member.name.value_or(std::string());
				BinaryNinja::Ref<BinaryNinja::Type> variableType;
				std::string typeError;
				if (member.tinfo)
					parseStackTypeFromMetadata(func, *member.tinfo, &variableType, &typeError);

				if (existingIt != layout.end() && !existingIt->second.empty())
				{
					const auto& existing = existingIt->second.front();
					if (variableName.empty())
						variableName = existing.name;
					if (!variableType && existing.type.GetValue())
						variableType = existing.type.GetValue();
				}

				if (!variableType && member.nbytes)
					variableType = BinaryNinja::Type::IntegerType(*member.nbytes, false);

				if (variableType && !variableName.empty())
				{
					func->CreateUserStackVariable(
						*stackOffset,
						BinaryNinja::Confidence<BinaryNinja::Ref<BinaryNinja::Type>>(variableType),
						variableName);
					stats.stackVariablesApplied++;
					applied = true;
					memberApplied = true;
				}
				else if (!typeError.empty())
				{
					std::string tagData = "stack_offset=" + std::to_string(*stackOffset) + "\n" + typeError;
					if (addLuminaFunctionTag(func, "Lumina Frame", tagData, stats))
						applied = true;
				}
			}

			if (!memberApplied && (member.comment || member.repeatableComment || member.infoRepresentation || member.tinfo))
			{
				if (addLuminaFunctionTag(func, "Lumina Frame", formatFrameMemberTagData(member), stats))
					applied = true;
			}
		}
	}

	struct AddressMetadataBundle
	{
		std::vector<std::string> normalComments;
		std::vector<std::string> repeatableComments;
		std::vector<std::string> previousExtraComments;
		std::vector<std::string> nextExtraComments;
	};
	std::map<uint64_t, AddressMetadataBundle> bundles;

	for (const auto& comment : cache.metadata.instructionComments)
	{
		auto addr = resolveLuminaChunkAddress(func, comment.functionChunkNumber, comment.functionChunkOffset);
		if (!addr)
		{
			if (addLuminaFunctionTag(func, "Lumina Comment", comment.comment, stats))
				applied = true;
			continue;
		}
		bundles[*addr].normalComments.push_back(comment.comment);
	}

	for (const auto& comment : cache.metadata.repeatableInstructionComments)
	{
		auto addr = resolveLuminaChunkAddress(func, comment.functionChunkNumber, comment.functionChunkOffset);
		if (!addr)
		{
			if (addLuminaFunctionTag(func, "Lumina Comment", comment.comment, stats))
				applied = true;
			continue;
		}
		bundles[*addr].repeatableComments.push_back(comment.comment);
	}

	for (const auto& comment : cache.metadata.extraCommentEntries)
	{
		auto addr = resolveLuminaChunkAddress(func, comment.functionChunkNumber, comment.functionChunkOffset);
		if (!addr)
		{
			if (addLuminaFunctionTag(func, "Lumina Comment", comment.previous + "\n" + comment.next, stats))
				applied = true;
			continue;
		}
		if (!comment.previous.empty())
			bundles[*addr].previousExtraComments.push_back(comment.previous);
		if (!comment.next.empty())
			bundles[*addr].nextExtraComments.push_back(comment.next);
	}

	for (const auto& [addr, bundle] : bundles)
	{
		const std::string mergedComment = buildMergedAddressComment(
			bundle.normalComments,
			bundle.repeatableComments,
			bundle.previousExtraComments,
			bundle.nextExtraComments);
		if (mergedComment.empty())
			continue;

		if (func->GetCommentForAddress(addr) != mergedComment)
		{
			func->SetCommentForAddress(addr, mergedComment);
			stats.addressCommentsApplied++;
			applied = true;
		}
	}

	for (const auto& point : cache.metadata.userStackPointEntries)
	{
		std::ostringstream data;
		data << "chunk=" << point.functionChunkNumber
			<< " off=0x" << std::hex << std::uppercase << point.functionChunkOffset << std::dec
			<< " delta=" << point.delta;

		auto addr = resolveLuminaChunkAddress(func, point.functionChunkNumber, point.functionChunkOffset);
		if (addr)
		{
			if (addLuminaAddressTag(func, *addr, "Lumina Stack Point", data.str(), stats))
				applied = true;
		}
		else if (addLuminaFunctionTag(func, "Lumina Stack Point", data.str(), stats))
		{
			applied = true;
		}
	}
	if (cache.metadata.userStackPointEntries.empty() && cache.metadata.userStackPoints
		&& !cache.metadata.userStackPoints->printableTexts.empty())
	{
		std::ostringstream tagData;
		for (size_t i = 0; i < cache.metadata.userStackPoints->printableTexts.size(); ++i)
		{
			if (i != 0)
				tagData << '\n';
			tagData << cache.metadata.userStackPoints->printableTexts[i];
		}
		if (addLuminaFunctionTag(func, "Lumina Stack Point", tagData.str(), stats))
			applied = true;
	}

	for (const auto& entry : cache.metadata.instructionOperandRepresentations)
	{
		auto addr = resolveLuminaChunkAddress(func, entry.functionChunkNumber, entry.functionChunkOffset);
		const std::string tagData = formatOperandRepresentationTagData(entry);
		if (addr)
		{
			if (addLuminaAddressTag(func, *addr, "Lumina Operand", tagData, stats))
				applied = true;
		}
		else if (addLuminaFunctionTag(func, "Lumina Operand", tagData, stats))
		{
			applied = true;
		}
	}
	if (cache.metadata.instructionOperandRepresentations.empty())
	{
		if (cache.metadata.operandRepresentations && !cache.metadata.operandRepresentations->printableTexts.empty())
		{
			std::ostringstream tagData;
			for (size_t i = 0; i < cache.metadata.operandRepresentations->printableTexts.size(); ++i)
			{
				if (i != 0)
					tagData << '\n';
				tagData << cache.metadata.operandRepresentations->printableTexts[i];
			}
			if (addLuminaFunctionTag(func, "Lumina Operand", tagData.str(), stats))
				applied = true;
		}
		if (cache.metadata.operandRepresentationsEx && !cache.metadata.operandRepresentationsEx->printableTexts.empty())
		{
			std::ostringstream tagData;
			for (size_t i = 0; i < cache.metadata.operandRepresentationsEx->printableTexts.size(); ++i)
			{
				if (i != 0)
					tagData << '\n';
				tagData << cache.metadata.operandRepresentationsEx->printableTexts[i];
			}
			if (addLuminaFunctionTag(func, "Lumina Operand", tagData.str(), stats))
				applied = true;
		}
	}
	if (cache.metadata.extraCommentEntries.empty() && !cache.metadata.extraComments.empty())
	{
		std::ostringstream tagData;
		for (size_t i = 0; i < cache.metadata.extraComments.size(); ++i)
		{
			if (i != 0)
				tagData << '\n';
			tagData << cache.metadata.extraComments[i];
		}
		if (addLuminaFunctionTag(func, "Lumina Comment", tagData.str(), stats))
			applied = true;
	}

	if (!cache.metadata.errors.empty())
	{
		std::ostringstream errorData;
		for (size_t i = 0; i < cache.metadata.errors.size(); ++i)
		{
			if (i != 0)
				errorData << '\n';
			errorData << cache.metadata.errors[i];
		}
		if (addLuminaFunctionTag(func, "Lumina Parse Issues", errorData.str(), stats))
			applied = true;
	}

	return applied;
}
