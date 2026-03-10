#include "lumina/pulled_metadata.h"

#include "binaryninjaapi.h"

#include <iomanip>
#include <sstream>

lumina::FunctionMetadata lumina::parsePulledMetadata(const std::vector<uint8_t>& raw, uint64_t address)
{
	lumina::FunctionMetadata metadata = lumina::parseFunctionMetadata(raw);
	if (!metadata.ok())
	{
		for (const auto& error : metadata.errors)
		{
			BinaryNinja::LogWarn("[Lumina] Metadata parse issue for 0x%llx: %s",
				(unsigned long long)address,
				error.c_str());
		}
	}
	return metadata;
}

std::string lumina::formatPulledMetadataReport(
	uint64_t address,
	const PullCacheEntry& cache)
{
	std::ostringstream out;
	out << "Address: 0x" << std::hex << std::uppercase << address << std::dec << "\n";
	out << "Remote Name: " << (cache.remoteName.empty() ? "<unnamed>" : cache.remoteName) << "\n";
	out << "Popularity: " << cache.popularity << "\n";
	out << "Remote Length: " << cache.len << "\n";
	out << "Raw Metadata Size: " << cache.raw.size() << " bytes\n\n";
	out << lumina::formatFunctionMetadata(cache.metadata, true);
	return out.str();
	}
