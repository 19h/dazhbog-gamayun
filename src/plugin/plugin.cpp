#include "ui/gamayun/gamayun.h"

#include "analysis/pattern_gen.h"
#include "lumina/apply.h"
#include "lumina/codec.h"
#include "lumina/pulled_metadata.h"
#include "lumina/session.h"
#include "lumina/settings.h"

#include <cstdio>

class View;

// Lumina metadata extraction and logging
void extractAndLogLuminaMetadata(BinaryViewRef data, ViewFrame* frame)
{
	// Print to both stderr (terminal) and Binary Ninja log
	fprintf(stderr, "\n========================================\n");
	fprintf(stderr, "LUMINA METADATA EXTRACTION STARTED\n");
	fprintf(stderr, "========================================\n");

	if (!data)
	{
		fprintf(stderr, "ERROR: No binary view available\n");
		BinaryNinja::LogInfo("No binary view available");
		return;
	}

	auto functions = data->GetAnalysisFunctionList();
	if (functions.empty())
	{
		fprintf(stderr, "ERROR: No functions found in binary\n");
		BinaryNinja::LogInfo("No functions found in binary");
		return;
	}

	// Get the current function if available, otherwise use the first function
	FunctionRef func;
	uint64_t funcStart;
	if (frame)
	{
		View* currentView = frame->getCurrentViewInterface();
		if (currentView && currentView->getCurrentFunction())
		{
			func = currentView->getCurrentFunction();
			funcStart = func->GetStart();
			fprintf(stderr, "\n=== LUMINA METADATA EXTRACTION FOR CURRENT FUNCTION ===\n");
			fprintf(stderr, "Function Address: 0x%llx\n", (unsigned long long)funcStart);
			BinaryNinja::LogInfo("=== LUMINA METADATA EXTRACTION FOR CURRENT FUNCTION ===");
			BinaryNinja::LogInfo("Function Address: 0x%llx", (unsigned long long)funcStart);
		}
		else
		{
			// Fallback to first function if no current function
			func = functions[0];
			funcStart = func->GetStart();
			fprintf(stderr, "\n=== LUMINA METADATA EXTRACTION FOR FIRST FUNCTION (no current function) ===\n");
			fprintf(stderr, "Function Address: 0x%llx\n", (unsigned long long)funcStart);
			BinaryNinja::LogInfo("=== LUMINA METADATA EXTRACTION FOR FIRST FUNCTION (no current function) ===");
			BinaryNinja::LogInfo("Function Address: 0x%llx", (unsigned long long)funcStart);
		}
	}
	else
	{
		// Fallback to first function if no frame
		func = functions[0];
		funcStart = func->GetStart();
		fprintf(stderr, "\n=== LUMINA METADATA EXTRACTION FOR FIRST FUNCTION (no frame) ===\n");
		fprintf(stderr, "Function Address: 0x%llx\n", (unsigned long long)funcStart);
		BinaryNinja::LogInfo("=== LUMINA METADATA EXTRACTION FOR FIRST FUNCTION (no frame) ===");
		BinaryNinja::LogInfo("Function Address: 0x%llx", (unsigned long long)funcStart);
	}
	
	// 1. FUNCTION IDENTITY
	auto symbol = func->GetSymbol();
	std::string funcName = symbol ? symbol->GetFullName() : "<unnamed>";
	fprintf(stderr, "\n[1] FUNCTION IDENTITY:\n");
	fprintf(stderr, "  Name: %s\n", funcName.c_str());
	fprintf(stderr, "  Start: 0x%llx\n", (unsigned long long)funcStart);
	uint64_t funcSize = func->GetHighestAddress() - funcStart;
	fprintf(stderr, "  Size: %llu bytes (approx)\n", (unsigned long long)funcSize);
	
	BinaryNinja::LogInfo("[1] FUNCTION IDENTITY:");
	BinaryNinja::LogInfo("  Name: %s", funcName.c_str());
	BinaryNinja::LogInfo("  Start: 0x%llx", (unsigned long long)funcStart);
	BinaryNinja::LogInfo("  Size: %llu bytes (approx)", (unsigned long long)funcSize);
	
	// 2. FUNCTION TYPE INFO
	fprintf(stderr, "\n[2] FUNCTION TYPE INFO:\n");
	fprintf(stderr, "  No-return flag: %s\n", func->CanReturn() ? "false" : "true");
	BinaryNinja::LogInfo("[2] FUNCTION TYPE INFO:");
	BinaryNinja::LogInfo("  No-return flag: %s", func->CanReturn() ? "false" : "true");
	
	// 3. FUNCTION COMMENTS
	fprintf(stderr, "\n[3] FUNCTION COMMENTS:\n");
	std::string funcComment = func->GetComment();
	if (!funcComment.empty())
	{
		fprintf(stderr, "  Function comment: %s\n", funcComment.c_str());
		BinaryNinja::LogInfo("  Function comment: %s", funcComment.c_str());
	}
	else
	{
		fprintf(stderr, "  No function comment\n");
		BinaryNinja::LogInfo("  No function comment");
	}
	
	// 4. BASIC BLOCKS INFO
	fprintf(stderr, "\n[4] BASIC BLOCKS:\n");
	auto blocks = func->GetBasicBlocks();
	fprintf(stderr, "  Block count: %zu\n", blocks.size());
	BinaryNinja::LogInfo("[4] BASIC BLOCKS:");
	BinaryNinja::LogInfo("  Block count: %zu", blocks.size());
	
	for (size_t i = 0; i < std::min((size_t)3, blocks.size()); i++)
	{
		auto block = blocks[i];
		uint64_t blockSize = block->GetEnd() - block->GetStart();
		fprintf(stderr, "    Block %zu: 0x%llx - 0x%llx (%llu bytes)\n",
		        i,
		        (unsigned long long)block->GetStart(),
		        (unsigned long long)block->GetEnd(),
		        (unsigned long long)blockSize);
		BinaryNinja::LogInfo("    Block %zu: 0x%llx - 0x%llx (%llu bytes)",
		        i,
		        (unsigned long long)block->GetStart(),
		        (unsigned long long)block->GetEnd(),
		        (unsigned long long)blockSize);
	}
	
	// 5. VARIABLES
	fprintf(stderr, "\n[5] STACK FRAME / VARIABLES:\n");
	auto vars = func->GetVariables();
	fprintf(stderr, "  Variable count: %zu\n", vars.size());
	BinaryNinja::LogInfo("[5] STACK FRAME / VARIABLES:");
	BinaryNinja::LogInfo("  Variable count: %zu", vars.size());
	
	// 6. CROSS REFERENCES
	fprintf(stderr, "\n[6] CROSS REFERENCES:\n");
	auto callSites = func->GetCallSites();
	fprintf(stderr, "  Call sites: %zu locations\n", callSites.size());
	BinaryNinja::LogInfo("[6] CROSS REFERENCES:");
	BinaryNinja::LogInfo("  Call sites: %zu locations", callSites.size());

	// 7. DECOMPILED CODE (HLIL)
	fprintf(stderr, "\n[7] DECOMPILED CODE (HLIL):\n");
	auto hlil = func->GetHighLevelIL();
	if (hlil)
	{
		// Get the root expression index directly using C API
		size_t rootExprIndex = BNGetHighLevelILRootExpr(hlil->GetObject());
		auto lines = hlil->GetExprText(rootExprIndex);
		std::string hlilStr;
		for (const auto& line : lines)
		{
			for (const auto& token : line.tokens)
			{
				hlilStr += token.text;
			}
			hlilStr += "\n";
		}
		fprintf(stderr, "  HLIL Code:\n%s", hlilStr.c_str());
		BinaryNinja::LogInfo("[7] DECOMPILED CODE (HLIL):");
		BinaryNinja::LogInfo("  HLIL Code:\n%s", hlilStr.c_str());
	}
	else
	{
		fprintf(stderr, "  No HLIL available\n");
		BinaryNinja::LogInfo("[7] DECOMPILED CODE (HLIL):");
		BinaryNinja::LogInfo("  No HLIL available");
	}

	// 8. LUMINA CALCREL PATTERN GENERATION
	fprintf(stderr, "\n[8] LUMINA CALCREL PATTERN GENERATION:\n");
	BinaryNinja::LogInfo("[8] LUMINA CALCREL PATTERN GENERATION:");

	// Generate pattern with full details
	lumina::PatternResult pattern = lumina::computePattern(data, func);

	if (pattern.success)
	{
		// Print CalcRel hash
		std::string hashStr;
		for (size_t i = 0; i < pattern.hash.size(); i++)
		{
			char hexByte[4];
			snprintf(hexByte, sizeof(hexByte), "%02x", pattern.hash[i]);
			hashStr += hexByte;
		}
		fprintf(stderr, "  CalcRel Hash: %s\n", hashStr.c_str());
		fprintf(stderr, "  Function Size: %u bytes\n", pattern.func_size);
		fprintf(stderr, "  Normalized Bytes: %zu bytes\n", pattern.normalized.size());
		fprintf(stderr, "  Hash = MD5(normalized || masks) [IDA-compatible]\n");
		BinaryNinja::LogInfo("  CalcRel Hash: %s", hashStr.c_str());
		BinaryNinja::LogInfo("  Function Size: %u bytes", pattern.func_size);
		BinaryNinja::LogInfo("  Normalized Bytes: %zu bytes", pattern.normalized.size());
		BinaryNinja::LogInfo("  Hash = MD5(normalized || masks) [IDA-compatible]");

		// Show first 64 bytes of normalized data
		fprintf(stderr, "\n  Normalized bytes (first 64):\n");
		BinaryNinja::LogInfo("  Normalized bytes (first 64):");
		const size_t bytesPerLine = 16;
		const size_t maxShow = std::min(pattern.normalized.size(), (size_t)64);
		for (size_t i = 0; i < maxShow; i += bytesPerLine)
		{
			char line[256];
			int pos = snprintf(line, sizeof(line), "    %04zx: ", i);
			size_t lineEnd = std::min(i + bytesPerLine, maxShow);
			for (size_t j = i; j < lineEnd; j++)
			{
				pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", pattern.normalized[j]);
			}
			fprintf(stderr, "%s\n", line);
			BinaryNinja::LogInfo("%s", line);
		}

		// Show mask bytes for same range
		fprintf(stderr, "\n  Mask bytes (first 64, 0xFF=masked, 0x00=kept):\n");
		BinaryNinja::LogInfo("  Mask bytes (first 64, 0xFF=masked, 0x00=kept):");
		for (size_t i = 0; i < maxShow && i < pattern.masks.size(); i += bytesPerLine)
		{
			char line[256];
			int pos = snprintf(line, sizeof(line), "    %04zx: ", i);
			size_t lineEnd = std::min(i + bytesPerLine, std::min(maxShow, pattern.masks.size()));
			for (size_t j = i; j < lineEnd; j++)
			{
				pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", pattern.masks[j]);
			}
			fprintf(stderr, "%s\n", line);
			BinaryNinja::LogInfo("%s", line);
		}
	}
	else
	{
		fprintf(stderr, "  Pattern generation failed: %s\n", pattern.error.c_str());
		BinaryNinja::LogInfo("  Pattern generation failed: %s", pattern.error.c_str());
	}

	// 9. PUSH ENCODING STATUS
	fprintf(stderr, "\n[9] PUSH ENCODING STATUS:\n");
	fprintf(stderr, "  Push support is intentionally disabled in this plugin.\n");
	fprintf(stderr, "  Local Binary Ninja metadata is not serialized for Lumina upload.\n");
	BinaryNinja::LogInfo("[9] PUSH ENCODING STATUS:");
	BinaryNinja::LogInfo("  Push support is intentionally disabled in this plugin.");
	BinaryNinja::LogInfo("  Local Binary Ninja metadata is not serialized for Lumina upload.");

	fprintf(stderr, "\n=== END LUMINA METADATA EXTRACTION ===\n");
	fprintf(stderr, "Plugin successfully extracted basic Lumina-relevant metadata\n");
	fprintf(stderr, "========================================\n\n");
	fflush(stderr);

	BinaryNinja::LogInfo("=== END LUMINA METADATA EXTRACTION ===");
	BinaryNinja::LogInfo("Plugin successfully extracted basic Lumina-relevant metadata");
}

// Helper to compute CalcRel hash for a function and return as hex string
static std::string computeHashString(BinaryViewRef bvRef, FunctionRef func)
{
	lumina::PatternResult pattern = lumina::computePattern(bvRef, func);
	if (!pattern.success)
		return "";

	char hashStr[33];
	for (int i = 0; i < 16; i++)
		snprintf(hashStr + i * 2, 3, "%02x", pattern.hash[i]);
	return std::string(hashStr);
}

// Auto-query Lumina server for Gamayun metadata
static void autoQueryLumina(BinaryNinja::BinaryView* view)
{
	BinaryNinja::LogInfo("[Lumina] Auto-querying Lumina server for function metadata...");

	BinaryViewRef bvRef = view;
	auto functions = view->GetAnalysisFunctionList();
	if (functions.empty())
	{
		BinaryNinja::LogInfo("[Lumina] No functions to query");
		return;
	}

	// Build hash list
	std::vector<std::array<uint8_t, 16>> hashes;
	std::vector<uint64_t> addrs;
	std::vector<FunctionRef> funcRefs;
	size_t skippedCount = 0;

	for (auto& func : functions)
	{
		auto pullFilter = lumina::shouldSkipPull(bvRef, func);
		if (pullFilter.shouldSkip)
		{
			skippedCount++;
			BinaryNinja::LogDebug("[Lumina] Auto-query filter: skipping %s - %s",
				func->GetSymbol() ? func->GetSymbol()->GetShortName().c_str() : "<unnamed>",
				pullFilter.reason.c_str());
			continue;
		}

		lumina::PatternResult pattern = lumina::computePattern(bvRef, func);
		if (pattern.success)
		{
			hashes.push_back(pattern.hash);
			addrs.push_back(func->GetStart());
			funcRefs.push_back(func);
		}
	}

	if (hashes.empty())
	{
		BinaryNinja::LogInfo("[Lumina] No valid function hashes to query");
		return;
	}

	if (skippedCount > 0)
	{
		BinaryNinja::LogInfo("[Lumina] Auto-query filter: skipped %zu function(s)", skippedCount);
	}

	BinaryNinja::LogInfo("[Lumina] Querying %zu functions from server %s:%d (TLS: %s)",
		hashes.size(),
		lumina::getHost().c_str(),
		lumina::getPort(),
		lumina::useTls() ? "yes" : "no");

	const auto hello = lumina::build_hello_request();
	const auto pull = lumina::build_pull_request(0, hashes);

	auto cli = lumina::createConfiguredClient(nullptr);
	QString err;
	std::vector<lumina::OperationResult> statuses;
	std::vector<lumina::PulledFunction> pulledFuncs;

	int timeout = lumina::getTimeoutMs();
	if (!cli->helloAndPull(hello, pull, &err, &statuses, &pulledFuncs, timeout))
	{
		BinaryNinja::LogError("[Lumina] Auto-query failed: %s", err.toStdString().c_str());
		return;
	}

	// Apply results
	size_t fi = 0, applied = 0;
	lumina::ApplyStats stats;
	for (size_t i = 0; i < statuses.size() && i < addrs.size(); ++i)
	{
		if (statuses[i] == lumina::OperationResult::Ok && fi < pulledFuncs.size())
		{
			const auto& pf = pulledFuncs[fi++];
			FunctionRef func = funcRefs[i];

			lumina::PullCacheEntry cache;
			cache.have = true;
			cache.metadata = lumina::parsePulledMetadata(pf.data, func->GetStart());
			cache.popularity = pf.popularity;
			cache.len = pf.len;
			cache.remoteName = pf.name;
			cache.raw = pf.data;

			if (lumina::applyMetadata(func, cache, stats))
				applied++;
		}
	}

	BinaryNinja::LogInfo("[Lumina] ========================================");
	BinaryNinja::LogInfo(
		"[Lumina] Auto-query complete: %zu queried, %zu found, %zu applied (%zu names, %zu function comments, %zu function types, %zu address comments, %zu stack vars, %zu tags)",
		hashes.size(),
		pulledFuncs.size(),
		applied,
		stats.namesApplied,
		stats.functionCommentsApplied,
		stats.functionTypesApplied,
		stats.addressCommentsApplied,
		stats.stackVariablesApplied,
		stats.tagsApplied);
	BinaryNinja::LogInfo("[Lumina] ========================================");
}

// Global callback for when initial analysis completes on any binary view
static void onInitialAnalysisComplete(BinaryNinja::BinaryView* view)
{
	if (!view)
		return;

	BinaryNinja::LogInfo("[Lumina] ========================================");
	BinaryNinja::LogInfo("[Lumina] Initial analysis complete - computing CalcRel for all functions");
	BinaryNinja::LogInfo("[Lumina] ========================================");

	auto functions = view->GetAnalysisFunctionList();
	if (functions.empty())
	{
		BinaryNinja::LogInfo("[Lumina] No functions found in binary");
		return;
	}

	BinaryNinja::LogInfo("[Lumina] Computing CalcRel for %zu functions...", functions.size());

	// Create a BinaryViewRef from the raw pointer
	BinaryViewRef bvRef = view;

	size_t success = 0;
	size_t failed = 0;

	for (auto& func : functions)
	{
		std::string funcName = func->GetSymbol() ? func->GetSymbol()->GetFullName() : "<unnamed>";
		uint64_t funcStart = func->GetStart();

		lumina::PatternResult pattern = lumina::computePattern(bvRef, func);

		if (pattern.success)
		{
			char hashStr[33];
			for (int i = 0; i < 16; i++)
			{
				snprintf(hashStr + i * 2, 3, "%02x", pattern.hash[i]);
			}

			BinaryNinja::LogInfo("[Lumina] 0x%08llx | %s | %s | %u bytes",
				(unsigned long long)funcStart,
				hashStr,
				funcName.c_str(),
				pattern.func_size);
			success++;
		}
		else
		{
			BinaryNinja::LogWarn("[Lumina] 0x%08llx | FAILED: %s | %s",
				(unsigned long long)funcStart,
				pattern.error.c_str(),
				funcName.c_str());
			failed++;
		}
	}

	BinaryNinja::LogInfo("[Lumina] ========================================");
	BinaryNinja::LogInfo("[Lumina] Completed: %zu succeeded, %zu failed", success, failed);
	BinaryNinja::LogInfo("[Lumina] ========================================");

	// Auto-query Lumina if enabled in settings
	if (lumina::autoQueryOnAnalysis())
	{
		autoQueryLumina(view);
	}
}

// Plugin initialization
extern "C"
{
	BN_DECLARE_UI_ABI_VERSION

	BINARYNINJAPLUGIN bool UIPluginInit()
	{
		// Register Lumina settings
		lumina::registerSettings();

		// Register the widget type
		Sidebar::addSidebarWidgetType(new GamayunWidgetType());

		// Register global callback for when initial analysis completes on any binary
		BinaryNinja::BinaryViewType::RegisterBinaryViewInitialAnalysisCompletionEvent(onInitialAnalysisComplete);

		BinaryNinja::LogInfo("[Lumina] Gamayun plugin loaded");
		BinaryNinja::LogInfo("[Lumina] Server: %s:%d (TLS: %s, Verify: %s)",
			lumina::getHost().c_str(),
			lumina::getPort(),
			lumina::useTls() ? "yes" : "no",
			lumina::verifyTls() ? "yes" : "no");
		BinaryNinja::LogInfo("[Lumina] Auto-query: %s", lumina::autoQueryOnAnalysis() ? "enabled" : "disabled");

		return true;
	}
}
