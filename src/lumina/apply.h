#pragma once

#include "binaryninjaapi.h"
#include "lumina/metadata.h"
#include "lumina/pulled_metadata.h"

#include <cstddef>
#include <string>

namespace lumina {

using FunctionRef = BinaryNinja::Ref<BinaryNinja::Function>;

struct ApplyStats {
    size_t namesApplied = 0;
    size_t functionCommentsApplied = 0;
    size_t functionTypesApplied = 0;
    size_t addressCommentsApplied = 0;
    size_t stackVariablesApplied = 0;
    size_t tagsApplied = 0;
};

std::string buildMergedFunctionComment(const FunctionMetadata& metadata);
bool applyMetadata(FunctionRef func, const PullCacheEntry& cache, ApplyStats& stats);

}  // namespace lumina
