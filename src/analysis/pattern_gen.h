#pragma once
/**
 * pattern_gen.h - Lumina-compatible function-hash generation for Binary Ninja
 *
 * This module implements the Lumina function signature algorithm which computes
 * a 16-byte MD5 hash that uniquely identifies a function's code pattern.
 *
 * Algorithm (matching IDA's implementation):
 *   1. For each instruction byte:
 *      - normalized_byte = raw_byte & ~mask_byte
 *      Where mask_byte: 0x00 = keep, 0xFF = mask out (position-dependent)
 *
 *   2. Compute hash = MD5(normalized_bytes || mask_bytes)
 *      The hash is over the concatenation of normalized bytes and mask bytes.
 *
 * This produces the same signature as IDA's Lumina, enabling cross-tool
 * function matching.
 */

#include <vector>
#include <array>
#include <cstdint>
#include <string>
#include <memory>
#include <utility>
#include "binaryninjaapi.h"
#include <capstone/capstone.h>

// Forward declarations for Binary Ninja types using Ref
using BinaryViewRef = BinaryNinja::Ref<BinaryNinja::BinaryView>;
using FunctionRef = BinaryNinja::Ref<BinaryNinja::Function>;
using ArchitectureRef = BinaryNinja::Ref<BinaryNinja::Architecture>;

namespace lumina {

/**
 * Result of pattern generation for a function
 */
struct PatternResult {
    std::array<uint8_t, 16> hash;       // 16-byte MD5 function hash
    std::vector<uint8_t> normalized;    // Normalized bytes (raw & ~mask)
    std::vector<uint8_t> masks;         // Placeholder masks
    uint32_t func_size;                 // Total function size in bytes
    bool success;                       // Whether generation succeeded
    std::string error;                  // Error message if failed
};

/**
 * Instruction normalization info
 */
struct InstructionMask {
    std::vector<uint8_t> raw_bytes;     // Raw instruction bytes
    std::vector<uint8_t> mask;          // Mask bytes (1 = mask out, 0 = keep)
};

/**
 * Architecture-specific mask generator interface
 */
class ArchMaskGenerator {
public:
    virtual ~ArchMaskGenerator() = default;

    /**
     * Generate placeholder mask for an instruction.
     *
     * @param bv Binary view
     * @param addr Instruction address
     * @param raw_bytes Raw instruction bytes
     * @return Mask where 1 bits indicate position-dependent (variable) bytes
     */
    virtual InstructionMask getMask(
        BinaryNinja::BinaryView* bv,
        uint64_t addr,
        const std::vector<uint8_t>& raw_bytes
    ) = 0;

    /**
     * Get architecture name for debugging
     */
    virtual std::string getName() const = 0;

    /**
     * Set the current function's address range.
     * Default implementation does nothing - override in arch-specific classes.
     */
    virtual void setFunctionRange(uint64_t start, uint64_t end) {
        (void)start; (void)end;  // Default: ignore
    }

    /**
     * Set the current function chunk ranges.
     * For IDA parity, x86/x64 near/far control-flow operands are treated as
     * internal only when they stay inside the same chunk as the source
     * instruction, not merely inside the overall function extent.
     */
    virtual void setFunctionChunks(const std::vector<std::pair<uint64_t, uint64_t>>& chunks) {
        (void)chunks;
    }
};

/**
 * x86/x64 mask generator
 * Approximates IDA's procmod-driven Lumina masking.
 * - Near/far control flow is chunk-aware
 * - Direct memory forms are masked like IDA's o_mem operands
 * - Offset-like immediates/displacements use Binary Ninja-side heuristics
 */
class X86MaskGenerator : public ArchMaskGenerator {
public:
    explicit X86MaskGenerator(bool is64bit = false);
    ~X86MaskGenerator() override;

    InstructionMask getMask(
        BinaryNinja::BinaryView* bv,
        uint64_t addr,
        const std::vector<uint8_t>& raw_bytes
    ) override;

    std::string getName() const override { return m_is64bit ? "x86_64" : "x86"; }

    /**
     * Set the current function's address range.
     * Used as a fallback when chunk information is unavailable.
     */
    void setFunctionRange(uint64_t start, uint64_t end) override {
        m_funcStart = start;
        m_funcEnd = end;
    }

    void setFunctionChunks(const std::vector<std::pair<uint64_t, uint64_t>>& chunks) override {
        m_chunkRanges = chunks;
    }

private:
    bool m_is64bit;
    uint64_t m_funcStart;  // Current function start address
    uint64_t m_funcEnd;    // Current function end address
    std::vector<std::pair<uint64_t, uint64_t>> m_chunkRanges;
    csh m_capstone;
    bool m_capstoneReady;

    bool initCapstone();
};

/**
 * ARM32 mask generator
 * Masks: B/BL branch offsets, PC-relative loads
 */
class ARMMaskGenerator : public ArchMaskGenerator {
public:
    explicit ARMMaskGenerator(bool isThumb = false, bool isBigEndian = false)
        : m_isThumb(isThumb), m_isBigEndian(isBigEndian) {}

    InstructionMask getMask(
        BinaryNinja::BinaryView* bv,
        uint64_t addr,
        const std::vector<uint8_t>& raw_bytes
    ) override;

    std::string getName() const override { return m_isThumb ? "thumb" : "arm"; }

    void setFunctionRange(uint64_t start, uint64_t end) override {
        m_funcStart = start;
        m_funcEnd = end;
    }

    void setFunctionChunks(const std::vector<std::pair<uint64_t, uint64_t>>& chunks) override {
        m_chunkRanges = chunks;
    }

private:
    bool m_isThumb;
    bool m_isBigEndian;
    uint64_t m_funcStart = 0;
    uint64_t m_funcEnd = 0;
    std::vector<std::pair<uint64_t, uint64_t>> m_chunkRanges;
};

/**
 * ARM64 (AArch64) mask generator
 * Masks: ADRP page offsets, branch targets, literal references
 */
class ARM64MaskGenerator : public ArchMaskGenerator {
public:
    explicit ARM64MaskGenerator(bool isBigEndian = false);
    ~ARM64MaskGenerator() override;

    InstructionMask getMask(
        BinaryNinja::BinaryView* bv,
        uint64_t addr,
        const std::vector<uint8_t>& raw_bytes
    ) override;

    std::string getName() const override { return "aarch64"; }

    void setFunctionRange(uint64_t start, uint64_t end) override {
        m_funcStart = start;
        m_funcEnd = end;
        m_trackedAddrValid.fill(false);
        m_trackedAddr.fill(0);
        m_trackedAddrTtl.fill(0);
        m_trackedChunkStart.fill(0);
        m_trackedChunkEnd.fill(0);
    }

    void setFunctionChunks(const std::vector<std::pair<uint64_t, uint64_t>>& chunks) override {
        m_chunkRanges = chunks;
    }

private:
    bool m_isBigEndian;
    uint64_t m_funcStart = 0;
    uint64_t m_funcEnd = 0;
    std::vector<std::pair<uint64_t, uint64_t>> m_chunkRanges;
    csh m_capstone = 0;
    bool m_capstoneReady = false;
    std::array<bool, 32> m_trackedAddrValid{};
    std::array<uint64_t, 32> m_trackedAddr{};
    std::array<uint8_t, 32> m_trackedAddrTtl{};
    std::array<uint64_t, 32> m_trackedChunkStart{};
    std::array<uint64_t, 32> m_trackedChunkEnd{};

    bool initCapstone();
};

/**
 * Generic/fallback mask generator
 * Uses Binary Ninja's instruction info to detect branches/calls and mask appropriately
 */
class GenericMaskGenerator : public ArchMaskGenerator {
public:
    explicit GenericMaskGenerator(ArchitectureRef arch) : m_arch(arch) {}

    InstructionMask getMask(
        BinaryNinja::BinaryView* bv,
        uint64_t addr,
        const std::vector<uint8_t>& raw_bytes
    ) override;

    std::string getName() const override;

private:
    ArchitectureRef m_arch;
};

/**
 * Pattern generator class
 * Computes Lumina-compatible function hashes for functions
 */
class PatternGenerator {
public:
    explicit PatternGenerator(BinaryViewRef bv);
    ~PatternGenerator();

    /**
     * Generate a function-hash pattern for a function
     *
     * @param func Function to process
     * @return PatternResult with hash and normalized bytes
     */
    PatternResult generatePattern(FunctionRef func);

    /**
     * Enable/disable debug logging
     */
    void setDebugLogging(bool enabled) { m_debug = enabled; }

private:
    BinaryViewRef m_bv;
    std::unique_ptr<ArchMaskGenerator> m_maskGen;
    bool m_debug = false;

    /**
     * Create appropriate mask generator for the binary's architecture
     */
    std::unique_ptr<ArchMaskGenerator> createMaskGenerator();

    /**
     * Process a single instruction and add normalized bytes
     */
    bool processInstruction(
        uint64_t addr,
        std::vector<uint8_t>& normalized,
        std::vector<uint8_t>& masks
    );

    /**
     * Compute MD5 hash of normalized_bytes concatenated with mask_bytes
     * This matches IDA's Lumina hash computation algorithm:
     * hash = MD5(normalized_bytes || mask_bytes)
     */
    std::array<uint8_t, 16> computeMD5(const std::vector<uint8_t>& normalized_bytes,
                                       const std::vector<uint8_t>& mask_bytes);
};

/**
 * Convenience function: compute a function hash for a function
 */
std::array<uint8_t, 16> computeFunctionHash(
    BinaryViewRef bv,
    FunctionRef func
);

/**
 * Convenience function: compute a function hash with full result info
 */
PatternResult computePattern(
    BinaryViewRef bv,
    FunctionRef func
);

/**
 * Pull filtering heuristic result
 */
struct PullFilterResult {
    bool shouldSkip;        // True if function should NOT be queried
    std::string reason;     // Reason for skipping (if shouldSkip=true)
    size_t suspiciousBranchCount = 0;
    uint64_t firstSuspiciousSource = 0;
    uint64_t firstSuspiciousTarget = 0;
};

/**
 * Determine if a function should be excluded from Lumina pull operations.
 *
 * Filters out functions that IDA doesn't query as ordinary Lumina targets:
 * - PLT stubs (in .plt or .plt.got sections)
 * - CRT functions (_init, _fini, frame_dummy, etc.)
 * - ARM64 functions with suspicious non-call branches into nearby executable
 *   code beyond the Binary Ninja function end, which are likely split-tail
 *   layout mismatches and therefore hash unreliability risks
 *
 * @param bv Binary view
 * @param func Function to check
 * @return PullFilterResult with skip decision and reason
 */
PullFilterResult shouldSkipPull(BinaryViewRef bv, FunctionRef func);

} // namespace lumina
