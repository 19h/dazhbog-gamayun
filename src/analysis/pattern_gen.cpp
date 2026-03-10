#include "analysis/pattern_gen.h"
#include "debug/debug_dump.h"
#include <QCryptographicHash>
#include <algorithm>
#include <cstring>
#include <cctype>
#include <fstream>
#include <filesystem>

// Check if debug mode is enabled - checked every time (no caching)
// Set LUMINA_DEBUG=1 to enable
static bool isDebugEnabled() {
    const char* env = std::getenv("LUMINA_DEBUG");
    return (env && *env == '1');
}

// Extra metadata logging (per-function summary)
static bool isMetaLoggingEnabled() {
    const char* env = std::getenv("LUMINA_DEBUG_META");
    return (env && *env == '1');
}

// Dump full raw/normalized/mask buffers to disk for deeper forensics.
static bool isByteDumpEnabled() {
    const char* env = std::getenv("LUMINA_DUMP_BYTES");
    return (env && *env == '1');
}

static std::string md5Hex(const std::vector<uint8_t>& bytes) {
    QCryptographicHash hash(QCryptographicHash::Md5);
    if (!bytes.empty()) {
        hash.addData(QByteArrayView(reinterpret_cast<const char*>(bytes.data()),
                                    qsizetype(bytes.size())));
    }
    QByteArray res = hash.result();
    std::string out;
    out.reserve(res.size() * 2);
    static const char* hex = "0123456789abcdef";
    for (auto b : res) {
        uint8_t v = static_cast<uint8_t>(b);
        out.push_back(hex[v >> 4]);
        out.push_back(hex[v & 0x0F]);
    }
    return out;
}

static void appendMetaLog(
    const std::string& name,
    uint64_t funcStart,
    uint64_t funcEnd,
    uint64_t imageStart,
    uint64_t imageEnd,
    const std::vector<uint8_t>& rawBytes,
    const std::vector<uint8_t>& normalized,
    const std::vector<uint8_t>& masks,
    const std::array<uint8_t,16>& hash,
    BinaryNinja::BinaryView* bv)
{
    try {
        std::filesystem::create_directories("/tmp/lumina_debug");
        std::ofstream out("/tmp/lumina_debug/meta.log", std::ios::app);
        if (!out.is_open()) return;

        auto toHexHash = [](const std::array<uint8_t,16>& h) {
            static const char* hex = "0123456789abcdef";
            std::string s;
            s.reserve(32);
            for (auto b : h) {
                s.push_back(hex[b >> 4]);
                s.push_back(hex[b & 0x0F]);
            }
            return s;
        };

        out << "Function " << name << " @0x" << std::hex << funcStart
            << " size=" << std::dec << (funcEnd - funcStart)
            << " img=[" << std::hex << imageStart << "," << imageEnd << ")\n";
        out << " Hash: " << toHexHash(hash)
            << " MD5(raw)=" << md5Hex(rawBytes)
            << " MD5(norm)=" << md5Hex(normalized)
            << " MD5(mask)=" << md5Hex(masks)
            << " MD5(norm||mask)=" << md5Hex([&](){std::vector<uint8_t> cat=normalized; cat.insert(cat.end(), masks.begin(), masks.end()); return cat;}()) << "\n";

        if (bv) {
            auto segs = bv->GetSegments();
            out << " Segments(" << segs.size() << "):";
            for (auto& s : segs) {
                out << " [" << std::hex << s->GetStart() << "," << s->GetEnd() << "]";
            }
            out << "\n";
        }

        auto dumpBytes = [&](const char* label, const std::vector<uint8_t>& v) {
            out << " " << label << " (" << v.size() << "): ";
            size_t limit = std::min<size_t>(v.size(), 128);
            for (size_t i = 0; i < limit; i++) {
                char buf[4]; snprintf(buf, sizeof(buf), "%02x", v[i]);
                out << buf;
            }
            if (v.size() > limit) out << "...";
            out << "\n";
        };
        dumpBytes("raw", rawBytes);
        dumpBytes("norm", normalized);
        dumpBytes("mask", masks);
        out << "----\n";
    } catch (...) {
        // best-effort; ignore logging failures
    }
}

static void dumpBytesToFiles(
    const std::string& name,
    uint64_t funcStart,
    const std::vector<uint8_t>& rawBytes,
    const std::vector<uint8_t>& normalized,
    const std::vector<uint8_t>& masks)
{
    if (!isByteDumpEnabled())
        return;

    try {
        std::filesystem::create_directories("/tmp/lumina_debug");

        // Sanitize the function name so we get predictable file names
        std::string cleanName = name;
        for (auto& c : cleanName) {
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_'))
                c = '_';
        }

        char suffix[32];
        std::snprintf(suffix, sizeof(suffix), "_%llx", (unsigned long long)funcStart);
        std::string basePath = "/tmp/lumina_debug/" + cleanName + suffix;

        auto writeFile = [](const std::string& path, const std::vector<uint8_t>& data) {
            std::ofstream out(path, std::ios::binary);
            if (!out.is_open())
                return;
            out.write(reinterpret_cast<const char*>(data.data()),
                      static_cast<std::streamsize>(data.size()));
        };

        writeFile(basePath + ".raw.bin", rawBytes);
        writeFile(basePath + ".norm.bin", normalized);
        writeFile(basePath + ".mask.bin", masks);
    } catch (...) {
        // Debug-only facility; ignore failures
    }
}

namespace lumina {

// ============================================================================
// X86MaskGenerator Implementation
// ============================================================================

X86MaskGenerator::X86MaskGenerator(bool is64bit)
    : m_is64bit(is64bit), m_funcStart(0), m_funcEnd(0), m_capstone(0), m_capstoneReady(false) {}

X86MaskGenerator::~X86MaskGenerator() {
    if (m_capstoneReady) {
        cs_close(&m_capstone);
    }
}

bool X86MaskGenerator::initCapstone() {
    if (m_capstoneReady) {
        return true;
    }

    cs_mode mode = m_is64bit ? CS_MODE_64 : CS_MODE_32;
    if (cs_open(CS_ARCH_X86, mode, &m_capstone) != CS_ERR_OK) {
        return false;
    }

    cs_option(m_capstone, CS_OPT_DETAIL, CS_OPT_ON);
    m_capstoneReady = true;
    return true;
}

static bool addressInRange(uint64_t addr, const std::pair<uint64_t, uint64_t>& range)
{
    return addr >= range.first && addr < range.second;
}

static const std::pair<uint64_t, uint64_t>* findContainingRange(
    const std::vector<std::pair<uint64_t, uint64_t>>& ranges,
    uint64_t addr)
{
    for (const auto& range : ranges) {
        if (addressInRange(addr, range)) {
            return &range;
        }
    }
    return nullptr;
}

static bool targetLeavesCurrentChunk(
    const std::vector<std::pair<uint64_t, uint64_t>>& ranges,
    uint64_t source,
    uint64_t target,
    uint64_t funcStart,
    uint64_t funcEnd)
{
    if (const auto* sourceRange = findContainingRange(ranges, source)) {
        return !addressInRange(target, *sourceRange);
    }
    return target < funcStart || target >= funcEnd;
}

static void markMaskBits(std::vector<uint8_t>& mask, size_t highExclusive, size_t lowInclusive)
{
    if (highExclusive <= lowInclusive) {
        return;
    }

    const size_t maxBits = mask.size() * 8;
    if (lowInclusive >= maxBits) {
        return;
    }
    if (highExclusive > maxBits) {
        highExclusive = maxBits;
    }

    for (size_t bit = lowInclusive; bit < highExclusive; ++bit) {
        const size_t byteIndex = bit / 8;
        const uint8_t bitMask = static_cast<uint8_t>(1u << (bit % 8));
        mask[byteIndex] |= bitMask;
    }
}

static void swapMaskGroups(std::vector<uint8_t>& mask, size_t groupSize)
{
    if (groupSize == 0 || mask.empty() || (mask.size() % groupSize) != 0) {
        return;
    }

    for (size_t i = 0; i < mask.size(); i += groupSize) {
        std::reverse(mask.begin() + static_cast<ptrdiff_t>(i),
                     mask.begin() + static_cast<ptrdiff_t>(i + groupSize));
    }
}

static bool isMappedAddress(BinaryNinja::BinaryView* bv, uint64_t target)
{
    if (!bv) {
        return false;
    }
    return bv->GetSegmentAt(target) != nullptr;
}

static bool readUint32LE(BinaryNinja::BinaryView* bv, uint64_t addr, uint32_t& out)
{
    if (!bv) {
        return false;
    }

    auto data = bv->ReadBuffer(addr, 4);
    if (data.GetLength() != 4) {
        return false;
    }

    const auto* bytes = static_cast<const uint8_t*>(data.GetData());
    out = static_cast<uint32_t>(bytes[0]) |
          (static_cast<uint32_t>(bytes[1]) << 8) |
          (static_cast<uint32_t>(bytes[2]) << 16) |
          (static_cast<uint32_t>(bytes[3]) << 24);
    return true;
}

static size_t getDispOperandSize(const cs_x86_encoding& enc, size_t insnSize)
{
    if (enc.disp_offset == 0 || enc.disp_offset >= insnSize) {
        return 0;
    }

    size_t dispSize = enc.disp_size;
    if (enc.imm_offset > enc.disp_offset) {
        dispSize = enc.imm_offset - enc.disp_offset;
    }

    if (enc.disp_offset + dispSize > insnSize) {
        dispSize = insnSize - enc.disp_offset;
    }
    return dispSize;
}

static size_t getImmOperandSize(const cs_x86_encoding& enc, size_t insnSize)
{
    if (enc.imm_offset == 0 || enc.imm_offset >= insnSize) {
        return 0;
    }

    size_t immSize = enc.imm_size;
    if (enc.imm_offset + immSize > insnSize) {
        immSize = insnSize - enc.imm_offset;
    }
    return immSize;
}

static bool isControlFlowImmediateInstruction(csh capstone, const cs_insn& insn)
{
    if (cs_insn_group(capstone, &insn, CS_GRP_CALL) ||
        cs_insn_group(capstone, &insn, CS_GRP_JUMP)) {
        return true;
    }

    std::string mnemonic = insn.mnemonic;
    return mnemonic == "call" || (!mnemonic.empty() && mnemonic[0] == 'j') ||
           mnemonic.rfind("loop", 0) == 0 || mnemonic == "jrcxz";
}

static bool isDirectMemoryOperand(const cs_x86_op& op)
{
    if (op.type != X86_OP_MEM) {
        return false;
    }

    return op.mem.base == X86_REG_RIP || op.mem.base == X86_REG_INVALID;
}

// Helper to check if a value is in a valid non-code (data) segment
// This handles both cases:
// - Binary 1: .rodata BEFORE .text (value < text_start)
// - Binary 2: .rodata AFTER .text (value > text_end)
static bool isInNonCodeRange(uint64_t value, BinaryNinja::BinaryView* bv) {
    if (!bv) return false;

    // Check if value falls within ANY non-executable segment
    for (const auto& seg : bv->GetSegments()) {
        // Skip executable segments
        if (seg->GetFlags() & 0x1) continue;  // Executable flag

        // Check if value is in this non-code segment
        if (value >= seg->GetStart() && value < seg->GetEnd()) {
            return true;
        }
    }

    return false;
}

// Helper to check if a value falls within any valid LOAD segment
static bool isInValidSegment(uint64_t value, BinaryNinja::BinaryView* bv) {
    if (!bv) return false;

    for (const auto& seg : bv->GetSegments()) {
        if (value >= seg->GetStart() && value < seg->GetEnd()) {
            return true;
        }
    }
    return false;
}

// Helper to check if instruction is a stack adjustment (SUB/ADD RSP/RBP)
static bool isStackAdjustment(const cs_insn* insn) {
    if (!insn || !insn->detail) return false;

    const cs_x86& x86 = insn->detail->x86;

    // Check for SUB or ADD
    uint16_t id = insn->id;
    if (id != X86_INS_SUB && id != X86_INS_ADD) {
        return false;
    }

    // Must have 2 operands
    if (x86.op_count != 2) return false;

    const cs_x86_op& op0 = x86.operands[0];
    const cs_x86_op& op1 = x86.operands[1];

    // First operand must be RSP or RBP register
    if (op0.type != X86_OP_REG) return false;
    if (op0.reg != X86_REG_RSP && op0.reg != X86_REG_RBP) return false;

    // Second operand must be immediate
    if (op1.type != X86_OP_IMM) return false;

    return true;
}

// Helper to check if instruction is a VEX-encoded comparison with predicate
static bool isVexCompareWithPredicate(const std::vector<uint8_t>& bytes, const cs_x86_encoding& enc) {
    if (bytes.size() < 3) return false;

    // Check for VEX prefix
    if (bytes[0] == 0xC5 && bytes.size() >= 4) {
        // 2-byte VEX: C5 [Rvvvvlpp] opcode ...
        // vcmpss/vcmpsd/vcmpps/vcmppd use opcode 0xC2
        return bytes[2] == 0xC2;
    } else if (bytes[0] == 0xC4 && bytes.size() >= 5) {
        // 3-byte VEX: C4 [RXBmmmmm] [Wvvvvlpp] opcode ...
        return bytes[3] == 0xC2;
    }

    return false;
}

InstructionMask X86MaskGenerator::getMask(
    BinaryNinja::BinaryView* bv,
    uint64_t addr,
    const std::vector<uint8_t>& raw_bytes)
{
    InstructionMask result;
    result.raw_bytes = raw_bytes;
    result.mask.resize(raw_bytes.size(), 0);  // Default: keep all bytes

    if (raw_bytes.empty()) {
        return result;
    }

    // Get function context for valid_loc check
    uint64_t funcStart = m_funcStart;
    uint64_t funcEnd = m_funcEnd;

    if (!initCapstone()) {
        return result;
    }

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(m_capstone, raw_bytes.data(), raw_bytes.size(), addr, 1, &insn);
    if (count == 0 || !insn || !insn[0].detail) {
        if (insn) {
            cs_free(insn, count);
        }
        return result;
    }

    const cs_x86& x86 = insn[0].detail->x86;
    const cs_x86_encoding& enc = insn[0].detail->x86.encoding;
    const auto* currentChunk = findContainingRange(m_chunkRanges, addr);

    auto staysInCurrentChunk = [&](uint64_t target) {
        if (currentChunk) {
            return addressInRange(target, *currentChunk);
        }
        return target >= funcStart && target < funcEnd;
    };

    auto addMask = [&](size_t offset, size_t length) {
        for (size_t i = 0; i < length && offset + i < result.mask.size(); i++) {
            result.mask[offset + i] = 0xFF;
        }
    };

    const size_t dispSize = getDispOperandSize(enc, raw_bytes.size());
    const size_t immSize = getImmOperandSize(enc, raw_bytes.size());
    const bool isVexEncoded = raw_bytes.size() >= 2 && (raw_bytes[0] == 0xC4 || raw_bytes[0] == 0xC5);
    const bool isControlFlowImmediate = isControlFlowImmediateInstruction(m_capstone, insn[0]);

    bool shouldMaskDisp = false;
    bool shouldMaskImm = false;
    bool hasRipRelativeMemory = false;

    // Approximate IDA pc/ana.cpp operand-driven calcrel logic:
    // - near/far control-flow operands -> mask when target leaves current chunk
    // - o_mem operands -> always mask their encoded bytes
    // - o_displ/o_imm -> mask only when they look like offsets
    for (size_t i = 0; i < x86.op_count; i++) {
        const cs_x86_op& op = x86.operands[i];

        if (op.type == X86_OP_MEM) {
            if (op.mem.base == X86_REG_RIP) {
                hasRipRelativeMemory = true;
            }

            if (isDirectMemoryOperand(op)) {
                shouldMaskDisp = dispSize > 0;
                continue;
            }

            if (op.mem.segment == X86_REG_FS || op.mem.segment == X86_REG_GS) {
                shouldMaskDisp = dispSize > 0;
                continue;
            }

            if (dispSize == 4) {
                int64_t dispVal = op.mem.disp;
                uint64_t uDispVal = (dispVal < 0)
                    ? static_cast<uint64_t>(dispVal & 0xFFFFFFFF)
                    : static_cast<uint64_t>(dispVal);
                if (isInNonCodeRange(uDispVal, bv)) {
                    shouldMaskDisp = true;
                }
            }
            continue;
        }

        if (op.type != X86_OP_IMM) {
            continue;
        }

        if (isControlFlowImmediate && immSize > 0) {
            uint64_t target = static_cast<uint64_t>(op.imm);
            if (!staysInCurrentChunk(target)) {
                shouldMaskImm = true;
            }
            continue;
        }

        if (immSize == 4 && !isStackAdjustment(&insn[0])) {
            int64_t immVal = op.imm;
            uint64_t uImmVal = (immVal < 0)
                ? static_cast<uint64_t>(immVal & 0xFFFFFFFF)
                : static_cast<uint64_t>(immVal);
            if (isInNonCodeRange(uImmVal, bv) && isInValidSegment(uImmVal, bv)) {
                shouldMaskImm = true;
            }
        }
    }

    if (shouldMaskDisp && dispSize > 0) {
        addMask(enc.disp_offset, dispSize);
    }

    if (shouldMaskImm && immSize > 0) {
        addMask(enc.imm_offset, immSize);
    }

    // =========================================================================
    // Rule 8: VEX comparison predicate masking
    // vcmpss, vcmpsd, vcmpps, vcmppd have a 1-byte predicate at the end
    // Empirical refinement on top of the generic procmod-style operand masking.
    // =========================================================================
    if (isVexCompareWithPredicate(raw_bytes, enc) && hasRipRelativeMemory) {
        if (enc.imm_offset && enc.imm_size == 1) {
            addMask(enc.imm_offset, 1);
        }
    }

    // =========================================================================
    // Rule 9: Legacy SSE comparison predicate masking
    // cmpps (0F C2), cmppd (66 0F C2), cmpss (F3 0F C2), cmpsd (F2 0F C2)
    // Empirical refinement on top of the generic procmod-style operand masking.
    // =========================================================================
    if (hasRipRelativeMemory && raw_bytes.size() >= 4) {
        bool isLegacySSECmp = false;

        // Check for 66 0F C2 (cmppd)
        if (raw_bytes[0] == 0x66 && raw_bytes[1] == 0x0F && raw_bytes[2] == 0xC2) {
            isLegacySSECmp = true;
        }
        // Check for F2 0F C2 (cmpsd) or F3 0F C2 (cmpss)
        else if ((raw_bytes[0] == 0xF2 || raw_bytes[0] == 0xF3) &&
                 raw_bytes[1] == 0x0F && raw_bytes[2] == 0xC2) {
            isLegacySSECmp = true;
        }
        // Check for 0F C2 (cmpps) - no prefix
        else if (raw_bytes[0] == 0x0F && raw_bytes[1] == 0xC2) {
            isLegacySSECmp = true;
        }

        if (isLegacySSECmp && enc.imm_offset && enc.imm_size == 1) {
            addMask(enc.imm_offset, 1);
        }
    }

    cs_free(insn, count);
    return result;
}

// ============================================================================
// ARM32 Mask Generator Implementation
// ============================================================================

namespace arm {

// Check if ARM instruction is a branch (B/BL)
inline bool isBranch(uint32_t insn) {
    uint8_t cond_op = (insn >> 24) & 0xFF;
    return (cond_op & 0x0E) == 0x0A;  // 1x1x = B/BL
}

inline bool isLinkBranch(uint32_t insn) {
    return isBranch(insn) && ((insn >> 24) & 1) != 0;
}

inline int32_t signExtend(uint32_t value, unsigned bits) {
    const uint32_t shift = 32 - bits;
    return static_cast<int32_t>(value << shift) >> shift;
}

inline int32_t branchOffset(uint32_t insn) {
    return signExtend(insn & 0x00FFFFFF, 24) << 2;
}

// Check if ARM instruction is LDR/STR with PC base
inline bool isLdrPCRelative(uint32_t insn) {
    if ((insn & 0x0C000000) != 0x04000000) return false;  // load/store immediate class
    if ((insn & (1u << 25)) != 0) return false;           // register offset forms are separate
    return ((insn >> 16) & 0xF) == 15;
}

inline bool isThumb32BranchPair(uint16_t hw1, uint16_t hw2) {
    return (hw1 & 0xF800) == 0xF000 && (hw2 & 0x8000) == 0x8000;
}

inline bool isThumb32BranchLink(uint16_t hw2) {
    return (hw2 & 0xD000) == 0xD000;
}

inline bool isThumb32BranchExchange(uint16_t hw2) {
    return (hw2 & 0xD001) == 0xC000;
}

inline int32_t thumb32BranchOffset(uint16_t hw1, uint16_t hw2) {
    const int s = (hw1 >> 10) & 1;
    const int i1 = ((hw2 >> 13) & 1) ^ s ^ 1;
    const int i2 = ((hw2 >> 11) & 1) ^ s ^ 1;
    uint32_t delta = (static_cast<uint32_t>(s) << 24)
                   | (static_cast<uint32_t>(i1) << 23)
                   | (static_cast<uint32_t>(i2) << 22)
                   | ((static_cast<uint32_t>(hw1) & 0x03FF) << 12)
                   | ((static_cast<uint32_t>(hw2) & 0x07FF) << 1);
    return signExtend(delta, 25);
}

} // namespace arm

InstructionMask ARMMaskGenerator::getMask(
    BinaryNinja::BinaryView* bv,
    uint64_t addr,
    const std::vector<uint8_t>& raw_bytes)
{
    InstructionMask result;
    result.raw_bytes = raw_bytes;
    result.mask.resize(raw_bytes.size(), 0);

    const auto outsideFunction = [&](uint64_t target) {
        return target < m_funcStart || target >= m_funcEnd;
    };

    if (m_isThumb) {
        if (raw_bytes.size() >= 4) {
            uint16_t hw1 = raw_bytes[0] | (raw_bytes[1] << 8);
            uint16_t hw2 = raw_bytes[2] | (raw_bytes[3] << 8);

            if (arm::isThumb32BranchPair(hw1, hw2)) {
                uint64_t startoff = addr + 4;
                if (arm::isThumb32BranchExchange(hw2)) {
                    startoff &= ~static_cast<uint64_t>(3);
                }
                uint64_t target = static_cast<uint64_t>(static_cast<int64_t>(startoff) + arm::thumb32BranchOffset(hw1, hw2));
                if (arm::isThumb32BranchLink(hw2) || arm::isThumb32BranchExchange(hw2) || outsideFunction(target)) {
                    markMaskBits(result.mask, 12, 0);
                    markMaskBits(result.mask, 28, 16);
                }
            }
        }

        if (raw_bytes.size() >= 2) {
            uint16_t insn = raw_bytes[0] | (raw_bytes[1] << 8);

            // Conditional branch: 1101 cond imm8 (excluding svc/permanent undefined)
            if ((insn & 0xF000) == 0xD000 && (insn & 0x0F00) != 0x0E00 && (insn & 0x0F00) != 0x0F00) {
                int32_t disp = arm::signExtend(insn & 0x00FF, 8) << 1;
                uint64_t target = static_cast<uint64_t>(static_cast<int64_t>(addr + 4) + disp);
                if (outsideFunction(target)) {
                    markMaskBits(result.mask, 8, 0);
                }
            }

            // Unconditional branch: 11100 imm11
            if ((insn & 0xF800) == 0xE000) {
                int32_t disp = arm::signExtend(insn & 0x07FF, 11) << 1;
                uint64_t target = static_cast<uint64_t>(static_cast<int64_t>(addr + 4) + disp);
                if (outsideFunction(target)) {
                    markMaskBits(result.mask, 11, 0);
                }
            }

            // LDR literal pool load: 01001 Rt imm8
            if ((insn & 0xF800) == 0x4800) {
                uint64_t target = ((addr & ~static_cast<uint64_t>(3)) + 4) + ((insn & 0x00FF) << 2);
                if (isMappedAddress(bv, target) && outsideFunction(target)) {
                    markMaskBits(result.mask, 8, 0);
                }
            }

            // ADD/ADR (PC-relative immediate): 1010 0xxx xxxxxxxx
            if ((insn & 0xF800) == 0xA000 && (insn & 0x0800) == 0) {
                uint64_t target = ((addr & ~static_cast<uint64_t>(3)) + 4) + ((insn & 0x00FF) << 2);
                if (isMappedAddress(bv, target)) {
                    markMaskBits(result.mask, 8, 0);
                }
            }
        }
    } else {
        if (raw_bytes.size() >= 4) {
            uint32_t insn = raw_bytes[0] | (raw_bytes[1] << 8) |
                           (raw_bytes[2] << 16) | (raw_bytes[3] << 24);

            // B / BL immediate
            if (arm::isBranch(insn)) {
                uint64_t target = static_cast<uint64_t>(static_cast<int64_t>(addr + 8) + arm::branchOffset(insn));
                if (arm::isLinkBranch(insn) || outsideFunction(target)) {
                    markMaskBits(result.mask, 24, 0);
                }
            }

            // LDR/STR immediate with PC base
            if (arm::isLdrPCRelative(insn)) {
                int64_t disp = static_cast<int64_t>(insn & 0x0FFF);
                if ((insn & (1u << 23)) == 0) {
                    disp = -disp;
                }
                uint64_t base = (addr + 8) & ~static_cast<uint64_t>(3);
                uint64_t target = static_cast<uint64_t>(static_cast<int64_t>(base) + disp);
                if (isMappedAddress(bv, target) && outsideFunction(target)) {
                    markMaskBits(result.mask, 12, 0);
                }
            }
        }
    }

    if (m_isBigEndian) {
        swapMaskGroups(result.mask, m_isThumb ? 2 : 4);
    }

    return result;
}

// ============================================================================
// ARM64 Mask Generator Implementation
// ============================================================================

ARM64MaskGenerator::ARM64MaskGenerator(bool isBigEndian)
    : m_isBigEndian(isBigEndian), m_capstone(0), m_capstoneReady(false) {}

ARM64MaskGenerator::~ARM64MaskGenerator() {
    if (m_capstoneReady) {
        cs_close(&m_capstone);
    }
}

bool ARM64MaskGenerator::initCapstone() {
    if (m_capstoneReady) {
        return true;
    }

    cs_mode mode = m_isBigEndian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
    if (cs_open(CS_ARCH_ARM64, mode, &m_capstone) != CS_ERR_OK) {
        return false;
    }

    cs_option(m_capstone, CS_OPT_DETAIL, CS_OPT_ON);
    m_capstoneReady = true;
    return true;
}

namespace arm64 {

inline bool trackedGprIndex(unsigned regId, uint32_t* out) {
    if (regId >= ARM64_REG_X0 && regId <= ARM64_REG_X28) {
        *out = static_cast<uint32_t>(regId - ARM64_REG_X0);
        return true;
    }
    if (regId == ARM64_REG_X29 || regId == ARM64_REG_FP) {
        *out = 29;
        return true;
    }
    if (regId == ARM64_REG_X30 || regId == ARM64_REG_LR) {
        *out = 30;
        return true;
    }
    if (regId == ARM64_REG_SP || regId == ARM64_REG_WSP) {
        *out = 31;
        return true;
    }
    if (regId >= ARM64_REG_W0 && regId <= ARM64_REG_W28) {
        *out = static_cast<uint32_t>(regId - ARM64_REG_W0);
        return true;
    }
    if (regId == ARM64_REG_W29) {
        *out = 29;
        return true;
    }
    if (regId == ARM64_REG_W30) {
        *out = 30;
        return true;
    }
    return false;
}

inline bool resolveConstantBaseRegisterValue(
    BinaryNinja::BinaryView* bv,
    uint64_t funcStart,
    uint64_t addr,
    uint32_t reg,
    uint64_t* value)
{
    if (bv == nullptr || value == nullptr || reg == 31) {
        return false;
    }

    auto funcs = bv->GetAnalysisFunctionsContainingAddress(addr);
    BinaryNinja::Ref<BinaryNinja::Function> currentFunc;
    for (auto& func : funcs) {
        if (func && func->GetStart() == funcStart) {
            currentFunc = func;
            break;
        }
    }

    if (!currentFunc && !funcs.empty()) {
        currentFunc = funcs.front();
    }
    if (!currentFunc) {
        return false;
    }

    auto arch = currentFunc->GetArchitecture();
    if (!arch) {
        return false;
    }

    std::string regName = "x" + std::to_string(reg);
    uint32_t archReg = arch->GetRegisterByName(regName);
    if (archReg == BN_INVALID_REGISTER) {
        return false;
    }

    auto regValue = currentFunc->GetRegisterValueAtInstruction(arch, addr, archReg);
    if (regValue.IsConstant() || regValue.state == ImportedAddressValue) {
        *value = static_cast<uint64_t>(regValue.value);
        return true;
    }

    if (regValue.state == ExternalPointerValue) {
        *value = static_cast<uint64_t>(regValue.value + regValue.offset);
        return true;
    }

    return false;
}

// Check if instruction is B/BL (unconditional branch)
inline bool isBranch(uint32_t insn) {
    // B: 000101 imm26
    // BL: 100101 imm26
    return (insn & 0x7C000000) == 0x14000000;
}

// Check if instruction is B.cond (conditional branch)
inline bool isBranchCond(uint32_t insn) {
    // B.cond: 01010100 imm19 0 cond
    return (insn & 0xFF000010) == 0x54000000;
}

// Check if instruction is CBZ/CBNZ
inline bool isCBZ(uint32_t insn) {
    // CBZ/CBNZ: sf 011010 op imm19 Rt
    return (insn & 0x7E000000) == 0x34000000;
}

// Check if instruction is TBZ/TBNZ
inline bool isTBZ(uint32_t insn) {
    // TBZ/TBNZ: b5 011011 op b40 imm14 Rt
    return (insn & 0x7E000000) == 0x36000000;
}

// Check if instruction is ADRP
inline bool isADRP(uint32_t insn) {
    // ADRP: 1 immlo 10000 immhi Rd
    return (insn & 0x9F000000) == 0x90000000;
}

// Check if instruction is ADR
inline bool isADR(uint32_t insn) {
    // ADR: 0 immlo 10000 immhi Rd
    return (insn & 0x9F000000) == 0x10000000;
}

// Check if instruction is LDR (literal)
inline bool isLDRLiteral(uint32_t insn) {
    // LDR (literal): opc 011 V 00 imm19 Rt
    return (insn & 0x3B000000) == 0x18000000;
}

inline int64_t signExtend(uint64_t value, unsigned bits) {
    const unsigned shift = 64 - bits;
    return static_cast<int64_t>(value << shift) >> shift;
}

inline int64_t branchOffset26(uint32_t insn) {
    return signExtend(insn & 0x03FFFFFFu, 26) << 2;
}

inline int64_t branchOffset19(uint32_t insn) {
    return signExtend((insn >> 5) & 0x7FFFFu, 19) << 2;
}

inline int64_t branchOffset14(uint32_t insn) {
    return signExtend((insn >> 5) & 0x3FFFu, 14) << 2;
}

inline bool isBL(uint32_t insn) {
    return (insn & 0xFC000000) == 0x94000000;
}

inline bool isAddSubImmediate(uint32_t insn) {
    return (insn & 0x1F000000) == 0x11000000;
}

inline bool isLoadStoreUnsignedImmediate(uint32_t insn) {
    return (insn & 0x3B000000) == 0x39000000;
}

inline bool isLoadStoreUnsignedImmediateLoad(uint32_t insn) {
    return isLoadStoreUnsignedImmediate(insn) && (((insn >> 22) & 1u) != 0);
}

inline uint64_t loadStoreUnsignedImmediateOffset(uint32_t insn) {
    uint64_t imm12 = (insn >> 10) & 0xFFFu;
    uint64_t scale = (insn >> 30) & 0x3u;
    return imm12 << scale;
}

inline uint32_t regRd(uint32_t insn) {
    return insn & 0x1Fu;
}

inline uint32_t regRn(uint32_t insn) {
    return (insn >> 5) & 0x1Fu;
}

inline uint64_t pageBase(uint64_t addr) {
    return addr & ~static_cast<uint64_t>(0xFFF);
}

inline int64_t adrpOffset(uint32_t insn) {
    uint64_t imm = ((static_cast<uint64_t>((insn >> 5) & 0x7FFFFu)) << 2)
                 | static_cast<uint64_t>((insn >> 29) & 0x3u);
    return signExtend(imm, 21) << 12;
}

inline uint64_t adrpTarget(uint64_t addr, uint32_t insn) {
    return static_cast<uint64_t>(static_cast<int64_t>(pageBase(addr)) + adrpOffset(insn));
}

inline int64_t adrOffset(uint32_t insn) {
    uint64_t imm = ((static_cast<uint64_t>((insn >> 5) & 0x7FFFFu)) << 2)
                 | static_cast<uint64_t>((insn >> 29) & 0x3u);
    return signExtend(imm, 21);
}

inline uint64_t adrTarget(uint64_t addr, uint32_t insn) {
    return static_cast<uint64_t>(static_cast<int64_t>(addr) + adrOffset(insn));
}

inline uint64_t addSubImmediateValue(uint32_t insn) {
    uint64_t imm12 = (insn >> 10) & 0xFFFu;
    uint64_t shift = ((insn >> 22) & 0x3u) == 1 ? 12u : 0u;
    return imm12 << shift;
}

inline bool isSubImmediate(uint32_t insn) {
    return ((insn >> 30) & 1u) != 0;
}

constexpr uint8_t kTrackedAddressLifetime = 255;

inline bool isPairedWithPreviousAdrp(
    BinaryNinja::BinaryView* bv,
    uint64_t addr,
    const std::vector<std::pair<uint64_t, uint64_t>>& chunkRanges,
    uint64_t funcStart,
    uint64_t funcEnd,
    uint32_t currentInsn,
    uint64_t* pairedTarget)
{
    if (addr < 4) {
        return false;
    }

    const uint64_t prevAddr = addr - 4;
    const auto* currentChunk = findContainingRange(chunkRanges, addr);
    if (currentChunk != nullptr) {
        if (!addressInRange(prevAddr, *currentChunk)) {
            return false;
        }
    } else if (prevAddr < funcStart || prevAddr >= funcEnd) {
        return false;
    }

    uint32_t prevInsn = 0;
    if (!readUint32LE(bv, prevAddr, prevInsn) || !isADRP(prevInsn)) {
        return false;
    }

    const uint32_t adrpReg = regRd(prevInsn);
    uint64_t target = 0;

    if (isAddSubImmediate(currentInsn)) {
        if (regRn(currentInsn) != adrpReg) {
            return false;
        }
        uint64_t base = adrpTarget(prevAddr, prevInsn);
        uint64_t imm = addSubImmediateValue(currentInsn);
        target = isSubImmediate(currentInsn) ? base - imm : base + imm;
    } else if (isLoadStoreUnsignedImmediate(currentInsn)) {
        if (regRn(currentInsn) != adrpReg) {
            return false;
        }
        target = adrpTarget(prevAddr, prevInsn) + loadStoreUnsignedImmediateOffset(currentInsn);
    } else {
        return false;
    }

    if (pairedTarget != nullptr) {
        *pairedTarget = target;
    }
    return true;
}

} // namespace arm64

InstructionMask ARM64MaskGenerator::getMask(
    BinaryNinja::BinaryView* bv,
    uint64_t addr,
    const std::vector<uint8_t>& raw_bytes)
{
    InstructionMask result;
    result.raw_bytes = raw_bytes;
    result.mask.resize(raw_bytes.size(), 0);

    if (raw_bytes.size() < 4) return result;

    // ARM64 instructions are always 4 bytes.
    uint32_t insn = raw_bytes[0] | (raw_bytes[1] << 8) |
                   (raw_bytes[2] << 16) | (raw_bytes[3] << 24);

    const auto* currentChunk = findContainingRange(m_chunkRanges, addr);
    std::array<bool, 32> refreshedTrackedAddr{};

    auto clearTrackedAddr = [&](uint32_t reg) {
        if (reg >= m_trackedAddrValid.size()) {
            return;
        }
        m_trackedAddrValid[reg] = false;
        m_trackedAddr[reg] = 0;
        m_trackedAddrTtl[reg] = 0;
        m_trackedChunkStart[reg] = 0;
        m_trackedChunkEnd[reg] = 0;
        refreshedTrackedAddr[reg] = false;
    };

    auto setTrackedAddr = [&](uint32_t reg, uint64_t target) {
        if (reg >= m_trackedAddrValid.size() || reg == 31) {
            return;
        }

        m_trackedAddrValid[reg] = true;
        m_trackedAddr[reg] = target;
        m_trackedAddrTtl[reg] = arm64::kTrackedAddressLifetime;
        if (currentChunk != nullptr) {
            m_trackedChunkStart[reg] = currentChunk->first;
            m_trackedChunkEnd[reg] = currentChunk->second;
        } else {
            m_trackedChunkStart[reg] = m_funcStart;
            m_trackedChunkEnd[reg] = m_funcEnd;
        }
        refreshedTrackedAddr[reg] = true;
    };

    auto refreshTrackedAddr = [&](uint32_t reg) {
        if (reg >= m_trackedAddrValid.size() || reg == 31 || !m_trackedAddrValid[reg]) {
            return;
        }
        m_trackedAddrTtl[reg] = arm64::kTrackedAddressLifetime;
        refreshedTrackedAddr[reg] = true;
    };

    auto getTrackedAddr = [&](uint32_t reg, uint64_t* target) {
        if (reg >= m_trackedAddrValid.size() || !m_trackedAddrValid[reg]) {
            return false;
        }

        if (target != nullptr) {
            *target = m_trackedAddr[reg];
        }
        return true;
    };

    for (size_t reg = 0; reg < m_trackedAddrValid.size(); ++reg) {
        if (!m_trackedAddrValid[reg]) {
            continue;
        }
        if (m_trackedAddrTtl[reg] == 0) {
            clearTrackedAddr(static_cast<uint32_t>(reg));
        }
    }

    std::array<bool, 32> writtenTrackedAddr{};
    bool isCallInstruction = false;
    bool isTrackedCalleeSavedMove = false;
    uint32_t moveDstReg = 0;
    uint32_t moveSrcReg = 0;
    if (initCapstone()) {
        cs_insn* decoded = nullptr;
        size_t count = cs_disasm(m_capstone, raw_bytes.data(), raw_bytes.size(), addr, 1, &decoded);
        if (count > 0) {
            isCallInstruction = cs_insn_group(m_capstone, &decoded[0], CS_GRP_CALL);
            if (!isCallInstruction) {
                isCallInstruction = std::strncmp(decoded[0].mnemonic, "bl", 2) == 0;
            }

            if (decoded[0].id == ARM64_INS_MOV && decoded[0].detail != nullptr) {
                const cs_arm64& arm = decoded[0].detail->arm64;
                if (arm.op_count == 2 && arm.operands[0].type == ARM64_OP_REG && arm.operands[1].type == ARM64_OP_REG) {
                    isTrackedCalleeSavedMove = arm64::trackedGprIndex(arm.operands[0].reg, &moveDstReg) &&
                                               arm64::trackedGprIndex(arm.operands[1].reg, &moveSrcReg) &&
                                               moveDstReg >= 19 && moveDstReg <= 28 && moveSrcReg >= 19 && moveSrcReg <= 28;
                }
            }

            cs_regs regsRead{};
            cs_regs regsWrite{};
            uint8_t readCount = 0;
            uint8_t writeCount = 0;
            if (cs_regs_access(m_capstone, decoded, regsRead, &readCount, regsWrite, &writeCount) == CS_ERR_OK) {
                for (uint8_t i = 0; i < writeCount; ++i) {
                    uint32_t reg = 0;
                    if (arm64::trackedGprIndex(regsWrite[i], &reg) && reg < writtenTrackedAddr.size()) {
                        writtenTrackedAddr[reg] = true;
                    }
                }
            }

        }
        cs_free(decoded, count);
    }

    if (isTrackedCalleeSavedMove) {
        uint64_t moveTarget = 0;
        if (getTrackedAddr(moveSrcReg, &moveTarget)) {
            setTrackedAddr(moveDstReg, moveTarget);
        }
    }

    const auto outsideFunction = [&](uint64_t target) {
        return target < m_funcStart || target >= m_funcEnd;
    };

    // B/BL: mask BL and any plain B that leaves the current BN function.
    if (arm64::isBranch(insn)) {
        uint64_t target = static_cast<uint64_t>(static_cast<int64_t>(addr) + arm64::branchOffset26(insn));
        if (arm64::isBL(insn) || outsideFunction(target)) {
            markMaskBits(result.mask, 26, 0);
        }
    }

    // B.cond: mask imm19 only when it leaves the current BN function.
    if (arm64::isBranchCond(insn)) {
        uint64_t target = static_cast<uint64_t>(static_cast<int64_t>(addr) + arm64::branchOffset19(insn));
        if (outsideFunction(target)) {
            markMaskBits(result.mask, 24, 5);
        }
    }

    // CBZ/CBNZ: same rule as conditional branches.
    if (arm64::isCBZ(insn)) {
        uint64_t target = static_cast<uint64_t>(static_cast<int64_t>(addr) + arm64::branchOffset19(insn));
        if (outsideFunction(target)) {
            markMaskBits(result.mask, 24, 5);
        }
    }

    // TBZ/TBNZ: same rule as conditional branches.
    if (arm64::isTBZ(insn)) {
        uint64_t target = static_cast<uint64_t>(static_cast<int64_t>(addr) + arm64::branchOffset14(insn));
        if (outsideFunction(target)) {
            markMaskBits(result.mask, 19, 5);
        }
    }

    // ADRP: always mask immhi:immlo.
    if (arm64::isADRP(insn)) {
        markMaskBits(result.mask, 24, 5);
        markMaskBits(result.mask, 31, 29);

        uint32_t reg = arm64::regRd(insn);
        uint64_t target = arm64::adrpTarget(addr, insn);
        if (isMappedAddress(bv, target) || isInValidSegment(target, bv)) {
            setTrackedAddr(reg, target);
        } else {
            clearTrackedAddr(reg);
        }
    }

    // ADR: always mask immhi:immlo.
    if (arm64::isADR(insn)) {
        markMaskBits(result.mask, 24, 5);
        markMaskBits(result.mask, 31, 29);

        uint32_t reg = arm64::regRd(insn);
        uint64_t target = arm64::adrTarget(addr, insn);
        if (isMappedAddress(bv, target) || isInValidSegment(target, bv)) {
            setTrackedAddr(reg, target);
        } else {
            clearTrackedAddr(reg);
        }
    }

    // LDR literal: approximate IDA's offset-gated rule by masking when the
    // literal target resolves to mapped memory.
    if (arm64::isLDRLiteral(insn)) {
        uint64_t target = static_cast<uint64_t>(static_cast<int64_t>(addr) + arm64::branchOffset19(insn));
        if (isMappedAddress(bv, target)) {
            markMaskBits(result.mask, 24, 5);
        }
    }

    // ADD/SUB (immediate) and load/store unsigned immediate: IDA masks the
    // imm12 field when analysis typed the operand as an offset. The strongest
    // heuristic we have in BN is the common ADRP + direct follow-up pair used
    // to build or access page-relative addresses.
    bool shouldMaskImm12 = false;
    uint64_t pairedTarget = 0;
    if (arm64::isPairedWithPreviousAdrp(bv, addr, m_chunkRanges, m_funcStart, m_funcEnd, insn, &pairedTarget)) {
        if (isMappedAddress(bv, pairedTarget) || isInValidSegment(pairedTarget, bv)) {
            shouldMaskImm12 = !arm64::isLoadStoreUnsignedImmediate(insn) || arm64::loadStoreUnsignedImmediateOffset(insn) != 0;
            if (arm64::isAddSubImmediate(insn)) {
                setTrackedAddr(arm64::regRd(insn), pairedTarget);
            } else if (arm64::isLoadStoreUnsignedImmediate(insn)) {
                uint32_t baseReg = arm64::regRn(insn);
                uint32_t destReg = arm64::regRd(insn);
                bool clobbersBase = arm64::isLoadStoreUnsignedImmediateLoad(insn) && baseReg == destReg;
                if (!clobbersBase) {
                    refreshTrackedAddr(baseReg);
                }
            }
        }
    }

    if (!shouldMaskImm12 && arm64::isAddSubImmediate(insn)) {
        uint64_t trackedBase = 0;
        uint64_t imm = arm64::addSubImmediateValue(insn);
        uint32_t destReg = arm64::regRd(insn);
        uint32_t nextInsn = 0;
        bool feedsImmediateCall = destReg < 8 && readUint32LE(bv, addr + 4, nextInsn) && arm64::isBL(nextInsn);
        if (feedsImmediateCall && imm != 0 && getTrackedAddr(arm64::regRn(insn), &trackedBase)) {
            uint64_t target = arm64::isSubImmediate(insn) ? trackedBase - imm : trackedBase + imm;
            if (isMappedAddress(bv, target) || isInValidSegment(target, bv)) {
                shouldMaskImm12 = true;
                refreshTrackedAddr(arm64::regRn(insn));
                setTrackedAddr(destReg, target);
            }
        }
    }

    if (!shouldMaskImm12 && arm64::isLoadStoreUnsignedImmediate(insn)) {
        uint64_t trackedBase = 0;
        uint64_t offset = arm64::loadStoreUnsignedImmediateOffset(insn);
        if (offset != 0 && getTrackedAddr(arm64::regRn(insn), &trackedBase)) {
            uint64_t target = trackedBase + offset;
            if (isMappedAddress(bv, target) || isInValidSegment(target, bv)) {
                shouldMaskImm12 = true;
                uint32_t baseReg = arm64::regRn(insn);
                uint32_t destReg = arm64::regRd(insn);
                bool clobbersBase = arm64::isLoadStoreUnsignedImmediateLoad(insn) && baseReg == destReg;
                if (!clobbersBase) {
                    refreshTrackedAddr(baseReg);
                }
            }
        }
    }

    if (!shouldMaskImm12 && arm64::isLoadStoreUnsignedImmediate(insn)) {
        uint64_t constantBase = 0;
        uint64_t offset = arm64::loadStoreUnsignedImmediateOffset(insn);
        if (offset != 0 && arm64::resolveConstantBaseRegisterValue(bv, m_funcStart, addr, arm64::regRn(insn), &constantBase)) {
            uint64_t target = constantBase + offset;
            if (isMappedAddress(bv, target) || isInValidSegment(target, bv)) {
                shouldMaskImm12 = true;
            }
        }
    }

    if (shouldMaskImm12) {
        markMaskBits(result.mask, 22, 10);
    }

    for (size_t reg = 0; reg < writtenTrackedAddr.size(); ++reg) {
        if (writtenTrackedAddr[reg] && !refreshedTrackedAddr[reg]) {
            clearTrackedAddr(static_cast<uint32_t>(reg));
        }
    }

    if (isCallInstruction) {
        for (uint32_t reg = 0; reg <= 18; ++reg) {
            clearTrackedAddr(reg);
        }
        clearTrackedAddr(30);
    }

    if (m_isBigEndian) {
        swapMaskGroups(result.mask, 4);
    }

    return result;
}

// ============================================================================
// Generic Mask Generator Implementation
// ============================================================================

InstructionMask GenericMaskGenerator::getMask(
    BinaryNinja::BinaryView* bv,
    uint64_t addr,
    const std::vector<uint8_t>& raw_bytes)
{
    InstructionMask result;
    result.raw_bytes = raw_bytes;
    result.mask.resize(raw_bytes.size(), 0);

    if (!m_arch || raw_bytes.empty()) return result;

    // Use Binary Ninja's instruction info to detect branches
    BinaryNinja::InstructionInfo info;
    if (!m_arch->GetInstructionInfo(raw_bytes.data(), addr, raw_bytes.size(), info)) {
        return result;
    }

    // If instruction has branch targets, try to mask the operand bytes
    // This is a heuristic - we assume the target address is encoded in the
    // latter part of the instruction
    for (size_t i = 0; i < info.branchCount; i++) {
        if (info.branchType[i] == CallDestination ||
            info.branchType[i] == UnconditionalBranch ||
            info.branchType[i] == TrueBranch ||
            info.branchType[i] == FalseBranch) {

            // Heuristic: mask the last 4 bytes (common for 32-bit offsets)
            // or last 1 byte for short branches
            size_t insnLen = info.length;
            if (insnLen > 1) {
                // Conservative: mask everything except the first byte (opcode)
                for (size_t j = 1; j < raw_bytes.size(); j++) {
                    result.mask[j] = 0xFF;
                }
            }
            break;
        }
    }

    return result;
}

std::string GenericMaskGenerator::getName() const {
    return m_arch ? m_arch->GetName() : "unknown";
}

// ============================================================================
// Pattern Generator Implementation
// ============================================================================

PatternGenerator::PatternGenerator(BinaryViewRef bv)
    : m_bv(bv)
{
    m_maskGen = createMaskGenerator();
}

PatternGenerator::~PatternGenerator() = default;

std::unique_ptr<ArchMaskGenerator> PatternGenerator::createMaskGenerator() {
    if (!m_bv) {
        return std::make_unique<GenericMaskGenerator>(nullptr);
    }

    auto arch = m_bv->GetDefaultArchitecture();
    if (!arch) {
        return std::make_unique<GenericMaskGenerator>(nullptr);
    }

    std::string archName = arch->GetName();

    // x86/x64
    if (archName == "x86" || archName == "x86_32") {
        return std::make_unique<X86MaskGenerator>(false);
    }
    if (archName == "x86_64") {
        return std::make_unique<X86MaskGenerator>(true);
    }

    // ARM
    if (archName == "armv7" || archName == "armv7eb" || archName == "arm") {
        return std::make_unique<ARMMaskGenerator>(false, archName == "armv7eb");
    }
    if (archName == "thumb2" || archName == "thumb2eb" || archName == "thumb") {
        return std::make_unique<ARMMaskGenerator>(true, archName == "thumb2eb");
    }

    // ARM64
    if (archName == "aarch64" || archName == "arm64" || archName == "aarch64be") {
        return std::make_unique<ARM64MaskGenerator>(archName == "aarch64be");
    }

    // Fallback to generic
    return std::make_unique<GenericMaskGenerator>(arch);
}

PatternResult PatternGenerator::generatePattern(FunctionRef func) {
    PatternResult result;
    result.success = false;
    result.func_size = 0;

    // Collect raw bytes for meta logging
    std::vector<uint8_t> rawCollected;

    if (!m_bv || !func) {
        result.error = "Invalid binary view or function";
        return result;
    }

    // Get function name and address for debug logging
    std::string funcName = func->GetSymbol() ? func->GetSymbol()->GetFullName() : "<unnamed>";
    uint64_t funcAddr = func->GetStart();

    // Create debug dump if enabled
    std::unique_ptr<debug::FunctionDump> dump;
    if (isDebugEnabled()) {
        dump = std::make_unique<debug::FunctionDump>(funcName, funcAddr);
        dump->section("FUNCTION INFO");
        dump->logKeyValue("Name", funcName);
        dump->logKeyValue("Start Address", funcAddr);
        dump->logKeyValue("Architecture", m_maskGen->getName());
    }

    // Get function address ranges and find the full extent
    // IDA includes ALL bytes from function start to end, including alignment NOPs
    // between basic blocks, so we need to do the same
    auto addrRanges = func->GetAddressRanges();
    uint64_t funcStart = func->GetStart();
    uint64_t funcEnd = funcStart;
    uint64_t imageStart = m_bv ? m_bv->GetStart() : 0;
    uint64_t imageEnd = m_bv ? m_bv->GetEnd() : 0;

    // Find the maximum end address across all ranges
    for (const auto& range : addrRanges) {
        if (range.end > funcEnd) {
            funcEnd = range.end;
        }
    }

    // Preserve contiguous function chunks so x86/x64 control-flow masking can
    // approximate IDA's same_chunk() behavior instead of treating the whole
    // function extent as one contiguous region.
    std::vector<std::pair<uint64_t, uint64_t>> chunkRanges;
    chunkRanges.reserve(addrRanges.size());
    for (const auto& range : addrRanges) {
        if (range.end > range.start) {
            chunkRanges.emplace_back(range.start, range.end);
        }
    }

    // Also check basic blocks in case address ranges are incomplete
    auto blocks = func->GetBasicBlocks();
    std::vector<std::pair<uint64_t, uint64_t>> blockRanges;
    blockRanges.reserve(blocks.size());

    for (auto& block : blocks) {
        blockRanges.emplace_back(block->GetStart(), block->GetEnd());
        if (block->GetEnd() > funcEnd) {
            funcEnd = block->GetEnd();
        }
    }

    if (chunkRanges.empty()) {
        chunkRanges = blockRanges;
    }

    auto mergeRangeVector = [](std::vector<std::pair<uint64_t, uint64_t>>& ranges) {
        std::sort(ranges.begin(), ranges.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });

        std::vector<std::pair<uint64_t, uint64_t>> merged;
        for (const auto& range : ranges) {
            if (range.second <= range.first) {
                continue;
            }

            if (merged.empty() || range.first > merged.back().second) {
                merged.push_back(range);
            } else {
                merged.back().second = std::max(merged.back().second, range.second);
            }
        }
        ranges = std::move(merged);
    };

    mergeRangeVector(chunkRanges);

    std::sort(blockRanges.begin(), blockRanges.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    auto arch = m_bv->GetDefaultArchitecture();

    if (dump) {
        dump->logBasicBlocks(blockRanges);
        dump->section("INSTRUCTIONS");
        dump->log("Function range: 0x" + std::to_string(funcStart) + " - 0x" + std::to_string(funcEnd));
        dump->log("Total bytes: " + std::to_string(funcEnd - funcStart));
    }

    // Process ALL bytes from function start to end (not just basic blocks)
    // This includes alignment NOPs between basic blocks, which IDA includes
    // IDA's algorithm:
    // 1. normalized_byte = raw_byte & ~mask_byte
    // 2. hash = MD5(normalized_bytes || mask_bytes)
    std::vector<uint8_t> normalized;
    std::vector<uint8_t> masks;

    // Set function range for the mask generator so it can determine
    // if RIP-relative targets are external references (should be masked)
    // or internal references (should not be masked)
    m_maskGen->setFunctionRange(funcStart, funcEnd);
    m_maskGen->setFunctionChunks(chunkRanges);

    // Linear disassembly from funcStart to funcEnd
    uint64_t addr = funcStart;
    while (addr < funcEnd) {
        // Get instruction length
        size_t maxLen = static_cast<size_t>(funcEnd - addr);
        if (maxLen > 16) maxLen = 16;  // Max instruction length

        // Read raw bytes
        BinaryNinja::DataBuffer buf = m_bv->ReadBuffer(addr, maxLen);
        if (buf.GetLength() == 0) {
            addr++;
            continue;
        }

        const uint8_t* data = reinterpret_cast<const uint8_t*>(buf.GetData());
        size_t bufLen = buf.GetLength();

        // Get instruction info for length
        BinaryNinja::InstructionInfo info;
        size_t insnLen = 1;  // Default

        if (arch && arch->GetInstructionInfo(data, addr, bufLen, info)) {
            insnLen = info.length;
            if (insnLen == 0) insnLen = 1;
        }

        if (insnLen > bufLen) insnLen = bufLen;

        // Get raw instruction bytes
        std::vector<uint8_t> rawBytes(data, data + insnLen);
        rawCollected.insert(rawCollected.end(), rawBytes.begin(), rawBytes.end());

        // Get mask for this instruction
        InstructionMask mask = m_maskGen->getMask(m_bv.GetPtr(), addr, rawBytes);

        // Apply normalization and collect masks (IDA's algorithm)
        std::vector<uint8_t> insnNormalized;
        for (size_t i = 0; i < rawBytes.size(); i++) {
            uint8_t m = (i < mask.mask.size()) ? mask.mask[i] : 0;
            uint8_t n = rawBytes[i] & ~m;  // normalized = raw & ~mask
            normalized.push_back(n);
            masks.push_back(m);
            insnNormalized.push_back(n);
        }

        // Log instruction details
        if (dump) {
            // Get disassembly if available
            std::string disasm;
            if (arch) {
                std::vector<BinaryNinja::InstructionTextToken> tokens;
                if (arch->GetInstructionText(data, addr, insnLen, tokens)) {
                    for (const auto& tok : tokens) {
                        disasm += tok.text;
                    }
                }
            }
            dump->logInstruction(addr, rawBytes, mask.mask, insnNormalized, disasm);
        }

        result.func_size += static_cast<uint32_t>(insnLen);
        addr += insnLen;
    }

    // Compute MD5 hash: MD5(normalized_bytes || mask_bytes)
    // This matches IDA's Lumina hash computation algorithm
    result.normalized = std::move(normalized);
    result.masks = std::move(masks);
    result.hash = computeMD5(result.normalized, result.masks);
    result.success = true;

    // Log final results
    if (dump) {
        dump->logFinalNormalized(result.normalized);
        dump->logHash(result.hash);
        dump->section("SUMMARY");
        dump->logKeyValue("Total bytes", result.func_size);
        dump->logKeyValue("Normalized bytes", (uint64_t)result.normalized.size());
        dump->logKeyValue("Mask bytes", (uint64_t)result.masks.size());
        dump->log("\nHash computed as MD5(normalized || masks) to match IDA");
        dump->log("\nDebug file: " + dump->getFilename());
    }

    if (m_debug) {
        BinaryNinja::LogInfo("PatternGen: %s - %zu bytes, hash: %02x%02x%02x%02x...",
            m_maskGen->getName().c_str(),
            result.normalized.size(),
            result.hash[0], result.hash[1], result.hash[2], result.hash[3]);
    }

    // Optional per-function summary logging for deeper diagnostics
    if (isMetaLoggingEnabled()) {
        appendMetaLog(funcName, funcStart, funcEnd, imageStart, imageEnd,
                      rawCollected, result.normalized, result.masks, result.hash, m_bv.GetPtr());
    }

    // Optional raw/normalized/mask dumps for post-mortem analysis
    dumpBytesToFiles(funcName, funcStart, rawCollected, result.normalized, result.masks);

    return result;
}

std::array<uint8_t, 16> PatternGenerator::computeMD5(
    const std::vector<uint8_t>& normalized_bytes,
    const std::vector<uint8_t>& mask_bytes)
{
    // IDA's algorithm: MD5(normalized_bytes || mask_bytes)
    // Where normalized_bytes[i] = raw_bytes[i] & ~mask_bytes[i]
    // The hash is computed over the concatenation of:
    // 1. Normalized instruction bytes (position-independent)
    // 2. The mask bytes (indicating which positions were masked)
    QCryptographicHash hash(QCryptographicHash::Md5);
    if (!normalized_bytes.empty()) {
        hash.addData(QByteArrayView(reinterpret_cast<const char*>(normalized_bytes.data()),
                                    qsizetype(normalized_bytes.size())));
    }
    if (!mask_bytes.empty()) {
        hash.addData(QByteArrayView(reinterpret_cast<const char*>(mask_bytes.data()),
                                    qsizetype(mask_bytes.size())));
    }
    QByteArray result = hash.result();

    std::array<uint8_t, 16> out{};
    for (int i = 0; i < 16 && i < result.size(); i++) {
        out[i] = static_cast<uint8_t>(result[i]);
    }
    return out;
}

// ============================================================================
// Convenience Functions
// ============================================================================

std::array<uint8_t, 16> computeCalcRelHash(
    BinaryViewRef bv,
    FunctionRef func)
{
    PatternGenerator gen(bv);
    PatternResult result = gen.generatePattern(func);
    if (result.success) {
        return result.hash;
    }
    return std::array<uint8_t, 16>{};
}

PatternResult computePattern(
    BinaryViewRef bv,
    FunctionRef func)
{
    PatternGenerator gen(bv);
    return gen.generatePattern(func);
}

// ============================================================================
// Pull Filtering Heuristic
// ============================================================================

static uint64_t getFunctionExtentEnd(FunctionRef func)
{
    if (!func) {
        return 0;
    }

    uint64_t funcEnd = func->GetStart();
    for (const auto& range : func->GetAddressRanges()) {
        funcEnd = std::max(funcEnd, range.end);
    }
    for (auto& block : func->GetBasicBlocks()) {
        funcEnd = std::max(funcEnd, block->GetEnd());
    }
    return funcEnd;
}

static PullFilterResult detectLikelyArm64SplitTailMismatch(BinaryViewRef bv, FunctionRef func)
{
    PullFilterResult result;
    result.shouldSkip = false;

    if (!bv || !func) {
        return result;
    }

    auto arch = bv->GetDefaultArchitecture();
    if (!arch) {
        return result;
    }

    const std::string archName = arch->GetName();
    if (archName != "aarch64" && archName != "arm64" && archName != "aarch64be") {
        return result;
    }

    const uint64_t funcStart = func->GetStart();
    const uint64_t funcEnd = getFunctionExtentEnd(func);
    if (funcEnd <= funcStart) {
        return result;
    }

    constexpr uint64_t kNearbyTailWindow = 0x300;

    uint64_t addr = funcStart;
    while (addr < funcEnd) {
        size_t maxLen = static_cast<size_t>(funcEnd - addr);
        if (maxLen > 16) {
            maxLen = 16;
        }

        BinaryNinja::DataBuffer buf = bv->ReadBuffer(addr, maxLen);
        if (buf.GetLength() == 0) {
            ++addr;
            continue;
        }

        const uint8_t* data = reinterpret_cast<const uint8_t*>(buf.GetData());
        size_t bufLen = buf.GetLength();

        BinaryNinja::InstructionInfo info;
        size_t insnLen = 1;
        if (arch->GetInstructionInfo(data, addr, bufLen, info)) {
            insnLen = info.length;
            if (insnLen == 0) {
                insnLen = 1;
            }
        }
        if (insnLen > bufLen) {
            insnLen = bufLen;
        }

        if (insnLen == 4 && bufLen >= 4) {
            uint32_t insn = 0;
            insn |= static_cast<uint32_t>(data[0]);
            insn |= static_cast<uint32_t>(data[1]) << 8;
            insn |= static_cast<uint32_t>(data[2]) << 16;
            insn |= static_cast<uint32_t>(data[3]) << 24;

            bool hasTarget = false;
            uint64_t target = 0;

            if (arm64::isBranch(insn) && !arm64::isBL(insn)) {
                target = static_cast<uint64_t>(static_cast<int64_t>(addr) + arm64::branchOffset26(insn));
                hasTarget = true;
            } else if (arm64::isBranchCond(insn) || arm64::isCBZ(insn)) {
                target = static_cast<uint64_t>(static_cast<int64_t>(addr) + arm64::branchOffset19(insn));
                hasTarget = true;
            } else if (arm64::isTBZ(insn)) {
                target = static_cast<uint64_t>(static_cast<int64_t>(addr) + arm64::branchOffset14(insn));
                hasTarget = true;
            }

            if (hasTarget && target >= funcEnd && target <= (funcEnd + kNearbyTailWindow)) {
                auto seg = bv->GetSegmentAt(target);
                if (seg && ((seg->GetFlags() & 0x1) != 0)) {
                    ++result.suspiciousBranchCount;
                    if (result.firstSuspiciousSource == 0) {
                        result.firstSuspiciousSource = addr;
                        result.firstSuspiciousTarget = target;
                    }
                }
            }
        }

        addr += insnLen;
    }

    if (result.suspiciousBranchCount > 0) {
        result.shouldSkip = true;
        result.reason = "Likely ARM64 split-tail layout mismatch ("
            + std::to_string(result.suspiciousBranchCount)
            + " nearby executable non-call branch"
            + (result.suspiciousBranchCount == 1 ? std::string() : std::string("es"))
            + ", first " + debug::hexAddr(result.firstSuspiciousSource)
            + " -> " + debug::hexAddr(result.firstSuspiciousTarget) + ")";
    }

    return result;
}

PullFilterResult shouldSkipPull(BinaryViewRef bv, FunctionRef func)
{
    PullFilterResult result;
    result.shouldSkip = false;

    if (!bv || !func) {
        result.shouldSkip = true;
        result.reason = "Invalid binary view or function";
        return result;
    }

    // Get function name
    std::string funcName;
    auto symbol = func->GetSymbol();
    if (symbol) {
        funcName = symbol->GetShortName();
    }

    // Skip CRT/runtime functions that IDA doesn't push
    // Note: IDA DOES push deregister_tm_clones, register_tm_clones, __do_global_dtors_aux
    // so we don't skip those
    static const std::vector<std::string> crtFunctions = {
        "_init",
        "_fini",
        "frame_dummy",
        "__libc_csu_init",
        "__libc_csu_fini",
        "__libc_start_main",
        "_dl_relocate_static_pie"
    };

    for (const auto& crtName : crtFunctions) {
        if (funcName == crtName) {
            result.shouldSkip = true;
            result.reason = "CRT function: " + funcName;
            return result;
        }
    }

    // Check if function is in PLT section
    uint64_t funcStart = func->GetStart();
    auto sections = bv->GetSectionsAt(funcStart);
    for (auto& sec : sections) {
        std::string secName = sec->GetName();
        if (secName == ".plt" || secName == ".plt.got" || secName == ".plt.sec") {
            result.shouldSkip = true;
            result.reason = "PLT stub in section: " + secName;
            return result;
        }
    }

    PullFilterResult mismatchRisk = detectLikelyArm64SplitTailMismatch(bv, func);
    if (mismatchRisk.shouldSkip) {
        return mismatchRisk;
    }

    return result;
}

} // namespace lumina
