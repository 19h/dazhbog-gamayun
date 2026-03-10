#include "lumina_type_decoder.h"

#include "lumina_protocol.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace lumina {

namespace {

constexpr uint8_t TYPE_BASE_MASK = 0x0F;
constexpr uint8_t TYPE_FLAGS_MASK = 0x30;
constexpr uint8_t TYPE_MODIF_MASK = 0xC0;

constexpr uint8_t BT_UNK = 0x00;
constexpr uint8_t BT_VOID = 0x01;
constexpr uint8_t BT_INT8 = 0x02;
constexpr uint8_t BT_INT16 = 0x03;
constexpr uint8_t BT_INT32 = 0x04;
constexpr uint8_t BT_INT64 = 0x05;
constexpr uint8_t BT_INT128 = 0x06;
constexpr uint8_t BT_INT = 0x07;
constexpr uint8_t BT_BOOL = 0x08;
constexpr uint8_t BT_FLOAT = 0x09;
constexpr uint8_t BT_PTR = 0x0A;
constexpr uint8_t BT_ARRAY = 0x0B;
constexpr uint8_t BT_FUNC = 0x0C;
constexpr uint8_t BT_COMPLEX = 0x0D;
constexpr uint8_t BT_BITFIELD = 0x0E;

constexpr uint8_t BTMT_SIZE0 = 0x00;
constexpr uint8_t BTMT_SIZE12 = 0x10;
constexpr uint8_t BTMT_SIZE48 = 0x20;
constexpr uint8_t BTMT_SIZE128 = 0x30;

constexpr uint8_t BTMT_UNKSIGN = 0x00;
constexpr uint8_t BTMT_SIGNED = 0x10;
constexpr uint8_t BTMT_USIGNED = 0x20;
constexpr uint8_t BTMT_CHAR = 0x30;

constexpr uint8_t BTMT_DEFBOOL = 0x00;
constexpr uint8_t BTMT_BOOL1 = 0x10;
constexpr uint8_t BTMT_BOOL2 = 0x20;
constexpr uint8_t BTMT_BOOL4 = 0x30;

constexpr uint8_t BTMT_FLOAT = 0x00;
constexpr uint8_t BTMT_DOUBLE = 0x10;
constexpr uint8_t BTMT_LNGDBL = 0x20;
constexpr uint8_t BTMT_SPECFLT = 0x30;

constexpr uint8_t BTMT_DEFPTR = 0x00;
constexpr uint8_t BTMT_NEAR = 0x10;
constexpr uint8_t BTMT_FAR = 0x20;
constexpr uint8_t BTMT_CLOSURE = 0x30;

constexpr uint8_t BTMT_NONBASED = 0x10;

constexpr uint8_t BTMT_STRUCT = 0x00;
constexpr uint8_t BTMT_UNION = 0x10;
constexpr uint8_t BTMT_ENUM = 0x20;
constexpr uint8_t BTMT_TYPEDEF = 0x30;

constexpr uint8_t BTMT_BFLDI8 = 0x00;
constexpr uint8_t BTMT_BFLDI16 = 0x10;
constexpr uint8_t BTMT_BFLDI32 = 0x20;
constexpr uint8_t BTMT_BFLDI64 = 0x30;

constexpr uint8_t BTM_CONST = 0x40;
constexpr uint8_t BTM_VOLATILE = 0x80;

constexpr uint8_t RESERVED_BYTE = 0xFF;
constexpr uint8_t TAH_BYTE = 0xFE;
constexpr uint8_t FAH_BYTE = 0xFF;

constexpr uint32_t MAX_DECL_ALIGN = 0x000F;
constexpr uint32_t TAH_HASATTRS = 0x0010;

constexpr uint32_t TAUDT_UNALIGNED = 0x0040;
constexpr uint32_t TAUDT_MSSTRUCT = 0x0020;
constexpr uint32_t TAUDT_CPPOBJ = 0x0080;
constexpr uint32_t TAUDT_VFTABLE = 0x0100;
constexpr uint32_t TAUDT_FLDREPR = 0x0200;
constexpr uint32_t TAUDT_FIXED = 0x0400;
constexpr uint32_t TAUDT_TUPLE = 0x0800;
constexpr uint32_t TAUDT_IFACE = 0x1000;

constexpr uint32_t TAFLD_METHOD = 0x0200;

constexpr uint32_t TAPTR_PTR32 = 0x0020;
constexpr uint32_t TAPTR_PTR64 = 0x0040;
constexpr uint32_t TAPTR_RESTRICT = 0x0060;
constexpr uint32_t TAPTR_SHIFTED = 0x0080;

constexpr uint32_t TAENUM_64BIT = 0x0020;
constexpr uint32_t TAENUM_UNSIGNED = 0x0040;
constexpr uint32_t TAENUM_SIGNED = 0x0080;
constexpr uint32_t TAENUM_OCT = 0x0100;
constexpr uint32_t TAENUM_BIN = 0x0200;
constexpr uint32_t TAENUM_NUMSIGN = 0x0400;
constexpr uint32_t TAENUM_LZERO = 0x0800;

constexpr uint8_t BTE_ALWAYS = 0x80;
constexpr uint8_t BTE_BITMASK = 0x10;

constexpr uint8_t CM_CC_MASK = 0xF0;
constexpr uint8_t CM_CC_VOIDARG = 0x20;
constexpr uint8_t CM_CC_CDECL = 0x30;
constexpr uint8_t CM_CC_ELLIPSIS = 0x40;
constexpr uint8_t CM_CC_STDCALL = 0x50;
constexpr uint8_t CM_CC_PASCAL = 0x60;
constexpr uint8_t CM_CC_FASTCALL = 0x70;
constexpr uint8_t CM_CC_THISCALL = 0x80;
constexpr uint8_t CM_CC_SWIFT = 0x90;
constexpr uint8_t CM_CC_SPOILED = 0xA0;
constexpr uint8_t CM_CC_GOLANG = 0xB0;
constexpr uint8_t CM_CC_RESERVE3 = 0xC0;
constexpr uint8_t CM_CC_SPECIALE = 0xD0;
constexpr uint8_t CM_CC_SPECIALP = 0xE0;
constexpr uint8_t CM_CC_SPECIAL = 0xF0;
constexpr uint32_t CM_CC_LAST_USERCALL = 0xFF;

constexpr uint8_t BFA_FUNC_MARKER = 0x0F;
constexpr uint8_t BFA_FUNC_EXT_FORMAT = 0x80;
constexpr uint8_t EXT_FUNC_HAS_SPOILED_REGS = 0x01;

constexpr uint32_t FAI_HIDDEN = 0x0001;
constexpr uint32_t FAI_RETPTR = 0x0002;
constexpr uint32_t FAI_STRUCT = 0x0004;
constexpr uint32_t FAI_ARRAY = 0x0008;
constexpr uint32_t FAI_UNUSED = 0x0010;

constexpr uint32_t ALOC_STACK = 1;
constexpr uint32_t ALOC_DIST = 2;
constexpr uint32_t ALOC_REG1 = 3;
constexpr uint32_t ALOC_REG2 = 4;
constexpr uint32_t ALOC_RREL = 5;
constexpr uint32_t ALOC_STATIC = 6;

constexpr uint32_t WIDE_EA_BIT = 0x20;
constexpr uint32_t SERIALIZED_BADLOC = 0x40;
constexpr uint32_t SCATTERED_BIT = 0x80;
constexpr uint32_t OLDBIT = 0x40;

constexpr uint32_t DQ_BNOT = 0x100;
constexpr uint32_t DQ_FF4 = 0x200;
constexpr uint32_t DQ_FF8 = 0x400;

constexpr uint8_t BV_MAGIC1 = 0xAC;
constexpr uint8_t BV_MAGIC2 = 0xAE;

struct TypeNode;

struct FunctionArg {
    std::string name;
    std::unique_ptr<TypeNode> type;
    std::optional<std::string> argloc;
    uint32_t flags = 0;
};

struct PrimitiveKind { std::string base; };
struct TyperefKind { std::string base; };
struct StructKind {
    std::optional<std::string> name;
    std::vector<std::pair<std::string, std::unique_ptr<TypeNode>>> members;
    bool isUnion = false;
};
struct EnumKind {
    std::optional<std::string> name;
    std::vector<std::string> members;
};
struct PointerKind { std::unique_ptr<TypeNode> inner; };
struct ArrayKind {
    std::unique_ptr<TypeNode> element;
    std::optional<uint32_t> count;
    std::optional<uint32_t> base;
};
struct FunctionKind {
    std::unique_ptr<TypeNode> ret;
    std::optional<std::string> cc;
    std::optional<std::string> retloc;
    std::vector<FunctionArg> args;
    bool varargs = false;
    bool unknownArgs = false;
};
struct BitfieldKind {
    std::string base;
    uint32_t width = 0;
    bool isUnsigned = false;
};

using TypeVariant = std::variant<PrimitiveKind, TyperefKind, StructKind, EnumKind, PointerKind, ArrayKind, FunctionKind, BitfieldKind>;

struct TypeNode {
    bool isConst = false;
    bool isVolatile = false;
    std::vector<std::string> attrs;
    TypeVariant kind;

    bool isVoid() const;
    std::string render(const std::optional<std::string>& name) const;
};

struct TypeAttr {
    std::vector<uint8_t> key;
    std::vector<uint8_t> value;
};

struct ParsedAttrHeader {
    uint8_t declAlign = 0;
    uint32_t bits = 0;
    std::vector<TypeAttr> attrs;
};

struct CallConv {
    uint32_t raw = 0;
    std::optional<std::string> keyword;
};

template <typename T>
using Result = std::optional<T>;

const uint8_t kEmptyByte = 0;

struct ByteView {
    const uint8_t* data = nullptr;
    size_t size = 0;

    ByteView() = default;
    ByteView(const uint8_t* bytes, size_t len) : data(len == 0 ? &kEmptyByte : bytes), size(len) {}
    ByteView(const std::vector<uint8_t>& bytes) : data(bytes.empty() ? &kEmptyByte : bytes.data()), size(bytes.size()) {}

    bool empty() const { return size == 0; }
    uint8_t front() const { return data[0]; }
    ByteView subspan(size_t offset) const { return offset > size ? ByteView{} : ByteView(data + offset, size - offset); }
    const uint8_t* begin() const { return data; }
    const uint8_t* end() const { return data + size; }
};

void appendCvPrefix(std::string& out, bool isConst, bool isVolatile)
{
    if (isConst)
        out += "const ";
    if (isVolatile)
        out += "volatile ";
}

void appendRenderAttrs(std::string& out, const std::vector<std::string>& attrs)
{
    if (attrs.empty())
        return;
    if (!out.empty())
        out.push_back(' ');
    for (size_t i = 0; i < attrs.size(); ++i)
    {
        if (i != 0)
            out.push_back(' ');
        out += attrs[i];
    }
}

std::string formatSignedDelta(int32_t delta)
{
    if (delta < 0)
        return "-0x" + [&]() { std::ostringstream ss; ss << std::hex << std::uppercase << static_cast<uint32_t>(-delta); return ss.str(); }();
    if (delta < 10)
        return std::to_string(delta);
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << static_cast<uint32_t>(delta);
    return ss.str();
}

std::string formatReg1(int32_t reg, int32_t off)
{
    if (off == 0)
        return "R" + std::to_string(reg);
    return "R" + std::to_string(reg) + "^" + std::to_string(off);
}

std::string formatReg2(int32_t regLo, int32_t regHi)
{
    return "R" + std::to_string(regHi) + ":R" + std::to_string(regLo);
}

std::string formatStackOffset(uint64_t value)
{
    return "^" + std::to_string(static_cast<int64_t>(value));
}

std::string formatRrel(int32_t reg, uint64_t off)
{
    const int64_t dist = static_cast<int64_t>(off);
    std::ostringstream ss;
    ss << "[R" << reg;
    if (dist < 0)
        ss << "-0x" << std::hex << std::uppercase << static_cast<uint64_t>(-dist);
    else
        ss << "+0x" << std::hex << std::uppercase << static_cast<uint64_t>(dist);
    ss << "]";
    return ss.str();
}

std::string formatEa(uint64_t ea)
{
    std::ostringstream ss;
    ss << "@0x" << std::hex << std::uppercase << ea;
    return ss.str();
}

std::optional<std::string> callconvKeyword(uint32_t raw)
{
    const uint32_t base = raw <= CM_CC_LAST_USERCALL ? (raw & static_cast<uint32_t>(CM_CC_MASK)) : raw;
    switch (base)
    {
    case CM_CC_CDECL: return "__cdecl";
    case CM_CC_STDCALL: return "__stdcall";
    case CM_CC_PASCAL: return "__pascal";
    case CM_CC_FASTCALL: return "__fastcall";
    case CM_CC_THISCALL: return "__thiscall";
    case CM_CC_SWIFT: return "__swiftcall";
    case CM_CC_GOLANG: return "__golang";
    case CM_CC_SPECIAL:
    case CM_CC_SPECIALE:
        return "__usercall";
    case CM_CC_SPECIALP:
        return "__userpurge";
    default:
        break;
    }

    if (raw > CM_CC_LAST_USERCALL)
    {
        std::ostringstream ss;
        ss << "__cc(0x" << std::hex << std::uppercase << raw << ")";
        return ss.str();
    }
    return std::nullopt;
}

bool isUserCc(uint32_t raw)
{
    return raw >= CM_CC_SPECIALE && raw <= CM_CC_LAST_USERCALL;
}

bool isVarargCc(uint32_t raw)
{
    if (raw > CM_CC_LAST_USERCALL)
        return false;
    const uint32_t cc = raw & ~0x0FU;
    return cc == CM_CC_ELLIPSIS || cc == CM_CC_SPECIALE;
}

std::vector<std::string> formatArgFlags(uint32_t flags)
{
    std::vector<std::string> out;
    if ((flags & FAI_UNUSED) != 0)
        out.emplace_back("__unused");
    if ((flags & FAI_HIDDEN) != 0)
        out.emplace_back("__hidden");
    if ((flags & FAI_RETPTR) != 0)
        out.emplace_back("__return_ptr");
    if ((flags & FAI_STRUCT) != 0)
        out.emplace_back("__struct_ptr");
    if ((flags & FAI_ARRAY) != 0)
        out.emplace_back("__array_ptr");
    return out;
}

std::string simpleTypeName(uint8_t base, uint8_t flags)
{
    switch (base)
    {
    case BT_VOID:
        switch (flags)
        {
        case BTMT_SIZE0: return "void";
        case BTMT_SIZE12: return "_BYTE";
        case BTMT_SIZE48: return "_DWORD";
        case BTMT_SIZE128: return "_OWORD";
        default: return "void";
        }
    case BT_UNK:
        switch (flags)
        {
        case BTMT_SIZE12: return "_WORD";
        case BTMT_SIZE48: return "_QWORD";
        case BTMT_SIZE128: return "_UNKNOWN";
        default: return "_UNKNOWN";
        }
    case BT_INT8:
        switch (flags)
        {
        case BTMT_CHAR: return "char";
        case BTMT_USIGNED: return "unsigned char";
        case BTMT_SIGNED: return "__int8";
        default: return "__int8";
        }
    case BT_INT16:
        return flags == BTMT_USIGNED ? "unsigned __int16" : "__int16";
    case BT_INT32:
        return flags == BTMT_USIGNED ? "unsigned __int32" : "__int32";
    case BT_INT64:
        return flags == BTMT_USIGNED ? "unsigned __int64" : "__int64";
    case BT_INT128:
        return flags == BTMT_USIGNED ? "unsigned __int128" : "__int128";
    case BT_INT:
        switch (flags)
        {
        case BTMT_USIGNED: return "unsigned int";
        case BTMT_SIGNED: return "signed int";
        case BTMT_CHAR: return "__seg";
        default: return "int";
        }
    case BT_BOOL:
        switch (flags)
        {
        case BTMT_BOOL1: return "_BOOL1";
        case BTMT_BOOL2: return "_BOOL2";
        case BTMT_BOOL4: return "_BOOL4";
        default: return "bool";
        }
    case BT_FLOAT:
        switch (flags)
        {
        case BTMT_FLOAT: return "float";
        case BTMT_DOUBLE: return "double";
        case BTMT_LNGDBL: return "long double";
        case BTMT_SPECFLT: return "_TBYTE";
        default: return "float";
        }
    default:
        break;
    }

    std::ostringstream ss;
    ss << "<type base=0x" << std::hex << std::uppercase << static_cast<uint32_t>(base)
       << " flags=0x" << static_cast<uint32_t>(flags) << ">";
    return ss.str();
}

bool isSdaclByte(uint8_t value)
{
    return (((value & static_cast<uint8_t>(~TYPE_FLAGS_MASK)) ^ TYPE_MODIF_MASK) <= BT_VOID);
}

bool isPrintableAscii(const std::vector<uint8_t>& bytes)
{
    return std::all_of(bytes.begin(), bytes.end(), [](uint8_t byte) {
        return std::isgraph(byte) != 0 || byte == ' ' || byte == '\t';
    });
}

std::string escapeBytesImpl(ByteView bytes)
{
    std::ostringstream ss;
    for (uint8_t byte : bytes)
    {
        switch (byte)
        {
        case '\\': ss << "\\\\"; break;
        case '\n': ss << "\\n"; break;
        case '\r': ss << "\\r"; break;
        case '\t': ss << "\\t"; break;
        default:
            if (byte >= 0x20 && byte <= 0x7E)
                ss << static_cast<char>(byte);
            else
            {
                ss << "\\x";
                static constexpr char kHex[] = "0123456789ABCDEF";
                ss << kHex[(byte >> 4) & 0xF] << kHex[byte & 0xF];
            }
            break;
        }
    }
    return ss.str();
}

std::optional<std::vector<uint32_t>> decodeAttrDdValues(const std::vector<uint8_t>& buffer, size_t count)
{
    std::vector<uint32_t> out;
    out.reserve(count);
    size_t offset = 0;
    for (size_t i = 0; i < count; ++i)
    {
        uint32_t value = 0;
        size_t consumed = 0;
        if (!unpack_dd(buffer.data() + offset, buffer.size() - offset, value, consumed) || consumed == 0)
            return std::nullopt;
        out.push_back(value);
        offset += consumed;
    }
    if (offset != buffer.size())
        return std::nullopt;
    return out;
}

std::string formatAttrKey(const std::vector<uint8_t>& key)
{
    if (key.size() == 1 && key[0] == 1)
        return "value_repr";
    if (std::all_of(key.begin(), key.end(), [](uint8_t byte) {
            return std::isalnum(byte) != 0 || byte == '_' || byte == ':';
        }))
    {
        return std::string(key.begin(), key.end());
    }
    return escapeBytesImpl(ByteView(key));
}

std::string formatAttrValue(const TypeAttr& attr)
{
    if (attr.value.empty())
        return {};

    if (attr.key == std::vector<uint8_t>{'_', '_', 'o', 'r', 'g', '_', 'a', 'r', 'r', 'd', 'i', 'm'})
    {
        auto vals = decodeAttrDdValues(attr.value, 2);
        if (vals)
            return std::to_string((*vals)[0]) + "," + std::to_string((*vals)[1]);
    }
    else if (attr.key == std::vector<uint8_t>{'f', 'o', 'r', 'm', 'a', 't'})
    {
        auto vals = decodeAttrDdValues(attr.value, 3);
        if (vals)
        {
            const char* func = "?";
            switch ((*vals)[0])
            {
            case 0: func = "printf"; break;
            case 1: func = "scanf"; break;
            case 2: func = "strftime"; break;
            case 3: func = "strfmon"; break;
            default: break;
            }
            return std::string(func) + "," + std::to_string((*vals)[1]) + "," + std::to_string((*vals)[2]);
        }
    }

    if (isPrintableAscii(attr.value))
        return std::string(attr.value.begin(), attr.value.end());
    return escapeBytesImpl(ByteView(attr.value));
}

std::string formatTypeAttrToken(const TypeAttr& attr)
{
    const std::string key = formatAttrKey(attr.key);
    const std::string value = formatAttrValue(attr);
    if (value.empty())
        return "__attribute__((" + key + "))";
    return "__attribute__((" + key + "(" + value + ")))";
}

std::vector<std::string> collectAttrTokens(const ParsedAttrHeader& header, uint32_t knownBits)
{
    std::vector<std::string> out;
    if (header.declAlign != 0)
    {
        const uint32_t align = 1U << static_cast<uint32_t>(std::max<int>(0, header.declAlign - 1));
        out.push_back("__align(" + std::to_string(align) + ")");
    }
    for (const auto& attr : header.attrs)
        out.push_back(formatTypeAttrToken(attr));

    const uint32_t unknown = header.bits & ~(knownBits | TAH_HASATTRS);
    if (unknown != 0)
    {
        std::ostringstream ss;
        ss << "__tah_bits(0x" << std::hex << std::uppercase << unknown << ")";
        out.push_back(ss.str());
    }
    return out;
}

std::vector<std::string> collectUdtAttrTokens(const ParsedAttrHeader& header)
{
    std::vector<std::string> out;
    if ((header.bits & TAUDT_UNALIGNED) != 0) out.push_back("__unaligned");
    if ((header.bits & TAUDT_MSSTRUCT) != 0) out.push_back("__msstruct");
    if ((header.bits & TAUDT_CPPOBJ) != 0) out.push_back("__cppobj");
    if ((header.bits & TAUDT_VFTABLE) != 0) out.push_back("__vftable");
    if ((header.bits & TAUDT_FIXED) != 0) out.push_back("__fixed");
    if ((header.bits & TAUDT_TUPLE) != 0) out.push_back("__tuple");
    if ((header.bits & TAUDT_IFACE) != 0) out.push_back("__interface");

    auto extra = collectAttrTokens(header,
        TAUDT_UNALIGNED | TAUDT_MSSTRUCT | TAUDT_CPPOBJ | TAUDT_VFTABLE |
        TAUDT_FLDREPR | TAUDT_FIXED | TAUDT_TUPLE | TAUDT_IFACE);
    out.insert(out.end(), extra.begin(), extra.end());
    return out;
}

std::vector<std::string> collectEnumAttrTokens(const ParsedAttrHeader& header)
{
    std::vector<std::string> out;
    if ((header.bits & TAENUM_64BIT) != 0) out.push_back("__enum64");
    if ((header.bits & TAENUM_UNSIGNED) != 0) out.push_back("__enum_unsigned");
    if ((header.bits & TAENUM_SIGNED) != 0) out.push_back("__enum_signed");
    if ((header.bits & TAENUM_OCT) != 0) out.push_back("__enum_octal");
    if ((header.bits & TAENUM_BIN) != 0) out.push_back("__enum_binary");
    if ((header.bits & TAENUM_NUMSIGN) != 0) out.push_back("__enum_numsign");
    if ((header.bits & TAENUM_LZERO) != 0) out.push_back("__enum_lzero");

    auto extra = collectAttrTokens(header,
        TAENUM_64BIT | TAENUM_UNSIGNED | TAENUM_SIGNED | TAENUM_OCT |
        TAENUM_BIN | TAENUM_NUMSIGN | TAENUM_LZERO);
    out.insert(out.end(), extra.begin(), extra.end());
    return out;
}

std::string formatShiftedAttr(const TypeNode& parent, int32_t delta)
{
    return "__shifted(" + parent.render(std::nullopt) + ", " + formatSignedDelta(delta) + ")";
}

class Decoder {
public:
    Decoder(ByteView type, ByteView fields) : m_type(type), m_fields(fields) {}

    std::optional<std::string> error() const { return m_error.empty() ? std::nullopt : std::optional<std::string>(m_error); }
    ByteView typeRemainder() const { return m_type; }
    ByteView fieldsRemainder() const { return m_fields; }

    Result<TypeNode> parseType()
    {
        auto t = readByte();
        if (!t)
            return fail<TypeNode>("truncated type string");

        const bool isConst = (*t & BTM_CONST) != 0;
        const bool isVolatile = (*t & BTM_VOLATILE) != 0;
        const uint8_t base = *t & TYPE_BASE_MASK;
        const uint8_t flags = *t & TYPE_FLAGS_MASK;

        std::optional<TypeVariant> kind;
        std::vector<std::string> attrs;

        switch (base)
        {
        case BT_UNK:
        case BT_VOID:
        case BT_INT8:
        case BT_INT16:
        case BT_INT32:
        case BT_INT64:
        case BT_INT128:
        case BT_INT:
        case BT_BOOL:
        case BT_FLOAT:
        {
            auto header = parseOptionalTah();
            if (!header)
                return std::nullopt;
            attrs = collectAttrTokens(*header, 0);
            kind = PrimitiveKind{simpleTypeName(base, flags)};
            break;
        }
        case BT_PTR:
        {
            auto parsed = parsePointer(flags);
            if (!parsed)
                return std::nullopt;
            kind = std::move(parsed->first);
            attrs = std::move(parsed->second);
            break;
        }
        case BT_ARRAY:
        {
            auto parsed = parseArray(flags);
            if (!parsed)
                return std::nullopt;
            kind = std::move(parsed->first);
            attrs = std::move(parsed->second);
            break;
        }
        case BT_FUNC:
        {
            auto parsed = parseFunction(flags);
            if (!parsed)
                return std::nullopt;
            kind = std::move(parsed->first);
            attrs = std::move(parsed->second);
            break;
        }
        case BT_COMPLEX:
        {
            auto parsed = parseComplex(flags);
            if (!parsed)
                return std::nullopt;
            kind = std::move(parsed->first);
            attrs = std::move(parsed->second);
            break;
        }
        case BT_BITFIELD:
        {
            auto parsed = parseBitfield(flags);
            if (!parsed)
                return std::nullopt;
            kind = std::move(parsed->first);
            attrs = std::move(parsed->second);
            break;
        }
        default:
        {
            std::ostringstream ss;
            ss << "unsupported base type byte 0x" << std::hex << std::uppercase << static_cast<uint32_t>(base);
            return fail<TypeNode>(ss.str());
        }
        }

        TypeNode node;
        node.isConst = isConst;
        node.isVolatile = isVolatile;
        node.attrs = std::move(attrs);
        node.kind = std::move(*kind);
        return node;
    }

private:
    template <typename T>
    Result<T> fail(const std::string& error)
    {
        if (m_error.empty())
            m_error = error;
        return std::nullopt;
    }

    Result<std::pair<TypeVariant, std::vector<std::string>>> parsePointer(uint8_t flags)
    {
        std::vector<std::string> attrs;
        if (flags == BTMT_CLOSURE)
        {
            auto marker = readByte();
            if (!marker)
                return fail<std::pair<TypeVariant, std::vector<std::string>>>("truncated closure pointer");
            if (*marker == 0)
                return fail<std::pair<TypeVariant, std::vector<std::string>>>("malformed closure pointer");
            if (*marker == RESERVED_BYTE)
            {
                auto target = parseType();
                if (!target)
                    return std::nullopt;
                if (!std::holds_alternative<FunctionKind>(target->kind))
                    return fail<std::pair<TypeVariant, std::vector<std::string>>>("closure pointer does not point to function");
                attrs.emplace_back("__closure");
            }
            else
            {
                attrs.push_back("__based_ptr(" + std::to_string(*marker) + ")");
            }
        }
        else
        {
            switch (flags)
            {
            case BTMT_NEAR: attrs.emplace_back("__near"); break;
            case BTMT_FAR: attrs.emplace_back("__far"); break;
            case BTMT_DEFPTR: break;
            default:
            {
                std::ostringstream ss;
                ss << "__ptr_mode(0x" << std::hex << std::uppercase << static_cast<uint32_t>(flags) << ")";
                attrs.push_back(ss.str());
                break;
            }
            }
        }

        auto ptrHeader = parseOptionalTah();
        if (!ptrHeader)
            return std::nullopt;

        switch (ptrHeader->bits & TAPTR_RESTRICT)
        {
        case TAPTR_PTR32: attrs.emplace_back("__ptr32"); break;
        case TAPTR_PTR64: attrs.emplace_back("__ptr64"); break;
        case TAPTR_RESTRICT: attrs.emplace_back("__restrict"); break;
        default: break;
        }

        auto inner = parseType();
        if (!inner)
            return std::nullopt;

        if ((ptrHeader->bits & TAPTR_SHIFTED) != 0)
        {
            auto parent = parseType();
            if (!parent)
                return std::nullopt;
            auto delta = readDe();
            if (!delta)
                return std::nullopt;
            attrs.push_back(formatShiftedAttr(*parent, static_cast<int32_t>(*delta)));
        }

        auto extra = collectAttrTokens(*ptrHeader, TAPTR_RESTRICT | TAPTR_SHIFTED);
        attrs.insert(attrs.end(), extra.begin(), extra.end());

        PointerKind pointerKind;
        pointerKind.inner = std::make_unique<TypeNode>(std::move(*inner));
        return std::make_pair(TypeVariant(std::move(pointerKind)), std::move(attrs));
    }

    Result<std::pair<TypeVariant, std::vector<std::string>>> parseArray(uint8_t flags)
    {
        std::optional<uint32_t> count;
        std::optional<uint32_t> base;
        if ((flags & BTMT_NONBASED) != 0)
        {
            auto n = readDt();
            if (!n)
                return std::nullopt;
            if (*n != 0)
                count = static_cast<uint32_t>(*n);
        }
        else
        {
            auto values = readDa();
            if (!values)
                return std::nullopt;
            if (values->first != 0)
                count = values->first;
            base = values->second;
        }

        auto attrHeader = parseOptionalTah();
        if (!attrHeader)
            return std::nullopt;
        auto elem = parseType();
        if (!elem)
            return std::nullopt;

        ArrayKind kind;
        kind.element = std::make_unique<TypeNode>(std::move(*elem));
        kind.count = count;
        kind.base = base;
        return std::make_pair(TypeVariant(std::move(kind)), collectAttrTokens(*attrHeader, 0));
    }

    Result<std::pair<TypeVariant, std::vector<std::string>>> parseFunction(uint8_t)
    {
        if (!skipFuncAttrs())
            return std::nullopt;
        auto cc = readCallConv();
        if (!cc)
            return std::nullopt;
        auto attrHeader = parseOptionalTah();
        if (!attrHeader)
            return std::nullopt;

        const auto retStart = m_type;
        Decoder retDecoder(m_type, {});
        auto ret = retDecoder.parseType();
        if (!ret)
            return fail<std::pair<TypeVariant, std::vector<std::string>>>(retDecoder.error().value_or("failed to parse function return type"));
        m_type = retDecoder.typeRemainder();

        std::optional<std::string> retloc;
        if (isUserCc(cc->raw) && !ret->isVoid())
        {
            auto loc = parseArgloc(false);
            if (!loc)
                return std::nullopt;
            if (*loc == "BADLOC")
                return fail<std::pair<TypeVariant, std::vector<std::string>>>("invalid usercall return location");
            retloc = *loc;
        }

        std::vector<FunctionArg> args;
        bool varargs = false;
        bool unknownArgs = false;
        if (cc->raw != CM_CC_VOIDARG)
        {
            auto n = readDt();
            if (!n)
                return std::nullopt;
            if (*n == 0)
            {
                if (isVarargCc(cc->raw))
                    varargs = true;
                else
                    unknownArgs = true;
            }
            else if (*n == 1)
            {
                const uint8_t preview = m_type.empty() ? 0 : m_type.front();
                if ((preview & TYPE_BASE_MASK) == BT_VOID && (preview & TYPE_FLAGS_MASK) == BTMT_SIZE0)
                {
                    Decoder voidDecoder(m_type, m_fields);
                    if (!voidDecoder.parseType())
                        return fail<std::pair<TypeVariant, std::vector<std::string>>>(voidDecoder.error().value_or("failed to parse void arg list"));
                    m_type = voidDecoder.typeRemainder();
                    m_fields = voidDecoder.fieldsRemainder();
                }
                else if (!parseFuncArgs(static_cast<size_t>(*n), cc->raw, args))
                {
                    return std::nullopt;
                }
            }
            else if (!parseFuncArgs(static_cast<size_t>(*n), cc->raw, args))
            {
                return std::nullopt;
            }
        }

        TypeNode retFinal = std::move(*ret);
        if (!m_fields.empty() && !retStart.empty() && ((retStart.front() & TYPE_BASE_MASK) > BT_FLOAT))
        {
            Decoder retWithFields(retStart, m_fields);
            auto parsed = retWithFields.parseType();
            if (parsed)
            {
                retFinal = std::move(*parsed);
                m_fields = retWithFields.fieldsRemainder();
            }
        }

        FunctionKind kind;
        kind.ret = std::make_unique<TypeNode>(std::move(retFinal));
        kind.cc = cc->keyword;
        kind.retloc = retloc;
        kind.args = std::move(args);
        kind.varargs = varargs;
        kind.unknownArgs = unknownArgs;
        return std::make_pair(TypeVariant(std::move(kind)), collectAttrTokens(*attrHeader, 0));
    }

    bool parseFuncArgs(size_t count, uint32_t ccRaw, std::vector<FunctionArg>& args)
    {
        for (size_t i = 0; i < count; ++i)
        {
            std::string argName = readName().value_or(std::string());
            uint32_t argFlags = 0;
            if (peekByte() == FAH_BYTE)
            {
                m_type = m_type.subspan(1);
                auto flags = readDe();
                if (!flags)
                    return false;
                argFlags = *flags;
            }

            auto argType = parseType();
            if (!argType)
                return false;

            std::optional<std::string> argloc;
            if (isUserCc(ccRaw))
            {
                argloc = parseArgloc(false);
                if (!argloc)
                    return false;
                if (*argloc == "BADLOC")
                {
                    fail<int>("invalid usercall argument location");
                    return false;
                }
            }

            FunctionArg arg;
            arg.name = std::move(argName);
            arg.type = std::make_unique<TypeNode>(std::move(*argType));
            arg.argloc = std::move(argloc);
            arg.flags = argFlags;
            args.push_back(std::move(arg));
        }
        return true;
    }

    Result<std::pair<TypeVariant, std::vector<std::string>>> parseComplex(uint8_t flags)
    {
        if (flags == BTMT_TYPEDEF)
        {
            TyperefKind kind{readTypeName().value_or(std::string("<anon_typeref>"))};
            auto attrHeader = parseOptionalTah();
            if (!attrHeader)
                return std::nullopt;
            return std::make_pair(TypeVariant(std::move(kind)), collectAttrTokens(*attrHeader, 0));
        }

        auto n = readComplexN();
        if (!n)
            return std::nullopt;

        if (*n == 0)
        {
            std::optional<std::string> name = readTypeName();
            auto sdacl = parseOptionalSdacl();
            if (!sdacl)
                return std::nullopt;
            switch (flags)
            {
            case BTMT_STRUCT:
            {
                StructKind kind;
                kind.name = name;
                kind.isUnion = false;
                return std::make_pair(TypeVariant(std::move(kind)), collectUdtAttrTokens(*sdacl));
            }
            case BTMT_UNION:
            {
                StructKind kind;
                kind.name = name;
                kind.isUnion = true;
                return std::make_pair(TypeVariant(std::move(kind)), collectUdtAttrTokens(*sdacl));
            }
            case BTMT_ENUM:
            {
                EnumKind kind;
                kind.name = name;
                return std::make_pair(TypeVariant(std::move(kind)), collectEnumAttrTokens(*sdacl));
            }
            default:
                return fail<std::pair<TypeVariant, std::vector<std::string>>>("unknown complex subtype");
            }
        }

        if (flags == BTMT_STRUCT || flags == BTMT_UNION)
            return parseUdt(*n, flags == BTMT_UNION);
        if (flags == BTMT_ENUM)
            return parseEnum(*n);
        return fail<std::pair<TypeVariant, std::vector<std::string>>>("unknown complex subtype");
    }

    Result<std::pair<TypeVariant, std::vector<std::string>>> parseUdt(uint32_t n, bool isUnion)
    {
        const size_t memberCount = static_cast<size_t>(n >> 3);
        auto header = parseOptionalSdacl();
        if (!header)
            return std::nullopt;
        const bool fixed = (header->bits & TAUDT_FIXED) != 0;

        StructKind kind;
        kind.isUnion = isUnion;
        kind.members.reserve(memberCount);
        for (size_t i = 0; i < memberCount; ++i)
        {
            const std::string memberName = readName().value_or(std::string());
            auto memberType = parseType();
            if (!memberType)
                return std::nullopt;

            uint32_t memberBits = 0;
            if (peekByte() && isSdaclByte(*peekByte()))
            {
                auto memberHeader = parseOptionalSdacl();
                if (!memberHeader)
                    return std::nullopt;
                memberBits = memberHeader->bits;
            }

            if (fixed && (memberBits & TAFLD_METHOD) == 0)
            {
                if (!readDq())
                    return std::nullopt;
            }

            kind.members.emplace_back(memberName, std::make_unique<TypeNode>(std::move(*memberType)));
        }

        if (fixed && !readDq())
            return std::nullopt;

        return std::make_pair(TypeVariant(std::move(kind)), collectUdtAttrTokens(*header));
    }

    Result<std::pair<TypeVariant, std::vector<std::string>>> parseEnum(uint32_t n)
    {
        auto header = parseOptionalTah();
        if (!header)
            return std::nullopt;
        const bool enum64 = (header->bits & TAENUM_64BIT) != 0;

        auto bte = readByte();
        if (!bte)
            return fail<std::pair<TypeVariant, std::vector<std::string>>>("truncated enum");
        if ((*bte & BTE_ALWAYS) == 0)
            return fail<std::pair<TypeVariant, std::vector<std::string>>>("malformed enum flags");

        EnumKind kind;
        kind.members.reserve(n);
        int32_t remainingGroup = 0;
        for (uint32_t i = 0; i < n; ++i)
        {
            kind.members.push_back(readName().value_or(std::string()));
            if (remainingGroup > 0)
            {
                remainingGroup -= 1;
            }
            else if ((*bte & BTE_BITMASK) != 0)
            {
                auto group = readDt();
                if (!group)
                    return std::nullopt;
                remainingGroup = *group;
                if (remainingGroup <= 0)
                    return fail<std::pair<TypeVariant, std::vector<std::string>>>("invalid enum bitmask group");
                remainingGroup -= 1;
            }

            if (!readDe())
                return std::nullopt;
            if (enum64 && !readDe())
                return std::nullopt;
        }

        return std::make_pair(TypeVariant(std::move(kind)), collectEnumAttrTokens(*header));
    }

    Result<std::pair<TypeVariant, std::vector<std::string>>> parseBitfield(uint8_t flags)
    {
        auto dt = readDt();
        if (!dt)
            return std::nullopt;

        auto header = parseOptionalTah();
        if (!header)
            return std::nullopt;

        BitfieldKind kind;
        kind.width = static_cast<uint32_t>(*dt) >> 1;
        kind.isUnsigned = (static_cast<uint32_t>(*dt) & 1U) != 0;
        switch (flags)
        {
        case BTMT_BFLDI8: kind.base = "__int8"; break;
        case BTMT_BFLDI16: kind.base = "__int16"; break;
        case BTMT_BFLDI32: kind.base = "__int32"; break;
        case BTMT_BFLDI64: kind.base = "__int64"; break;
        default:
            return fail<std::pair<TypeVariant, std::vector<std::string>>>("invalid bitfield base");
        }

        return std::make_pair(TypeVariant(std::move(kind)), collectAttrTokens(*header, 0));
    }

    bool skipFuncAttrs()
    {
        while (peekByte() && ((*peekByte() & CM_CC_MASK) == CM_CC_SPOILED))
        {
            auto lead = readByte();
            if (!lead)
                return false;
            size_t spoilCount = *lead & 0x0F;
            if (spoilCount == BFA_FUNC_MARKER)
            {
                auto bfa = readByte();
                if (!bfa)
                {
                    fail<int>("truncated function attr marker");
                    return false;
                }
                if ((*bfa & BFA_FUNC_EXT_FORMAT) != 0)
                {
                    if (!readDe())
                        return false;
                    if ((*bfa & EXT_FUNC_HAS_SPOILED_REGS) != 0)
                    {
                        auto count = readDt();
                        if (!count)
                            return false;
                        spoilCount = static_cast<size_t>(*count);
                    }
                    else
                    {
                        spoilCount = 0;
                    }
                }
                else
                {
                    spoilCount = 0;
                }
            }
            for (size_t i = 0; i < spoilCount; ++i)
            {
                if (!skipSpoilInfo())
                    return false;
            }
        }
        return true;
    }

    bool skipSpoilInfo()
    {
        auto t = readByte();
        if (!t)
        {
            fail<int>("truncated spoil info");
            return false;
        }
        if ((*t & 0x80) == 0)
            return true;
        if (*t == 0xFF && !readDt())
            return false;
        if (!readByte())
        {
            fail<int>("truncated spoil size");
            return false;
        }
        return true;
    }

    Result<CallConv> readCallConv()
    {
        auto cm = readByte();
        if (!cm)
            return fail<CallConv>("truncated calling convention");
        uint32_t raw = 0;
        if ((*cm & CM_CC_MASK) == CM_CC_RESERVE3)
        {
            auto value = readDe();
            if (!value)
                return std::nullopt;
            raw = *value;
        }
        else
        {
            raw = static_cast<uint32_t>(*cm & CM_CC_MASK);
        }
        CallConv cc;
        cc.raw = raw;
        cc.keyword = callconvKeyword(raw);
        return cc;
    }

    Result<ParsedAttrHeader> parseOptionalTah()
    {
        if (peekByte() == TAH_BYTE)
            return parseAttrHeader(false);
        return ParsedAttrHeader{};
    }

    Result<ParsedAttrHeader> parseOptionalSdacl()
    {
        if (peekByte() && isSdaclByte(*peekByte()))
            return parseAttrHeader(true);
        return ParsedAttrHeader{};
    }

    Result<ParsedAttrHeader> parseAttrHeader(bool sdacl)
    {
        auto t = readByte();
        if (!t)
            return fail<ParsedAttrHeader>("truncated attr header");

        uint32_t tahBits = 0;
        if (!sdacl)
        {
            if (*t != TAH_BYTE)
                return fail<ParsedAttrHeader>("expected tah header");
            tahBits = 8;
        }
        else if (*t == TAH_BYTE)
        {
            tahBits = 8;
        }
        else
        {
            tahBits = (((static_cast<uint32_t>(*t & TYPE_FLAGS_MASK)) >> 3) | static_cast<uint32_t>(*t & 1U)) + 1;
        }

        if (tahBits == 8)
        {
            tahBits = 0;
            uint32_t shift = 0;
            for (;;)
            {
                auto byte = readByte();
                if (!byte)
                    return fail<ParsedAttrHeader>("truncated tah bits");
                if (*byte == 0)
                    return fail<ParsedAttrHeader>("malformed tah bits");
                tahBits |= static_cast<uint32_t>(*byte & 0x7F) << shift;
                if ((*byte & 0x80) == 0)
                    break;
                shift += 7;
                if (shift > 28)
                    return fail<ParsedAttrHeader>("tah bits too large");
            }
        }

        ParsedAttrHeader header;
        header.declAlign = static_cast<uint8_t>(tahBits & MAX_DECL_ALIGN);
        header.bits = tahBits & ~MAX_DECL_ALIGN;
        if ((header.bits & TAH_HASATTRS) != 0)
        {
            auto attrs = deserializeTypeAttrs();
            if (!attrs)
                return std::nullopt;
            header.attrs = std::move(*attrs);
        }
        return header;
    }

    Result<std::vector<TypeAttr>> deserializeTypeAttrs()
    {
        auto n = readDt();
        if (!n)
            return std::nullopt;
        if (*n <= 0)
            return fail<std::vector<TypeAttr>>("empty type attribute array");

        std::vector<TypeAttr> attrs;
        attrs.reserve(static_cast<size_t>(*n));
        std::optional<std::vector<uint8_t>> prevKey;
        for (int32_t i = 0; i < *n; ++i)
        {
            auto key = readLenPrefixedTypeBytes();
            if (!key)
                return std::nullopt;
            if (key->empty() || std::find(key->begin(), key->end(), 0) != key->end())
                return fail<std::vector<TypeAttr>>("invalid type attribute key");
            if (prevKey && *prevKey >= *key)
                return fail<std::vector<TypeAttr>>("type attribute keys are not sorted");
            auto value = deserializeAttrBytevec();
            if (!value)
                return std::nullopt;
            prevKey = *key;
            attrs.push_back(TypeAttr{std::move(*key), std::move(*value)});
        }
        return attrs;
    }

    Result<std::vector<uint8_t>> deserializeAttrBytevec()
    {
        auto n = readDt();
        if (!n)
            return std::nullopt;
        if (*n < 0)
            return fail<std::vector<uint8_t>>("invalid type attribute value length");

        std::vector<uint8_t> out;
        out.reserve(static_cast<size_t>(*n));
        for (int32_t i = 0; i < *n; ++i)
        {
            auto byte = readByte();
            if (!byte)
                return fail<std::vector<uint8_t>>("truncated type attribute value");
            if (*byte == 0)
                return fail<std::vector<uint8_t>>("invalid zero byte in type attribute value");
            uint8_t value = *byte;
            if (value == BV_MAGIC1)
            {
                value = 0;
            }
            else if (value == BV_MAGIC2)
            {
                auto escaped = readByte();
                if (!escaped)
                    return fail<std::vector<uint8_t>>("truncated escaped type attribute value");
                if (*escaped != BV_MAGIC1 && *escaped != BV_MAGIC2)
                    return fail<std::vector<uint8_t>>("invalid escaped type attribute value");
                value = *escaped;
            }
            out.push_back(value);
        }
        return out;
    }

    Result<std::vector<uint8_t>> readLenPrefixedTypeBytes()
    {
        auto len = readDt();
        if (!len)
            return std::nullopt;
        if (*len < 0 || m_type.size < static_cast<size_t>(*len))
            return fail<std::vector<uint8_t>>("truncated length-prefixed data");
        std::vector<uint8_t> out(m_type.begin(), m_type.begin() + *len);
        m_type = m_type.subspan(static_cast<size_t>(*len));
        return out;
    }

    Result<std::string> parseArgloc(bool forbidStackOff)
    {
        auto high = readByte();
        if (!high)
            return fail<std::string>("truncated argloc");

        if (*high == 0xFF)
        {
            auto n = readDt();
            if (!n)
                return std::nullopt;
            uint32_t value = static_cast<uint32_t>(*n);
            bool wideEa = false;
            if ((value & WIDE_EA_BIT) != 0)
            {
                value &= ~WIDE_EA_BIT;
                wideEa = true;
            }

            if (value == SERIALIZED_BADLOC)
                return std::string("BADLOC");

            uint32_t scatteredBit = 0;
            if ((value & OLDBIT) != 0 && value < (OLDBIT << 1))
                scatteredBit = OLDBIT;
            else if ((value & SCATTERED_BIT) != 0)
                scatteredBit = SCATTERED_BIT;

            if (scatteredBit != 0)
            {
                value &= ~scatteredBit;
                std::vector<std::string> parts;
                parts.reserve(value);
                for (uint32_t i = 0; i < value; ++i)
                {
                    auto partLoc = parseArgloc(false);
                    if (!partLoc)
                        return std::nullopt;
                    auto off = readDt();
                    if (!off)
                        return std::nullopt;
                    uint32_t partSize = 0;
                    if (scatteredBit == OLDBIT)
                    {
                        auto size = readDt();
                        if (!size)
                            return std::nullopt;
                        partSize = static_cast<uint32_t>(*size);
                    }
                    else
                    {
                        auto size = readDe();
                        if (!size)
                            return std::nullopt;
                        partSize = *size;
                    }
                    std::string part = std::to_string(*off) + ":" + *partLoc;
                    if (partSize > 0)
                        part += "." + std::to_string(partSize);
                    parts.push_back(std::move(part));
                }

                std::string joined;
                for (size_t i = 0; i < parts.size(); ++i)
                {
                    if (i != 0)
                        joined += ", ";
                    joined += parts[i];
                }
                return joined;
            }

            switch (value + 1)
            {
            case ALOC_STACK:
            {
                if (forbidStackOff)
                    return fail<std::string>("stack argloc forbidden");
                auto ea = readEa(wideEa);
                if (!ea)
                    return std::nullopt;
                return formatStackOffset(*ea);
            }
            case ALOC_DIST:
                return std::string("BADLOC");
            case ALOC_REG1:
            {
                auto reg = readDt();
                auto off = readDt();
                if (!reg || !off)
                    return std::nullopt;
                return formatReg1(*reg, *off);
            }
            case ALOC_REG2:
            {
                auto regLo = readDt();
                auto regHi = readDt();
                if (!regLo || !regHi)
                    return std::nullopt;
                return formatReg2(*regLo, *regHi);
            }
            case ALOC_RREL:
            {
                auto reg = readDt();
                auto off = readEa(wideEa);
                if (!reg || !off)
                    return std::nullopt;
                return formatRrel(*reg, *off);
            }
            case ALOC_STATIC:
            {
                auto ea = readEa(wideEa);
                if (!ea)
                    return std::nullopt;
                return formatEa(*ea);
            }
            default:
                return fail<std::string>("invalid argloc kind");
            }
        }

        const int32_t reg1 = static_cast<int32_t>(*high & 0x7F) - 1;
        if (*high > 0x80)
        {
            auto low = readByte();
            if (!low)
                return fail<std::string>("truncated old-style reg pair argloc");
            if (*low == 0)
                return fail<std::string>("invalid old-style reg pair argloc");
            return formatReg2(reg1, static_cast<int32_t>(*low) - 1);
        }
        if (reg1 == -1)
        {
            if (forbidStackOff)
                return fail<std::string>("stack argloc forbidden");
            return std::string("^0");
        }
        return formatReg1(reg1, 0);
    }

    Result<uint64_t> readEa(bool wideEa)
    {
        auto low = readDe();
        if (!low)
            return std::nullopt;
        uint64_t high = 0;
        if (wideEa)
        {
            auto hi = readDe();
            if (!hi)
                return std::nullopt;
            high = *hi;
        }
        return (high << 32) | *low;
    }

    Result<uint32_t> readComplexN()
    {
        auto n = readDt();
        if (!n)
            return std::nullopt;
        uint32_t value = static_cast<uint32_t>(*n);
        if (value == 0x7FFE)
        {
            auto ext = readDe();
            if (!ext)
                return std::nullopt;
            value = *ext;
        }
        return value;
    }

    Result<std::pair<uint32_t, uint32_t>> readDa()
    {
        uint32_t value = 0;
        for (size_t i = 0; i < 4; ++i)
        {
            auto byte = readByte();
            if (!byte)
                return fail<std::pair<uint32_t, uint32_t>>("truncated da");
            if (static_cast<int8_t>(*byte) >= 0)
                return fail<std::pair<uint32_t, uint32_t>>("invalid da encoding");
            value = (value << 7) | static_cast<uint32_t>(*byte & 0x7F);
        }

        auto tail = readByte();
        if (!tail)
            return fail<std::pair<uint32_t, uint32_t>>("truncated da tail");
        if (*tail == 0)
            return fail<std::pair<uint32_t, uint32_t>>("invalid da tail");

        value = (value << 4) | static_cast<uint32_t>(*tail & 0x0F);
        const uint32_t base = value;

        uint32_t num = static_cast<uint32_t>((*tail & 0x70) >> 4);
        for (size_t i = 0; i < 4; ++i)
        {
            auto byte = readByte();
            if (!byte)
                return fail<std::pair<uint32_t, uint32_t>>("truncated da count");
            if (static_cast<int8_t>(*byte) >= 0)
                return fail<std::pair<uint32_t, uint32_t>>("invalid da count encoding");
            num = (num << 7) | static_cast<uint32_t>(*byte & 0x7F);
        }
        return std::make_pair(num, base);
    }

    Result<uint64_t> readDq()
    {
        auto header = readDt();
        if (!header)
            return std::nullopt;
        const uint32_t hdr = static_cast<uint32_t>(*header);
        if (hdr == DQ_FF8)
            return std::numeric_limits<uint64_t>::max();
        if (hdr == DQ_FF4)
            return static_cast<uint64_t>(std::numeric_limits<uint32_t>::max());

        uint64_t value = 0;
        for (size_t i = 0; i < 8; ++i)
        {
            if ((hdr & (1U << i)) != 0)
            {
                auto byte = readByte();
                if (!byte)
                    return fail<uint64_t>("truncated dq");
                if (*byte == 0)
                    return fail<uint64_t>("invalid zero byte in dq");
                value |= static_cast<uint64_t>(*byte) << (i * 8);
            }
        }
        if ((hdr & DQ_BNOT) != 0)
            value = ~value;
        return value;
    }

    Result<int32_t> readDt()
    {
        auto byte = readByte();
        if (!byte)
            return fail<int32_t>("truncated dt");
        int32_t value = static_cast<int8_t>(*byte);
        if (value == 0)
            return fail<int32_t>("invalid zero dt byte");
        if (value < 0)
        {
            const uint8_t next = m_type.empty() ? 0 : m_type.front();
            if (next == 0)
                return fail<int32_t>("invalid dt extension");
            auto ext = readByte();
            if (!ext)
                return fail<int32_t>("truncated dt extension");
            value &= 0x7F;
            value |= static_cast<int32_t>(*ext) << 7;
        }
        return value - 1;
    }

    Result<uint32_t> readDe()
    {
        uint32_t value = 0;
        for (;;)
        {
            auto byte = readByte();
            if (!byte)
                return fail<uint32_t>("truncated de");
            if (*byte == 0)
                return fail<uint32_t>("invalid zero de byte");
            value <<= 6;
            if (static_cast<int8_t>(*byte) < 0)
            {
                value = (value << 1) | static_cast<uint32_t>(*byte & 0x7F);
            }
            else
            {
                value |= static_cast<uint32_t>(*byte & 0x3F);
                break;
            }
        }
        return value;
    }

    std::optional<std::string> readName()
    {
        if (m_fields.empty() || m_fields.front() == 0)
            return std::nullopt;
        auto len = readDtFromFields();
        if (!len || *len < 0 || m_fields.size < static_cast<size_t>(*len))
            return std::nullopt;
        std::string name(m_fields.begin(), m_fields.begin() + *len);
        m_fields = m_fields.subspan(static_cast<size_t>(*len));
        return name;
    }

    std::optional<std::string> readTypeName()
    {
        auto len = readDt();
        if (!len || *len < 0 || m_type.size < static_cast<size_t>(*len))
            return std::nullopt;
        std::string name(m_type.begin(), m_type.begin() + *len);
        m_type = m_type.subspan(static_cast<size_t>(*len));
        return name;
    }

    Result<int32_t> readDtFromFields()
    {
        auto byte = readFieldByte();
        if (!byte)
            return fail<int32_t>("truncated field dt");
        int32_t value = static_cast<int8_t>(*byte);
        if (value == 0)
            return fail<int32_t>("invalid zero field dt byte");
        if (value < 0)
        {
            const uint8_t next = m_fields.empty() ? 0 : m_fields.front();
            if (next == 0)
                return fail<int32_t>("invalid field dt extension");
            auto ext = readFieldByte();
            if (!ext)
                return fail<int32_t>("truncated field dt extension");
            value &= 0x7F;
            value |= static_cast<int32_t>(*ext) << 7;
        }
        return value - 1;
    }

    std::optional<uint8_t> readByte()
    {
        if (m_type.empty())
            return std::nullopt;
        const uint8_t byte = m_type.front();
        m_type = m_type.subspan(1);
        return byte;
    }

    std::optional<uint8_t> readFieldByte()
    {
        if (m_fields.empty())
            return std::nullopt;
        const uint8_t byte = m_fields.front();
        m_fields = m_fields.subspan(1);
        return byte;
    }

    std::optional<uint8_t> peekByte() const
    {
        if (m_type.empty())
            return std::nullopt;
        return m_type.front();
    }

    ByteView m_type;
    ByteView m_fields;
    std::string m_error;
};

bool TypeNode::isVoid() const
{
    if (const auto* primitive = std::get_if<PrimitiveKind>(&kind))
        return primitive->base == "void";
    return false;
}

std::string TypeNode::render(const std::optional<std::string>& name) const
{
    if (const auto* primitive = std::get_if<PrimitiveKind>(&kind))
    {
        std::string out;
        appendCvPrefix(out, isConst, isVolatile);
        out += primitive->base;
        if (name && !name->empty())
            out += " " + *name;
        appendRenderAttrs(out, attrs);
        return out;
    }
    if (const auto* typeref = std::get_if<TyperefKind>(&kind))
    {
        std::string out;
        appendCvPrefix(out, isConst, isVolatile);
        out += typeref->base;
        if (name && !name->empty())
            out += " " + *name;
        appendRenderAttrs(out, attrs);
        return out;
    }
    if (const auto* udt = std::get_if<StructKind>(&kind))
    {
        std::string out;
        appendCvPrefix(out, isConst, isVolatile);
        out += udt->isUnion ? "union" : "struct";
        if (udt->name && !udt->name->empty())
            out += " " + *udt->name;
        if (!udt->members.empty())
        {
            out += " {\n";
            for (const auto& member : udt->members)
                out += "    " + member.second->render(member.first) + ";\n";
            out += "}";
        }
        if (name && !name->empty())
            out += " " + *name;
        appendRenderAttrs(out, attrs);
        return out;
    }
    if (const auto* en = std::get_if<EnumKind>(&kind))
    {
        std::string out;
        appendCvPrefix(out, isConst, isVolatile);
        out += "enum";
        if (en->name && !en->name->empty())
            out += " " + *en->name;
        if (!en->members.empty())
        {
            out += " { ";
            for (size_t i = 0; i < en->members.size(); ++i)
            {
                if (i != 0)
                    out += ", ";
                out += en->members[i];
            }
            out += " }";
        }
        if (name && !name->empty())
            out += " " + *name;
        appendRenderAttrs(out, attrs);
        return out;
    }
    if (const auto* pointer = std::get_if<PointerKind>(&kind))
    {
        std::string declarator = (name && !name->empty()) ? "*" + *name : "*";
        if (!attrs.empty())
        {
            declarator.push_back(' ');
            for (size_t i = 0; i < attrs.size(); ++i)
            {
                if (i != 0)
                    declarator.push_back(' ');
                declarator += attrs[i];
            }
        }
        if (isConst)
            declarator += " const";
        if (isVolatile)
            declarator += " volatile";
        if (std::holds_alternative<FunctionKind>(pointer->inner->kind) || std::holds_alternative<ArrayKind>(pointer->inner->kind))
            declarator = "(" + declarator + ")";
        return pointer->inner->render(declarator);
    }
    if (const auto* array = std::get_if<ArrayKind>(&kind))
    {
        std::string suffix;
        if (array->count && array->base && *array->base != 0)
            suffix = "[base=" + std::to_string(*array->base) + ", count=" + std::to_string(*array->count) + "]";
        else if (array->count)
            suffix = "[" + std::to_string(*array->count) + "]";
        else if (array->base && *array->base != 0)
            suffix = "[base=" + std::to_string(*array->base) + "]";
        else
            suffix = "[]";

        std::string declarator = (name && !name->empty()) ? *name + suffix : suffix;
        if (!attrs.empty())
        {
            declarator.push_back(' ');
            for (size_t i = 0; i < attrs.size(); ++i)
            {
                if (i != 0)
                    declarator.push_back(' ');
                declarator += attrs[i];
            }
        }
        return array->element->render(declarator);
    }
    if (const auto* fn = std::get_if<FunctionKind>(&kind))
    {
        std::vector<std::string> parts;
        if (fn->unknownArgs)
        {
            parts.emplace_back("...");
        }
        else
        {
            for (const auto& arg : fn->args)
            {
                std::string rendered = arg.name.empty() ? arg.type->render(std::nullopt) : arg.type->render(arg.name);
                auto flags = formatArgFlags(arg.flags);
                if (!flags.empty())
                {
                    std::string prefix;
                    for (size_t i = 0; i < flags.size(); ++i)
                    {
                        if (i != 0)
                            prefix.push_back(' ');
                        prefix += flags[i];
                    }
                    rendered = prefix + " " + rendered;
                }
                if (arg.argloc)
                    rendered += " @<" + *arg.argloc + ">";
                parts.push_back(std::move(rendered));
            }
            if (fn->varargs)
                parts.emplace_back("...");
            if (parts.empty())
                parts.emplace_back("void");
        }

        std::string declarator = name.value_or(std::string());
        if (fn->cc)
            declarator = declarator.empty() ? *fn->cc : *fn->cc + " " + declarator;
        if (fn->retloc)
        {
            if (!declarator.empty())
                declarator.push_back(' ');
            declarator += "@<" + *fn->retloc + ">";
        }
        declarator.push_back('(');
        for (size_t i = 0; i < parts.size(); ++i)
        {
            if (i != 0)
                declarator += ", ";
            declarator += parts[i];
        }
        declarator.push_back(')');
        if (!attrs.empty())
        {
            declarator.push_back(' ');
            for (size_t i = 0; i < attrs.size(); ++i)
            {
                if (i != 0)
                    declarator.push_back(' ');
                declarator += attrs[i];
            }
        }
        return fn->ret->render(declarator);
    }
    const auto& bitfield = std::get<BitfieldKind>(kind);
    std::string out;
    appendCvPrefix(out, isConst, isVolatile);
    if (bitfield.isUnsigned)
        out += "unsigned ";
    out += bitfield.base;
    if (name && !name->empty())
        out += " " + *name;
    out += ":" + std::to_string(bitfield.width);
    appendRenderAttrs(out, attrs);
    return out;
}

}  // namespace

TypeDeclResult decodeTinfoDecl(const std::vector<uint8_t>& typeBytes, const std::vector<uint8_t>& fieldsBytes)
{
    TypeDeclResult result;
    if (typeBytes.empty())
    {
        result.error = "empty type string";
        return result;
    }

    Decoder decoder(typeBytes, fieldsBytes);
    auto type = decoder.parseType();
    if (!type)
    {
        result.error = decoder.error().value_or("type decode failed");
        return result;
    }

    result.declaration = type->render(std::nullopt);
    return result;
}

std::string escapeBytes(const std::vector<uint8_t>& bytes)
{
    return escapeBytesImpl(bytes);
}

}  // namespace lumina
