#pragma once
/**
 * debug_dump.h - Comprehensive debug logging for Lumina CalcRel hash computation
 *
 * Dumps every step to disk for comparison with IDA's implementation.
 */

#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <filesystem>
#include "binaryninjaapi.h"

namespace lumina {
namespace debug {

// Get the debug output directory
inline std::string getDebugDir() {
    const char* env = std::getenv("LUMINA_DEBUG_DIR");
    if (env && *env) return env;
    return "/tmp/lumina_debug";
}

// Ensure debug directory exists
inline void ensureDebugDir() {
    std::filesystem::create_directories(getDebugDir());
}

// Format bytes as hex string
inline std::string hexBytes(const uint8_t* data, size_t len) {
    std::ostringstream ss;
    for (size_t i = 0; i < len; i++) {
        if (i > 0) ss << " ";
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    }
    return ss.str();
}

inline std::string hexBytes(const std::vector<uint8_t>& data) {
    return hexBytes(data.data(), data.size());
}

// Format address
inline std::string hexAddr(uint64_t addr) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::setfill('0') << std::setw(16) << addr;
    return ss.str();
}

/**
 * Debug dump context for a single function
 */
class FunctionDump {
public:
    FunctionDump(const std::string& funcName, uint64_t funcAddr)
        : m_funcName(funcName), m_funcAddr(funcAddr)
    {
        ensureDebugDir();

        // Create filename with address
        std::ostringstream fname;
        fname << getDebugDir() << "/func_" << std::hex << funcAddr << "_"
              << sanitizeName(funcName) << ".txt";
        m_filename = fname.str();

        m_ss << "================================================================================\n";
        m_ss << "LUMINA DEBUG DUMP\n";
        m_ss << "================================================================================\n";
        m_ss << "Function: " << funcName << "\n";
        m_ss << "Address:  " << hexAddr(funcAddr) << "\n";
        m_ss << "Time:     " << currentTime() << "\n";
        m_ss << "================================================================================\n\n";
    }

    ~FunctionDump() {
        // Write to file on destruction
        std::ofstream f(m_filename);
        if (f.is_open()) {
            f << m_ss.str();
            f.close();
        }
    }

    void section(const std::string& name) {
        m_ss << "\n--- " << name << " ---\n";
    }

    void log(const std::string& msg) {
        m_ss << msg << "\n";
    }

    void logKeyValue(const std::string& key, const std::string& value) {
        m_ss << std::setw(20) << std::left << key << ": " << value << std::right << "\n";
    }

    void logKeyValue(const std::string& key, uint64_t value) {
        std::ostringstream ss;
        ss << value << " (0x" << std::hex << value << ")";
        logKeyValue(key, ss.str());
    }

    void logBasicBlocks(const std::vector<std::pair<uint64_t, uint64_t>>& blocks) {
        section("BASIC BLOCKS");
        m_ss << "Count: " << blocks.size() << "\n";
        for (size_t i = 0; i < blocks.size(); i++) {
            m_ss << "  [" << i << "] " << hexAddr(blocks[i].first)
                 << " - " << hexAddr(blocks[i].second)
                 << " (size: " << std::dec << (blocks[i].second - blocks[i].first) << " bytes)\n";
        }
    }

    void logInstruction(
        uint64_t addr,
        const std::vector<uint8_t>& rawBytes,
        const std::vector<uint8_t>& mask,
        const std::vector<uint8_t>& normalized,
        const std::string& disasm = "")
    {
        m_ss << hexAddr(addr) << ":\n";
        m_ss << "  Raw:        " << hexBytes(rawBytes) << "\n";
        m_ss << "  Mask:       " << hexBytes(mask) << "\n";
        m_ss << "  Normalized: " << hexBytes(normalized) << "\n";
        if (!disasm.empty()) {
            m_ss << "  Disasm:     " << disasm << "\n";
        }
        m_ss << "\n";
    }

    void logFinalNormalized(const std::vector<uint8_t>& data) {
        section("FINAL NORMALIZED BYTES");
        m_ss << "Total bytes: " << data.size() << "\n\n";

        // Reset stream flags to ensure proper formatting
        m_ss << std::right;

        // Hexdump format
        for (size_t i = 0; i < data.size(); i += 16) {
            m_ss << "  " << std::hex << std::setfill('0') << std::setw(8) << i << ":  ";

            // Hex bytes
            for (size_t j = i; j < i + 16 && j < data.size(); j++) {
                m_ss << std::hex << std::setfill('0') << std::setw(2) << (int)data[j] << " ";
                if (j == i + 7) m_ss << " ";
            }

            // Padding
            for (size_t j = data.size(); j < i + 16; j++) {
                m_ss << "   ";
                if (j == i + 7) m_ss << " ";
            }

            // ASCII
            m_ss << " |";
            for (size_t j = i; j < i + 16 && j < data.size(); j++) {
                char c = data[j];
                m_ss << (c >= 32 && c < 127 ? c : '.');
            }
            m_ss << "|\n";
        }
    }

    void logHash(const std::array<uint8_t, 16>& hash) {
        section("FINAL HASH (MD5)");
        m_ss << std::right;  // Ensure proper formatting
        m_ss << "Hash: ";
        for (int i = 0; i < 16; i++) {
            m_ss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
        }
        m_ss << "\n";

        // Also show as raw bytes array
        m_ss << "Raw:  [";
        for (int i = 0; i < 16; i++) {
            if (i > 0) m_ss << ", ";
            m_ss << std::dec << (int)hash[i];
        }
        m_ss << "]\n";
    }

    std::string getFilename() const { return m_filename; }

private:
    std::string m_funcName;
    uint64_t m_funcAddr;
    std::string m_filename;
    std::ostringstream m_ss;

    static std::string sanitizeName(const std::string& name) {
        std::string result;
        for (char c : name) {
            if (std::isalnum(c) || c == '_') {
                result += c;
            } else {
                result += '_';
            }
        }
        if (result.size() > 50) result = result.substr(0, 50);
        return result;
    }

    static std::string currentTime() {
        time_t now = time(nullptr);
        char buf[64];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
        return buf;
    }
};

/**
 * Dump the full pull request for comparison
 */
inline void dumpPullRequest(
    const std::string& filename,
    const std::vector<std::array<uint8_t, 16>>& hashes,
    const std::vector<uint64_t>& addrs,
    const std::vector<std::string>& names)
{
    ensureDebugDir();
    std::string path = getDebugDir() + "/" + filename;

    std::ofstream f(path);
    if (!f.is_open()) return;

    f << "=== BINJA PULL REQUEST DUMP ===\n";
    f << "Function count: " << hashes.size() << "\n\n";

    for (size_t i = 0; i < hashes.size(); i++) {
        f << "--- Function[" << i << "] ---\n";
        f << "Address: " << hexAddr(addrs.size() > i ? addrs[i] : 0) << "\n";
        f << "Name: " << (names.size() > i ? names[i] : "?") << "\n";
        f << "Hash: ";
        for (int j = 0; j < 16; j++) {
            f << std::hex << std::setfill('0') << std::setw(2) << (int)hashes[i][j];
        }
        f << "\n";
        f << "Hash (raw bytes): [";
        for (int j = 0; j < 16; j++) {
            if (j > 0) f << ", ";
            f << std::dec << (int)hashes[i][j];
        }
        f << "]\n\n";
    }

    f.close();
}

/**
 * Write raw binary data
 */
inline void dumpBinary(const std::string& filename, const std::vector<uint8_t>& data) {
    ensureDebugDir();
    std::string path = getDebugDir() + "/" + filename;

    std::ofstream f(path, std::ios::binary);
    if (f.is_open()) {
        f.write(reinterpret_cast<const char*>(data.data()), data.size());
        f.close();
    }
}

} // namespace debug
} // namespace lumina
