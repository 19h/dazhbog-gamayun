#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lumina {

struct TypeDeclResult {
    std::string declaration;
    std::string error;

    bool ok() const { return error.empty(); }
};

TypeDeclResult decodeTinfoDecl(const std::vector<uint8_t>& typeBytes, const std::vector<uint8_t>& fieldsBytes);
std::string escapeBytes(const std::vector<uint8_t>& bytes);

}  // namespace lumina
