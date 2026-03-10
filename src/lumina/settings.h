#pragma once

#include <cstdint>
#include <string>

namespace lumina {

// Settings keys
constexpr const char* SETTINGS_GROUP = "lumina";
constexpr const char* SETTING_HOST = "lumina.server.host";
constexpr const char* SETTING_PORT = "lumina.server.port";
constexpr const char* SETTING_USE_TLS = "lumina.server.useTls";
constexpr const char* SETTING_VERIFY_TLS = "lumina.server.verifyTls";
constexpr const char* SETTING_AUTO_QUERY = "lumina.autoQueryOnAnalysis";
constexpr const char* SETTING_TIMEOUT = "lumina.timeout";

// Register all Lumina settings with Binary Ninja
void registerSettings();

// Get settings values
std::string getHost();
uint16_t getPort();
bool useTls();
bool verifyTls();
bool autoQueryOnAnalysis();
int getTimeoutMs();

} // namespace lumina
