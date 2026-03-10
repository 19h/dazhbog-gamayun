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
constexpr const char* SETTING_USERNAME = "lumina.server.username";
constexpr const char* SETTING_PASSWORD = "lumina.server.password";
constexpr const char* SETTING_ALLOW_PLAINTEXT_FALLBACK = "lumina.server.allowPlaintextFallback";
constexpr const char* SETTING_AUTO_QUERY = "lumina.autoQueryOnAnalysis";
constexpr const char* SETTING_TIMEOUT = "lumina.timeout";
constexpr const char* SETTING_QT_PLUGIN_PATH = "lumina.qt.pluginPath";

// Register all Lumina settings with Binary Ninja
void registerSettings();

// Get settings values
std::string getHost();
uint16_t getPort();
bool useTls();
bool verifyTls();
std::string getUsername();
std::string getPassword();
bool allowPlaintextFallback();
bool autoQueryOnAnalysis();
int getTimeoutMs();
std::string getQtPluginPath();

} // namespace lumina
