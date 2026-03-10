#include "lumina/settings.h"

#include "binaryninjaapi.h"

#include <cstdlib>

namespace lumina {

void registerSettings()
{
    auto settings = BinaryNinja::Settings::Instance();

    // Register the Lumina settings group
    settings->RegisterGroup(SETTINGS_GROUP, "Lumina");

    // Server host
    settings->RegisterSetting(SETTING_HOST,
        "{"
        "\"title\": \"Lumina Server Host\","
        "\"type\": \"string\","
        "\"default\": \"ida.int.mov\","
        "\"description\": \"Hostname or IP address of the Lumina server\""
        "}");

    // Server port
    settings->RegisterSetting(SETTING_PORT,
        "{"
        "\"title\": \"Lumina Server Port\","
        "\"type\": \"number\","
        "\"default\": 1234,"
        "\"minValue\": 1,"
        "\"maxValue\": 65535,"
        "\"description\": \"Port number of the Lumina server\""
        "}");

    // Use TLS
    settings->RegisterSetting(SETTING_USE_TLS,
        "{"
        "\"title\": \"Use TLS\","
        "\"type\": \"boolean\","
        "\"default\": true,"
        "\"description\": \"Enable TLS encryption for Lumina server connections\""
        "}");

    // Verify TLS certificate
    settings->RegisterSetting(SETTING_VERIFY_TLS,
        "{"
        "\"title\": \"Verify TLS Certificate\","
        "\"type\": \"boolean\","
        "\"default\": false,"
        "\"description\": \"Verify the server TLS certificate (disable for self-signed)\""
        "}");

    settings->RegisterSetting(SETTING_USERNAME,
        "{"
        "\"title\": \"Username\","
        "\"type\": \"string\","
        "\"default\": \"guest\","
        "\"description\": \"Lumina username. Overridden by BN_LUMINA_USERNAME. Defaults to guest when blank.\""
        "}");

    settings->RegisterSetting(SETTING_PASSWORD,
        "{"
        "\"title\": \"Password\","
        "\"type\": \"string\","
        "\"default\": \"\","
        "\"description\": \"Lumina password. Overridden by BN_LUMINA_PASSWORD. Stored as plain text in settings.\""
        "}");

    settings->RegisterSetting(SETTING_ALLOW_PLAINTEXT_FALLBACK,
        "{"
        "\"title\": \"Allow Plaintext Fallback\","
        "\"type\": \"boolean\","
        "\"default\": false,"
        "\"description\": \"If TLS initialization fails locally, retry the Lumina connection without TLS\""
        "}");

    // Auto-query after analysis
    settings->RegisterSetting(SETTING_AUTO_QUERY,
        "{"
        "\"title\": \"Auto-Query After Analysis\","
        "\"type\": \"boolean\","
        "\"default\": false,"
        "\"description\": \"Automatically query Lumina after initial analysis completes\""
        "}");

	// Connection timeout
	settings->RegisterSetting(SETTING_TIMEOUT,
        "{"
        "\"title\": \"Connection Timeout (ms)\","
        "\"type\": \"number\","
        "\"default\": 10000,"
        "\"minValue\": 1000,"
        "\"maxValue\": 300000,"
        "\"description\": \"Timeout in milliseconds for Lumina server connections\""
        "}");

    settings->RegisterSetting(SETTING_QT_PLUGIN_PATH,
        "{"
        "\"title\": \"Qt TLS Plugin Path\","
        "\"type\": \"string\","
        "\"default\": \"\","
        "\"description\": \"Optional extra Qt plugin directory to search for TLS backends\""
        "}");

    BinaryNinja::LogInfo("[Lumina] Settings registered");
}

std::string getHost()
{
    return BinaryNinja::Settings::Instance()->Get<std::string>(SETTING_HOST);
}

uint16_t getPort()
{
    return static_cast<uint16_t>(BinaryNinja::Settings::Instance()->Get<int64_t>(SETTING_PORT));
}

bool useTls()
{
    return BinaryNinja::Settings::Instance()->Get<bool>(SETTING_USE_TLS);
}

bool verifyTls()
{
    return BinaryNinja::Settings::Instance()->Get<bool>(SETTING_VERIFY_TLS);
}

std::string getUsername()
{
    if (const char* envUsername = std::getenv("BN_LUMINA_USERNAME"))
        return *envUsername != '\0' ? std::string(envUsername) : std::string("guest");

    const std::string username = BinaryNinja::Settings::Instance()->Get<std::string>(SETTING_USERNAME);
    return username.empty() ? std::string("guest") : username;
}

std::string getPassword()
{
    if (const char* envPassword = std::getenv("BN_LUMINA_PASSWORD"))
        return std::string(envPassword);

    return BinaryNinja::Settings::Instance()->Get<std::string>(SETTING_PASSWORD);
}

bool allowPlaintextFallback()
{
    return BinaryNinja::Settings::Instance()->Get<bool>(SETTING_ALLOW_PLAINTEXT_FALLBACK);
}

bool autoQueryOnAnalysis()
{
	return BinaryNinja::Settings::Instance()->Get<bool>(SETTING_AUTO_QUERY);
}

int getTimeoutMs()
{
    return static_cast<int>(BinaryNinja::Settings::Instance()->Get<int64_t>(SETTING_TIMEOUT));
}

std::string getQtPluginPath()
{
    return BinaryNinja::Settings::Instance()->Get<std::string>(SETTING_QT_PLUGIN_PATH);
}

} // namespace lumina
