#include "lumina/settings.h"

#include "binaryninjaapi.h"

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

bool autoQueryOnAnalysis()
{
	return BinaryNinja::Settings::Instance()->Get<bool>(SETTING_AUTO_QUERY);
}

int getTimeoutMs()
{
    return static_cast<int>(BinaryNinja::Settings::Instance()->Get<int64_t>(SETTING_TIMEOUT));
}

} // namespace lumina
