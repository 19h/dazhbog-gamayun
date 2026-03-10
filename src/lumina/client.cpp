#include "lumina/client.h"

#include "binaryninjaapi.h"
#include "lumina/settings.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QDeadlineTimer>
#include <QtCore/QDir>

#include <array>
#include <utility>

namespace lumina {

namespace {

QString packetTypeString(PacketType type)
{
    return QStringLiteral("0x%1")
        .arg(static_cast<unsigned int>(static_cast<uint8_t>(type)), 2, 16, QLatin1Char('0'));
}

QString yesNo(bool value)
{
    return value ? QStringLiteral("yes") : QStringLiteral("no");
}

QString runtimeQtVersion()
{
    return QString::fromLatin1(qVersion());
}

QString buildQtVersion()
{
#ifdef GAMAYUN_BUILD_QT_VERSION
    return QStringLiteral(GAMAYUN_BUILD_QT_VERSION);
#else
    return QStringLiteral("unknown");
#endif
}

QString buildQtPluginPath()
{
#ifdef GAMAYUN_BUILD_QT_PLUGIN_PATH
    return QStringLiteral(GAMAYUN_BUILD_QT_PLUGIN_PATH);
#else
    return QString();
#endif
}

QString joinStrings(const QStringList& values)
{
    return values.isEmpty() ? QStringLiteral("<none>") : values.join(QStringLiteral(", "));
}

QStringList currentLibraryPaths()
{
    if (QCoreApplication::instance() == nullptr)
        return {};
    return QCoreApplication::libraryPaths();
}

void addLibraryPathIfPresent(const QString& path, QStringList* addedPaths)
{
    if ((QCoreApplication::instance() == nullptr) || path.isEmpty())
        return;

    QDir dir(path);
    if (!dir.exists())
        return;

    const QString cleanPath = QDir::cleanPath(dir.absolutePath());
    const QStringList libraryPaths = QCoreApplication::libraryPaths();
    if (libraryPaths.contains(cleanPath))
        return;

    QCoreApplication::addLibraryPath(cleanPath);
    if (addedPaths != nullptr)
        addedPaths->push_back(cleanPath);
}

QStringList configureQtPluginPaths()
{
    QStringList addedPaths;
    if (QCoreApplication::instance() == nullptr)
        return addedPaths;

    const QString appDir = QCoreApplication::applicationDirPath();
    addLibraryPathIfPresent(QDir(appDir).absoluteFilePath(QStringLiteral("qt")), &addedPaths);
    addLibraryPathIfPresent(QDir(appDir).absoluteFilePath(QStringLiteral("../PlugIns")), &addedPaths);
    addLibraryPathIfPresent(QDir(appDir).absoluteFilePath(QStringLiteral("../Plugins")), &addedPaths);
    addLibraryPathIfPresent(QString::fromStdString(lumina::getQtPluginPath()), &addedPaths);
    addLibraryPathIfPresent(qEnvironmentVariable("BN_LUMINA_QT_PLUGIN_PATH"), &addedPaths);
    addLibraryPathIfPresent(buildQtPluginPath(), &addedPaths);
    return addedPaths;
}

#if LUMINA_HAS_SSL
QString tlsEnvironmentSummary()
{
    return QStringLiteral("Qt build=%1, Qt runtime=%2, supportsSsl=%3, activeBackend=%4, availableBackends=[%5], libraryPaths=[%6]")
        .arg(buildQtVersion())
        .arg(runtimeQtVersion())
        .arg(yesNo(QSslSocket::supportsSsl()))
        .arg(QSslSocket::activeBackend().isEmpty() ? QStringLiteral("<none>") : QSslSocket::activeBackend())
        .arg(joinStrings(QSslSocket::availableBackends()))
        .arg(joinStrings(currentLibraryPaths()));
}

QString tlsUnavailableMessage()
{
    return QStringLiteral(
        "TLS connection failed: no functional Qt TLS backend was found. %1. "
        "Set `lumina.qt.pluginPath` or `BN_LUMINA_QT_PLUGIN_PATH` to a Qt plugin directory containing TLS backends.")
        .arg(tlsEnvironmentSummary());
}

QString tlsFailureDetails(const QSslSocket& socket)
{
    QString message = socket.errorString();
    const auto sslErrors = socket.sslHandshakeErrors();
    if (!sslErrors.isEmpty())
    {
        message += QStringLiteral(" (SSL: ");
        for (const auto& sslError : sslErrors)
            message += sslError.errorString() + QStringLiteral("; ");
        message += QLatin1Char(')');
    }

    return QStringLiteral("TLS connection failed: %1. %2").arg(message, tlsEnvironmentSummary());
}

bool shouldFallbackToPlaintext(const QString& message)
{
    return message.contains(QStringLiteral("TLS initialization failed"), Qt::CaseInsensitive)
        || message.contains(QStringLiteral("No functional TLS backend"), Qt::CaseInsensitive)
        || message.contains(QStringLiteral("The remote host closed the connection"), Qt::CaseInsensitive)
        || message.contains(QStringLiteral("unexpected eof"), Qt::CaseInsensitive)
        || message.contains(QStringLiteral("decode_error"), Qt::CaseInsensitive);
}

void logTlsEnvironmentOnce()
{
    static bool logged = false;
    if (logged)
        return;

    logged = true;
    const QStringList addedPaths = configureQtPluginPaths();
    if (!addedPaths.isEmpty())
    {
        BinaryNinja::LogInfo(
            "[Lumina] Added Qt plugin search path(s) for TLS: %s",
            joinStrings(addedPaths).toStdString().c_str());
    }

    BinaryNinja::LogInfo("[Lumina] %s", tlsEnvironmentSummary().toStdString().c_str());
}
#endif

bool readExact(QTcpSocket& socket, char* buffer, qint64 size, QString* err, QDeadlineTimer& deadline)
{
    qint64 offset = 0;
    while (offset < size)
    {
        if (socket.bytesAvailable() == 0)
        {
            const int remaining = deadline.remainingTime();
            if (remaining <= 0 || !socket.waitForReadyRead(remaining))
            {
                if (err != nullptr)
                    *err = QStringLiteral("Timed out while reading from server: %1").arg(socket.errorString());
                return false;
            }
        }

        const qint64 chunk = socket.read(buffer + offset, size - offset);
        if (chunk <= 0)
        {
            if (err != nullptr)
                *err = QStringLiteral("Read failed: %1").arg(socket.errorString());
            return false;
        }

        offset += chunk;
    }

    return true;
}

}  // namespace

Client* Client::fromSettings(QObject* parent)
{
    return new Client(
        QString::fromStdString(getHost()),
        getPort(),
        parent,
        useTls(),
        verifyTls(),
        allowPlaintextFallback());
}

std::unique_ptr<QTcpSocket> Client::createPlainSocket(QString* err, int timeoutMs)
{
    auto socket = std::make_unique<QTcpSocket>();
    socket->connectToHost(m_host, m_port);
    if (!socket->waitForConnected(timeoutMs))
    {
        if (err != nullptr)
            *err = QStringLiteral("Connect failed: %1").arg(socket->errorString());
        return nullptr;
    }

    return socket;
}

std::unique_ptr<QTcpSocket> Client::createSocket(QString* err, int timeoutMs)
{
#if LUMINA_HAS_SSL
    if (m_useTls)
    {
        logTlsEnvironmentOnce();

        if (!QSslSocket::supportsSsl() || QSslSocket::availableBackends().isEmpty())
        {
            const QString message = tlsUnavailableMessage();
            if (m_allowPlaintextFallback)
            {
                BinaryNinja::LogWarn(
                    "[Lumina] %s Falling back to plaintext because `lumina.server.allowPlaintextFallback` is enabled.",
                    message.toStdString().c_str());
                return createPlainSocket(err, timeoutMs);
            }

            if (err != nullptr)
                *err = message;
            return nullptr;
        }

        auto socket = std::make_unique<QSslSocket>();

        if (!m_verifyTls)
        {
            socket->setPeerVerifyMode(QSslSocket::VerifyNone);
            auto configuration = socket->sslConfiguration();
            configuration.setPeerVerifyMode(QSslSocket::VerifyNone);
            socket->setSslConfiguration(configuration);
        }

        socket->connectToHostEncrypted(m_host, m_port);
        if (!socket->waitForEncrypted(timeoutMs))
        {
            const QString message = tlsFailureDetails(*socket);
            if (m_allowPlaintextFallback && shouldFallbackToPlaintext(message))
            {
                BinaryNinja::LogWarn(
                    "[Lumina] %s Falling back to plaintext because `lumina.server.allowPlaintextFallback` is enabled.",
                    message.toStdString().c_str());
                return createPlainSocket(err, timeoutMs);
            }

            if (err != nullptr)
                *err = message;
            return nullptr;
        }

        return std::unique_ptr<QTcpSocket>(socket.release());
    }
#else
    if (m_useTls)
    {
        if (err != nullptr)
            *err = QStringLiteral("TLS support not available (Qt built without SSL)");
        return nullptr;
    }
#endif

    return createPlainSocket(err, timeoutMs);
}

bool Client::performHello(QTcpSocket& socket, const HelloRequest& helloRequest, QString* err, int timeoutMs)
{
    if (!writePacket(socket, PacketType::Hello, serialize_payload(helloRequest), err, timeoutMs))
        return false;

    PacketType responseType = PacketType::RpcFail;
    std::vector<uint8_t> payload;
    do
    {
        if (!readPacket(socket, &responseType, &payload, err, timeoutMs))
            return false;
    } while (responseType == PacketType::RpcNotify);

    if (responseType == PacketType::RpcFail)
    {
        decodeRpcFail(payload, err);
        return false;
    }

    if (responseType == PacketType::RpcOk)
        return true;

    if (responseType != PacketType::HelloResult)
    {
        if (err != nullptr)
            *err = QStringLiteral("Unexpected hello response type %1").arg(packetTypeString(responseType));
        return false;
    }

    HelloResult result;
    if (!deserialize_payload(payload, &result))
    {
        if (err != nullptr)
            *err = QStringLiteral("Malformed hello response");
        return false;
    }

    return true;
}

QByteArray Client::makePacket(PacketType type, const std::vector<uint8_t>& payload)
{
    QByteArray out;
    out.resize(5 + static_cast<int>(payload.size()));

    const uint32_t length = static_cast<uint32_t>(payload.size());
    out[0] = static_cast<char>((length >> 24) & 0xFF);
    out[1] = static_cast<char>((length >> 16) & 0xFF);
    out[2] = static_cast<char>((length >> 8) & 0xFF);
    out[3] = static_cast<char>(length & 0xFF);
    out[4] = static_cast<char>(type);

    if (!payload.empty())
        std::copy(payload.begin(), payload.end(), reinterpret_cast<uint8_t*>(out.data() + 5));

    return out;
}

bool Client::writePacket(
    QTcpSocket& socket,
    PacketType type,
    const std::vector<uint8_t>& payload,
    QString* err,
    int timeoutMs)
{
    const QByteArray frame = makePacket(type, payload);
    QDeadlineTimer deadline(timeoutMs);

    qint64 written = 0;
    while (written < frame.size())
    {
        const qint64 chunk = socket.write(frame.constData() + written, frame.size() - written);
        if (chunk < 0)
        {
            if (err != nullptr)
                *err = QStringLiteral("Write failed: %1").arg(socket.errorString());
            return false;
        }

        written += chunk;
        const int remaining = deadline.remainingTime();
        if (written < frame.size() && (remaining <= 0 || !socket.waitForBytesWritten(remaining)))
        {
            if (err != nullptr)
                *err = QStringLiteral("Timed out while writing to server: %1").arg(socket.errorString());
            return false;
        }
    }

    if (socket.bytesToWrite() > 0)
    {
        const int remaining = deadline.remainingTime();
        if (remaining <= 0 || !socket.waitForBytesWritten(remaining))
        {
            if (err != nullptr)
                *err = QStringLiteral("Timed out while flushing request: %1").arg(socket.errorString());
            return false;
        }
    }

    return true;
}

bool Client::readPacket(
    QTcpSocket& socket,
    PacketType* outType,
    std::vector<uint8_t>* outPayload,
    QString* err,
    int timeoutMs)
{
    if (outType == nullptr || outPayload == nullptr)
    {
        if (err != nullptr)
            *err = QStringLiteral("Internal error: null packet output");
        return false;
    }

    QDeadlineTimer deadline(timeoutMs);
    std::array<char, 5> header{};
    if (!readExact(socket, header.data(), static_cast<qint64>(header.size()), err, deadline))
        return false;

    const auto* bytes = reinterpret_cast<const uint8_t*>(header.data());
    const uint32_t payloadSize = (static_cast<uint32_t>(bytes[0]) << 24)
        | (static_cast<uint32_t>(bytes[1]) << 16)
        | (static_cast<uint32_t>(bytes[2]) << 8)
        | static_cast<uint32_t>(bytes[3]);

    if (payloadSize > kMaxPacketPayloadSize)
    {
        if (err != nullptr)
            *err = QStringLiteral("Remote packet too large: %1 bytes").arg(payloadSize);
        return false;
    }

    *outType = static_cast<PacketType>(bytes[4]);
    outPayload->assign(payloadSize, 0);
    if (payloadSize == 0)
        return true;

    return readExact(
        socket,
        reinterpret_cast<char*>(outPayload->data()),
        static_cast<qint64>(payloadSize),
        err,
        deadline);
}

bool Client::decodeRpcFail(const std::vector<uint8_t>& payload, QString* err)
{
    RpcFail fail;
    if (!deserialize_payload(payload, &fail))
    {
        if (err != nullptr)
            *err = QStringLiteral("Malformed server failure response");
        return false;
    }

    if (err != nullptr)
        *err = QStringLiteral("Server rejected request (%1): %2")
            .arg(fail.result)
            .arg(QString::fromStdString(fail.error));
    return true;
}

bool Client::helloAndPull(
    const HelloRequest& helloRequest,
    const PullMetadataRequest& pullRequest,
    QString* err,
    std::vector<OperationResult>* outStatuses,
    std::vector<PulledFunction>* outFunctions,
    int timeoutMs)
{
    auto socket = createSocket(err, timeoutMs);
    if (!socket)
        return false;

    if (!performHello(*socket, helloRequest, err, timeoutMs))
        return false;

    if (!writePacket(*socket, PacketType::PullMetadata, serialize_payload(pullRequest), err, timeoutMs))
        return false;

    PacketType responseType = PacketType::RpcFail;
    std::vector<uint8_t> payload;
    do
    {
        if (!readPacket(*socket, &responseType, &payload, err, timeoutMs))
            return false;
    } while (responseType == PacketType::RpcNotify);

    if (responseType == PacketType::RpcFail)
    {
        decodeRpcFail(payload, err);
        return false;
    }

    if (responseType != PacketType::PullMetadataResult)
    {
        if (err != nullptr)
            *err = QStringLiteral("Unexpected pull response type %1").arg(packetTypeString(responseType));
        return false;
    }

    PullMetadataResult result;
    if (!deserialize_payload(payload, &result))
    {
        if (err != nullptr)
            *err = QStringLiteral("Malformed pull response");
        return false;
    }

    if (outStatuses != nullptr)
        *outStatuses = result.codes;

    if (outFunctions != nullptr)
    {
        outFunctions->clear();
        outFunctions->reserve(result.results.size());
        for (const auto& entry : result.results)
        {
            PulledFunction function;
            function.popularity = entry.frequency;
            function.len = entry.info.size;
            function.name = entry.info.name;
            function.data = entry.info.metadata;
            outFunctions->push_back(std::move(function));
        }
    }

    return true;
}

}  // namespace lumina
