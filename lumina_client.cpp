#include "lumina_client.h"

#include "lumina_settings.h"

#include <QtCore/QDeadlineTimer>

#include <array>
#include <utility>

namespace lumina {

namespace {

QString packetTypeString(PacketType type)
{
    return QStringLiteral("0x%1")
        .arg(static_cast<unsigned int>(static_cast<uint8_t>(type)), 2, 16, QLatin1Char('0'));
}

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
        verifyTls());
}

std::unique_ptr<QTcpSocket> Client::createSocket(QString* err, int timeoutMs)
{
#if LUMINA_HAS_SSL
    if (m_useTls)
    {
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
            if (err != nullptr)
            {
                QString message = socket->errorString();
                const auto sslErrors = socket->sslHandshakeErrors();
                if (!sslErrors.isEmpty())
                {
                    message += QStringLiteral(" (SSL: ");
                    for (const auto& sslError : sslErrors)
                        message += sslError.errorString() + QStringLiteral("; ");
                    message += QLatin1Char(')');
                }
                *err = QStringLiteral("TLS connection failed: %1").arg(message);
            }
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
