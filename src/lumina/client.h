#pragma once

#include "lumina/protocol.h"

#include <QtCore/QObject>
#include <QtNetwork/QTcpSocket>

#include <memory>
#include <string>
#include <vector>

#ifndef QT_NO_SSL
#include <QtNetwork/QSslConfiguration>
#include <QtNetwork/QSslSocket>
#define LUMINA_HAS_SSL 1
#else
#define LUMINA_HAS_SSL 0
#endif

namespace lumina {

struct PulledFunction {
    uint32_t popularity = 0;
    uint32_t len = 0;
    std::string name;
    std::vector<uint8_t> data;
};

class Client : public QObject {
    Q_OBJECT

public:
    explicit Client(
        const QString& host,
        quint16 port,
        QObject* parent = nullptr,
        bool useTls = false,
        bool verifyTls = true,
        bool allowPlaintextFallback = false)
        : QObject(parent),
          m_host(host),
          m_port(port),
          m_useTls(useTls),
          m_verifyTls(verifyTls),
          m_allowPlaintextFallback(allowPlaintextFallback)
    {
    }

    static Client* fromSettings(QObject* parent = nullptr);

    bool helloAndPull(
        const HelloRequest& helloRequest,
        const PullMetadataRequest& pullRequest,
        QString* err,
        std::vector<OperationResult>* outStatuses,
        std::vector<PulledFunction>* outFunctions,
        int timeoutMs = 5000);

private:
    QString m_host;
    quint16 m_port;
    bool m_useTls;
    bool m_verifyTls;
    bool m_allowPlaintextFallback;

    std::unique_ptr<QTcpSocket> createPlainSocket(QString* err, int timeoutMs);
    std::unique_ptr<QTcpSocket> createSocket(QString* err, int timeoutMs);
    bool performHello(QTcpSocket& socket, const HelloRequest& helloRequest, QString* err, int timeoutMs);

    static QByteArray makePacket(PacketType type, const std::vector<uint8_t>& payload);
    static bool writePacket(
        QTcpSocket& socket,
        PacketType type,
        const std::vector<uint8_t>& payload,
        QString* err,
        int timeoutMs);
    static bool readPacket(
        QTcpSocket& socket,
        PacketType* outType,
        std::vector<uint8_t>* outPayload,
        QString* err,
        int timeoutMs);
    static bool decodeRpcFail(const std::vector<uint8_t>& payload, QString* err);
};

}  // namespace lumina
