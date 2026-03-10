#include "lumina/session.h"

#include "lumina/settings.h"

#include <QProcessEnvironment>

std::unique_ptr<lumina::Client> lumina::createConfiguredClient(QObject* parent)
{
	QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
	QString host = QString::fromStdString(lumina::getHost());
	if (env.contains("BN_LUMINA_HOST"))
		host = env.value("BN_LUMINA_HOST");

	quint16 port = lumina::getPort();
	if (env.contains("BN_LUMINA_PORT"))
	{
		bool ok = false;
		const quint16 envPort = env.value("BN_LUMINA_PORT").toUShort(&ok);
		if (ok)
			port = envPort;
	}

	return std::make_unique<lumina::Client>(
		host,
		port,
		parent,
		lumina::useTls(),
		lumina::verifyTls(),
		lumina::allowPlaintextFallback());
}
