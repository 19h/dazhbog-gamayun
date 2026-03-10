#pragma once

#include "lumina/client.h"

#include <memory>

namespace lumina {

std::unique_ptr<Client> createConfiguredClient(QObject* parent);

}  // namespace lumina
