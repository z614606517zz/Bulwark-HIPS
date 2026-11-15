#pragma once
#include "ai/McpConfig.h"

#include <QList>
#include <optional>

class McpManager;
class QWidget;

namespace mcpui {

std::optional<McpServerConfig> editServer(QWidget* parent, McpManager* mcp, const McpServerConfig& initial,
                                          bool isNew);

QList<McpServerConfig> importServers(QWidget* parent, QString* note);

}
