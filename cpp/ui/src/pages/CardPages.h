#pragma once

class QWidget;
class IpcClient;

namespace pages {

QWidget* settings(IpcClient* ipc);
QWidget* boost(IpcClient* ipc);

}
