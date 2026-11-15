#pragma once
class QWidget;
class IpcClient;

namespace pages {

QWidget* interceptions(IpcClient* ipc);
QWidget* activity(IpcClient* ipc);
QWidget* timeline(IpcClient* ipc);
QWidget* processes(IpcClient* ipc);
QWidget* rules(IpcClient* ipc);
QWidget* trust(IpcClient* ipc);
QWidget* softwareCatalog();
QWidget* quarantine(IpcClient* ipc);
QWidget* persistence(IpcClient* ipc);
QWidget* hardening(IpcClient* ipc);
QWidget* yaraRules(IpcClient* ipc);

}
