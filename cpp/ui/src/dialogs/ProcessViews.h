#pragma once
#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/ProcessEntry.h"

#include <QColor>
#include <QString>

class Inspector;
class IpcClient;
class QMenu;
class QWidget;

namespace procview {

struct Hint {
    QString text;
    QColor color;
    int rank = 0;
};
Hint hint(const bulwark::ProcessEntry& e);
QColor tone(const bulwark::ProcessEntry& e);
QString signatureText(const bulwark::ProcessEntry& e);
QColor signatureColor(const bulwark::ProcessEntry& e);
QString lockReason(const bulwark::ProcessEntry& e);
QString searchText(const bulwark::ProcessEntry& e);

void fill(Inspector* in, const bulwark::ProcessEntry& e, IpcClient* ipc, bool actions);
void fillMenu(QMenu* menu, QWidget* context, const bulwark::ProcessEntry& e, IpcClient* ipc,
              bool withDetailWindow);
void run(QWidget* context, IpcClient* ipc, const bulwark::ProcessEntry& e, bulwark::ipc::ProcessActionKind kind);
void openDetail(QWidget* parent, const bulwark::ProcessEntry& e, IpcClient* ipc);

}
