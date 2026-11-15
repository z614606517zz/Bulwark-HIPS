#pragma once
#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/SecurityEvent.h"
#include "design/RecordModel.h"

#include <QColor>
#include <QList>
#include <QPair>
#include <QString>
#include <QUuid>

#include <optional>

class Inspector;
class IpcClient;
class QMenu;
class QVBoxLayout;
class QWidget;

namespace evtview {

struct Outcome {
    bulwark::VerdictAction action = bulwark::VerdictAction::Allow;
    bulwark::EnforcementOutcome enforcement = bulwark::EnforcementOutcome::NotApplicable;
};
inline Outcome outcomeOf(const bulwark::ipc::EventLogPayload& p) { return {p.action, p.enforcement}; }

RecordView recordView(const bulwark::ipc::EventLogPayload& p);
QString searchText(const bulwark::SecurityEvent& e);
inline QString keyOf(const bulwark::SecurityEvent& e) { return e.id.toString(QUuid::WithoutBraces); }

QList<QPair<QString, QColor>> factChips(const bulwark::SecurityEvent& e);
QWidget* evidenceList(const bulwark::SecurityEvent& e);
QWidget* codeSection(const bulwark::SecurityEvent& e, bool commandLineFallback);
QWidget* processChain(const bulwark::SecurityEvent& e);
void addForensicFields(QVBoxLayout* section, const bulwark::SecurityEvent& e);

void fillInspector(Inspector* in, const bulwark::ipc::EventLogPayload& p, IpcClient* ipc,
                   const QString& trustSource);
void fillContextMenu(QMenu* menu, QWidget* context, const bulwark::ipc::EventLogPayload& p,
                     IpcClient* ipc, const QString& trustSource);

void openTimeline(QWidget* parent, const bulwark::SecurityEvent& e, IpcClient* ipc,
                  std::optional<Outcome> outcome = std::nullopt);
void openGraph(QWidget* context, IpcClient* ipc, const QUuid& seedEventId, int pid, const QString& title);

void trust(QWidget* context, IpcClient* ipc, const QString& path, bool isDirectory, const QString& source);

}
