#pragma once
#include "design/Sheet.h"

#include "bulwark/ipc/Payloads.h"

#include <QHash>
#include <QList>
#include <QPointer>
#include <QUuid>

class CountdownBar;
class FitScrollArea;
class IpcClient;
class QPushButton;
class QVBoxLayout;

class RemediationReportDialog : public Sheet
{
    Q_OBJECT
public:
    RemediationReportDialog(const bulwark::ipc::RemediationReportPayload& report,
                            IpcClient* ipc, QWidget* parent = nullptr);

private:
    QWidget* group(QVBoxLayout* into, const QString& key, const QString& title, const QColor& color, int count);
    void scrollToGroup(const QString& key);
    void retryAll();
    void forceHandle(const bulwark::ipc::RemediationSkippedItem& item, QPushButton* button);
    void openQuarantine();
    QString reportText() const;
    void setPinned(bool pinned);

    bulwark::ipc::RemediationReportPayload m_report;
    IpcClient* m_ipc = nullptr;
    FitScrollArea* m_scroll = nullptr;
    QHash<QString, QWidget*> m_groups;
    QList<QPair<QString, QPushButton*>> m_retry;
    QHash<QUuid, QPointer<QPushButton>> m_forcePending;
    CountdownBar* m_autoClose = nullptr;
    QPushButton* m_pin = nullptr;
    bool m_pinned = false;
};
