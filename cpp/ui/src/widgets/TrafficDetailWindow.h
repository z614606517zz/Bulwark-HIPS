#pragma once
#include <QDialog>
#include <QHash>
#include <QUuid>

#include "bulwark/ipc/Payloads.h"

class ElidingLabel;
class IpcClient;
class QLabel;
class QPushButton;
class QTreeWidget;
class QTreeWidgetItem;

class TrafficDetailWindow : public QDialog
{
    Q_OBJECT
public:
    TrafficDetailWindow(IpcClient* ipc, const bulwark::ipc::NetTrafficRowPayload& row, QWidget* parent = nullptr);
    ~TrafficDetailWindow() override;

    int pid() const { return m_pid; }

private:
    void onSnapshot(const bulwark::ipc::NetTrafficSnapshotPayload& snap);
    void updateHeader(const bulwark::ipc::NetTrafficRowPayload* row, bool perProcess);
    void updateConnections(const QList<bulwark::ipc::NetTrafficConnPayload>& conns);
    void requestHistory();
    void onTimeline(const bulwark::ipc::TimelineResponsePayload& p);
    void connMenu(const QPoint& pos);
    void setStatus(const QString& text);

    IpcClient* m_ipc = nullptr;
    int m_pid = 0;
    bulwark::ipc::NetTrafficRowPayload m_row;
    bool m_gotConnections = false;

    QLabel* m_rateValue = nullptr;
    QLabel* m_totalValue = nullptr;
    QLabel* m_connValue = nullptr;
    QLabel* m_proxyValue = nullptr;
    QLabel* m_proxyCaption = nullptr;
    ElidingLabel* m_status = nullptr;

    QTreeWidget* m_conns = nullptr;
    QLabel* m_connNote = nullptr;
    QHash<QString, QTreeWidgetItem*> m_connItems;

    QTreeWidget* m_files = nullptr;
    QTreeWidget* m_events = nullptr;
    QLabel* m_histNote = nullptr;
    QPushButton* m_refresh = nullptr;
    QUuid m_timelineReq;
};
