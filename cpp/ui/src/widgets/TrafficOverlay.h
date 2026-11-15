#pragma once
#include <QHash>
#include <QIcon>
#include <QList>
#include <QPoint>
#include <QPointer>
#include <QRect>
#include <QString>
#include <QUuid>
#include <QVector>
#include <QWidget>

#include "bulwark/ipc/Payloads.h"

class IpcClient;
class QTimer;
namespace motion { class Ticker; }

class TrafficOverlay : public QWidget
{
    Q_OBJECT
public:
    explicit TrafficOverlay(IpcClient* ipc, QWidget* parent = nullptr);
    ~TrafficOverlay() override;

    static TrafficOverlay* instance();
    static bool savedEnabled();

    bool overlayEnabled() const { return m_enabled; }
    void setOverlayEnabled(bool on);
    void applySavedState();
    void resetPosition();
    void openDetails(const bulwark::ipc::NetTrafficRowPayload& row);
    static bool locateFile(const QString& path);

signals:
    void overlayEnabledChanged(bool on);
    void notice(const QString& heading, const QString& detail);

protected:
    void paintEvent(QPaintEvent* e) override;
    void mousePressEvent(QMouseEvent* e) override;
    void mouseMoveEvent(QMouseEvent* e) override;
    void mouseReleaseEvent(QMouseEvent* e) override;
    void mouseDoubleClickEvent(QMouseEvent* e) override;
    void contextMenuEvent(QContextMenuEvent* e) override;
    void enterEvent(QEnterEvent* e) override;
    void leaveEvent(QEvent* e) override;
    void showEvent(QShowEvent* e) override;
    void hideEvent(QHideEvent* e) override;
    bool event(QEvent* e) override;

private:
    struct RowView {
        bulwark::ipc::NetTrafficRowPayload r;
        double down = 0.0;
        double up = 0.0;
        double pdown = 0.0;
        double pup = 0.0;
        qint64 lastSeenMs = 0;
        qint64 lastActiveMs = 0;
    };

    enum class Hit { None, Close, Chevron, Boost };

    void onSnapshot(const bulwark::ipc::NetTrafficSnapshotPayload& snap);
    void onTick();
    void rebuildOrder();
    const RowView* viewOf(int pid) const;

    void syncSubscription();
    void applyGeometry();
    void positionDefault();
    void clampToScreen();

    int bodyHeight() const;
    QRect closeRect() const;
    QRect chevronRect() const;
    QRect boostRect() const;
    QRect headerRect() const;
    QRect rowRect(int index) const;
    int rowAt(const QPoint& pos) const;
    Hit buttonAt(const QPoint& pos) const;
    QString rowTip(const RowView& v) const;
    QIcon iconFor(const QString& path);

    void setCollapsed(bool on);
    void setOnlyActive(bool on);
    void locate(const RowView& v);
    void kill(const RowView& v, bool tree);
    void analyze(const RowView& v);
    void openInProcesses(int pid);
    void copyPath(const RowView& v);
    void onProcessActionResult(const bulwark::ipc::ProcessActionResultPayload& r);
    void runBoost();
    void onSystemBoostResult(const bulwark::ipc::SystemBoostResultPayload& r);

    IpcClient* m_ipc = nullptr;
    bool m_enabled = false;
    bool m_subscribed = false;
    QList<int> m_sentFocus;
    QHash<int, QPointer<QWidget>> m_details;
    bool m_collapsed = false;
    bool m_onlyActive = false;

    bulwark::ipc::NetTrafficSnapshotPayload m_snap;
    QHash<int, RowView> m_rows;
    QVector<int> m_order;
    int m_hidden = 0;
    double m_sysDown = 0.0;
    double m_sysUp = 0.0;
    QVector<double> m_histDown;
    QVector<double> m_histUp;
    qint64 m_lastSnapMs = 0;
    bool m_gotData = false;

    int m_hoverRow = -1;
    Hit m_hoverBtn = Hit::None;
    Hit m_pressBtn = Hit::None;
    int m_selectedPid = 0;
    bool m_dragging = false;
    bool m_dragMoved = false;
    bool m_userMoved = false;
    QPoint m_dragStartGlobal;
    QPoint m_dragStartPos;

    struct LastAction {
        int pid = 0;
        int kind = -1;
        qint64 atMs = 0;
        QString name;
    } m_last;

    QUuid m_boostReq;
    qint64 m_boostStartMs = 0;

    QHash<QString, QIcon> m_icons;
    QTimer* m_tick = nullptr;

    // 雷达表指针:按弹簧阻尼追向目标刻度(0..1),而不是一秒一跳。[0] 下行,[1] 上行。
    void kickNeedles();
    void stepNeedles();
    double gaugeTarget(int i) const;
    double m_needle[2] = {0.0, 0.0};
    double m_needleV[2] = {0.0, 0.0};
    motion::Ticker* m_needleTick = nullptr;
};
