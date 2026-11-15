#pragma once
#include <QByteArray>
#include <QColor>
#include <QHash>
#include <QList>
#include <QPointer>
#include <QRect>
#include <QSet>
#include <QStringList>
#include <QUuid>
#include <QVariantMap>
#include <QWidget>

#include "bulwark/models/Enums.h"

#include <functional>

class Backdrop;
class BannerHost;
class BrandPanel;
class HexButton;
class IconTile;
class KeyCap;
class KeyGroup;
class PromptDialog;
class QAction;
class QButtonGroup;
class QCloseEvent;
class QHBoxLayout;
class QLabel;
class QStackedWidget;
class QSystemTrayIcon;
class QVBoxLayout;
class IpcClient;
class PageTransition;
class QPropertyAnimation;
class ResidentBot;
namespace motion { class Ticker; }
class ToastNotifier;
class TrafficOverlay;

namespace bulwark {
struct SecurityEvent;
namespace ipc {
struct RemediationReportPayload;
struct YaraRulesStatusPayload;
}
}

// 主窗口 = 小垒的机身:无边框异形窗,外壳自绘(design/Shell),顶部一排键帽导航。
class MainWindow : public QWidget
{
    Q_OBJECT
public:
    // quiet:切换皮肤重建窗口时为 true,不再重复弹「已在托盘」之类的欢迎通知。
    explicit MainWindow(QWidget* parent = nullptr, bool quiet = false);
    ~MainWindow() override;

    void setQuitAuthorizer(std::function<void(const QString& reason)> fn) {
        m_quitAuthorizer = std::move(fn);
    }

    // 收托盘授权器。任何到达 closeEvent 的关闭都必须消费 WindowGuard 发出的短时一次性
    // 授权；这使原生消息过滤器被 Qt 绕过、或外部线程直接投递 WM_CLOSE 时也不能隐藏界面。
    void setCloseToTrayAuthorizer(std::function<bool()> fn) {
        m_closeToTrayAuthorizer = std::move(fn);
    }

    void setNativeEventHook(std::function<bool(const QByteArray&, void*, qintptr*)> fn) {
        m_nativeEventHook = std::move(fn);
    }

    void reportSelfProtectionEvent(const QString& what, const QString& detail);

    // 换皮肤:只有没有询问弹窗、也没有模态框挂着时才能整窗重建。
    bool canRebuild() const;
    QString currentPageKey() const { return currentKey(); }
    void openPage(const QString& key) { navigateTo(key); }

    void showFromTray();
    // 下一次 show() 不做淡入(换装转场自己负责过渡)。
    void skipNextIntro() { m_skipIntro = true; }

signals:
    void windowVisibilityIntentChanged(bool expectedHidden);

protected:
    bool nativeEvent(const QByteArray& eventType, void* message, qintptr* result) override;
    void closeEvent(QCloseEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void changeEvent(QEvent* event) override;
    void showEvent(QShowEvent* event) override;
    void hideEvent(QHideEvent* event) override;
    void paintEvent(QPaintEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseDoubleClickEvent(QMouseEvent* event) override;
    void leaveEvent(QEvent* event) override;
    bool eventFilter(QObject* watched, QEvent* event) override;

private slots:
    void onNavClicked(int index);
    void onPromptReceived(const bulwark::SecurityEvent& event);
    void onBlockNotification(const bulwark::SecurityEvent& event,
                             bulwark::EnforcementOutcome enforcement,
                             bool timeoutBlock, bool execBlocked);
    void onRemediationReport(const bulwark::ipc::RemediationReportPayload& report);
    void onYaraStatus(const bulwark::ipc::YaraRulesStatusPayload& status);
    void setConnected(bool connected);
    void quitApp();

private:
    QWidget* buildTopBar();
    QWidget* buildContent();
    void addPage(const QString& key, const QString& group, const QString& icon, const QString& nav,
                 const QString& title, const QString& subtitle, QWidget* page);
    KeyGroup* groupFor(const QString& title);
    void setupTray();
    void navigateTo(const QString& pageKey, const QVariantMap& args = QVariantMap());
    void refreshProtectionPill();
    void refreshQuitAction();
    void startBackendFromUi();

    bool shellMaximized() const;
    void toggleMaximize();
    void applyShellMargins();
    void syncKeyDensity();
    QRect bodyRect() const;
    QRectF shellBody() const;
    Qt::Edges edgesAt(const QPoint& pos) const;
    void beginMove(const QPoint& globalPos);

    QString currentKey() const;
    bool isViewing(const QString& key) const;
    void bumpBadge(const QString& key);
    void clearBadge(const QString& key);
    void clearViewedBadge();

    void focusPageSearch();

    QStackedWidget* m_stack = nullptr;
    QButtonGroup* m_navGroup = nullptr;
    QWidget* m_topBar = nullptr;
    QHBoxLayout* m_keysRow = nullptr;
    QList<KeyGroup*> m_groups;
    BrandPanel* m_brand = nullptr;
    HexButton* m_maxBtn = nullptr;
    Backdrop* m_content = nullptr;
    IconTile* m_titleTile = nullptr;
    QLabel* m_title = nullptr;
    QLabel* m_subtitle = nullptr;
    QLabel* m_titleCode = nullptr;   // 金刚:页标题右边的英文代号
    QHBoxLayout* m_headerActions = nullptr;
    QList<QWidget*> m_pageActions;
    BannerHost* m_banners = nullptr;
    PageTransition* m_pageFx = nullptr;
    QList<KeyCap*> m_navButtons;
    bool m_compactKeys = false;
    int m_brandMood = 7;   // robot::Mood::Sleep:外壳上的能量宝石跟着防护状态变色
    int m_dimLights = 0x3F; // 金刚外壳顶边的六盏示廓灯 = 六个防护维度(位序见 shell::Extras::lights)
    motion::Ticker* m_crownTicker = nullptr;
    QPropertyAnimation* m_intro = nullptr;
    bool m_skipIntro = false;

    bool m_fakeMax = false;
    QRect m_restoreGeometry;
    QPoint m_pressPos;
    bool m_pressOnChrome = false;

    QHash<QString, int> m_unread;
    // YARA 最近命中(SHA-256 | 时间)。连上服务后的第一份状态只作基线,之后新出现的才提醒。
    QSet<QString> m_yaraSeen;
    bool m_yaraBaseline = false;

    // 防护状态所依赖的真实状态。默认按「未知」呈现,绝不默认说"已开启"。
    bool m_svcConnected = false;
    bool m_backendStarting = false;   // 后台服务启动流程进行中(含 UAC 与等待就绪)
    bool m_protectionEnabled = false;
    // 「退出界面即停止防护」的当前值(服务推来的)。决定托盘退出项的文案、以及退出前要不要
    // 先把后果说清楚。默认 false = 按「防护常驻」说话,与服务端的默认一致。
    bool m_protectionFollowsUi = false;
    bool m_kernelConnected = false;
    bool m_haveSettings = false;
    QString m_kernelStatus;
    IpcClient* m_ipc = nullptr;
    QSystemTrayIcon* m_tray = nullptr;
    QAction* m_actQuit = nullptr;
    QAction* m_actTraffic = nullptr;
    QAction* m_actResident = nullptr;
    ToastNotifier* m_toasts = nullptr;
    TrafficOverlay* m_traffic = nullptr;
    ResidentBot* m_resident = nullptr;
    QStringList m_titles;
    QStringList m_subtitles;
    QStringList m_pageKeys;
    QStringList m_pageIcons;
    QList<QColor> m_pageHues;
    bool m_forceQuit = false;
    bool m_quiet = false;
    std::function<bool()> m_closeToTrayAuthorizer;
    std::function<void(const QString&)> m_quitAuthorizer;
    std::function<bool(const QByteArray&, void*, qintptr*)> m_nativeEventHook;
    bool m_trayHintShown = false;
    bool m_trayIntroShown = false;
    int m_trayRetries = 0;
    qint64 m_aiCreditNoticeMs = 0;
    int m_blockedToday = 0;

    int m_promptTimeoutSeconds = 30;
    bool m_defaultBlock = false;
    bool m_promptTimeoutBlockHighRisk = true;

    QHash<QUuid, PromptDialog*> m_openPrompts;
};
