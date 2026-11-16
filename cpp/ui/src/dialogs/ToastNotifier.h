#pragma once
#include <QHash>
#include <QList>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QUuid>

#include "bulwark/models/Enums.h"

namespace bulwark { struct SecurityEvent; }
namespace bulwark::ipc {
struct AttackChainHitPayload;
struct ManualQuarantineResultPayload;
struct RemediationReportPayload;
}

namespace ui { struct ConfirmSpec; }

class AiScanner;
class IpcClient;
class ToastWindow;
class QTimer;
class QWidget;

class ToastNotifier : public QObject
{
    Q_OBJECT
public:
    explicit ToastNotifier(QObject* parent = nullptr);

    void reserveCorner(QWidget* window);
    void releaseCorner(QWidget* window);

    void setAiScanner(AiScanner* ai);

    void setIpc(IpcClient* ipc);

    void showBlock(const bulwark::SecurityEvent& event,
                   bulwark::EnforcementOutcome enforcement =
                       bulwark::EnforcementOutcome::NotApplicable,
                   bool timeoutBlock = false,
                   bool execBlocked = false);
    void showInfo(const QString& heading, const QString& detail, int lifetimeMs = 5000,
                  const QString& actionText = QString(), const QString& actionId = QString());

    void showRemediation(const bulwark::ipc::RemediationReportPayload& report);
    void showQuarantineRetry(const bulwark::ipc::ManualQuarantineResultPayload& result);

    // 受保护目录拒掉了一次写入 / 改名 / 删除,而引擎没有把这个程序判成威胁:文件没被改动,
    // 不属于「拦下了危险行为」。
    static bool isGuardedWriteDenial(const bulwark::SecurityEvent& event,
                                     bulwark::EnforcementOutcome enforcement,
                                     bool timeoutBlock, bool execBlocked);

    // 拦截通知上「撤销拦截 · 信任 1 小时」点下去之后那张确认框的内容。独立成静态函数,
    // 离屏预览才能把它画出来核对。
    static ui::ConfirmSpec undoBlockConfirmSpec(const QString& path);

signals:
    // unenforced:这张通知说的是「没拦住 / 处置未成功」的行为,事件记录里它们在「未拦住」页签下。
    void blockToastClicked(bool unenforced);
    void infoToastActivated(const QString& actionId);

    void blockPresented(const QString& actorPath, bulwark::EnforcementOutcome enforcement);
    void blockBatchPresented(int blocked, int unenforced);

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    // navigateOnClick=false:这张拦截通知的主按钮另有用途,点它不要跳到拦截记录。
    // unenforced:点「查看详情」时跳到事件记录的「未拦住」页签,而不是「拦截」。
    void present(ToastWindow* toast, bool isBlock, bool navigateOnClick = true, bool unenforced = false);
    // 先做前置检查,再弹确认框;确认后才真正写入 1 小时信任。
    void undoBlockByTrust(const QString& actorPath);
    void confirmUndoBlock(const QString& path);
    void showGuardedWriteDenied(const bulwark::SecurityEvent& e, qint64 nowMs);
    void trustGuardedWriter(const QString& actorPath);
    void reflow();
    void scheduleReflow();
    void remove(ToastWindow* toast);
    void flushSuppressed();
    void pruneRecentKeys(qint64 nowMs);
    void applyTrustCorrection(const QString& actorPath, bulwark::RememberScope scope, QWidget* parent);
    void applyRuleDeletion(const QString& matchedRuleNote, QWidget* parent);

    QList<ToastWindow*> m_stack;
    QList<QPointer<QWidget>> m_cornerWindows; // reserveCorner():toast 必须让开的窗口
    QPointer<AiScanner> m_ai;
    QPointer<IpcClient> m_ipc;

    static constexpr int kAiReadMs = 10000;
    static constexpr int kAiFailReadMs = 4000;
    // 离线解释的保底阅读时间。比 kAiReadMs 略短:它从卡片出现的第一刻就在那儿,
    // 不像 AI 解读要先等几秒才到,所以卡片原本的时长已经覆盖了一部分阅读时间。
    static constexpr int kLocalReadMs = 9000;
    bool m_reflowPending = false;

    QHash<QString, qint64> m_recentBlockKeys;
    qint64 m_lastBlockToastMs = 0;
    int m_suppressedBlocks = 0;
    int m_suppressedUnenforced = 0;
    QTimer* m_coalesceTimer = nullptr;

    static constexpr int kMaxVisible = 4;
    static constexpr int kDedupWindowMs = 10000;
    static constexpr int kMinBlockGapMs = 800;

    // 同一个程序往受保护目录里写被拒,一分钟只提醒一次:解压 / 保存会连着触发几十次。
    QHash<QString, qint64> m_guardNoticeMs;
    static constexpr int kGuardNoticeGapMs = 60000;

};
