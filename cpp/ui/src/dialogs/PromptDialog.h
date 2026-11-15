#pragma once
#include "design/Sheet.h"

#include "bulwark/models/SecurityEvent.h"

#include <QElapsedTimer>
#include <QString>

class AiScanner;
class CountdownBar;
class QLabel;
class QPushButton;
class Segmented;
namespace ui { struct ConfirmSpec; }

class PromptDialog : public Sheet
{
    Q_OBJECT
public:
    explicit PromptDialog(const bulwark::SecurityEvent& event, QWidget* parent = nullptr,
                          int timeoutSeconds = 0, bool defaultAllow = true, AiScanner* ai = nullptr);

    bool allowed() const { return m_allowed; }
    bool timedOut() const { return m_timedOut; }
    bool remember() const;
    int scopeIndex() const;

    // 高危询问选「永久」放行时那张二次确认框的内容。独立成静态函数,离屏预览才能把它画出来核对。
    static ui::ConfirmSpec permanentAllowConfirmSpec(const bulwark::SecurityEvent& event);

protected:
    void showEvent(QShowEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    bool focusNextPrevChild(bool next) override;

private:
    void decide(bool allow);
    bool inputGuardActive() const;
    void syncScopeUi();
    bool needsPermanentAllowConfirm() const;
    bool confirmPermanentAllow();

    bulwark::SecurityEvent m_event;
    bool m_allowed = false;
    bool m_timedOut = false;
    bool m_decided = false;      // 用户点了裁决按钮(而不是 Esc / 关窗 / 超时 / 被撤回)
    bool m_confirming = false;   // 「永久放行」的二次确认框正开着
    Segmented* m_scope = nullptr;
    QLabel* m_scopeHint = nullptr;
    CountdownBar* m_countdown = nullptr;
    int m_timeoutSeconds = 0;
    bool m_defaultAllow = true;
    QPushButton* m_allowBtn = nullptr;
    QPushButton* m_blockBtn = nullptr;
    QString m_allowText;         // 按钮的基础文字,选了范围后在后面拼上范围名
    QString m_blockText;
    QElapsedTimer m_shownAt;     // 弹出时刻,用来忽略刚弹出那一瞬间的输入
};
