#pragma once
#include <QColor>
#include <QPoint>
#include <QString>
#include <QStringList>
#include <QWidget>

class CountdownBar;
class ElidingLabel;
class QHBoxLayout;
class QLabel;
class QPropertyAnimation;
class RobotWidget;
class StampLabel;

class ToastWindow : public QWidget
{
    Q_OBJECT
public:
    enum class Kind {
        Block, BlockAlertedOnly, BlockFailed, Info, Cleanup, CleanupIncomplete,
    };

    ToastWindow(Kind kind, const QString& heading, const QString& sentence, const QString& meta,
                const QStringList& tags, int lifetimeMs, const QString& badgeText = QString(),
                const QString& actionText = QString(), QWidget* parent = nullptr);

    void setThreat(const QString& category, const QString& name = QString());

    void setCode(QWidget* block);

    void setInsight(QWidget* panel);

    void settleInsight(int minRemainingMs);

    void place(const QPoint& topLeft);

    // 主按钮右边的次要按钮(幽灵样式),点了发 secondaryClicked 并关闭卡片。
    void setSecondaryAction(const QString& text);
    // 卡片被「砸」一下(钢印落下时用);自带钢印的卡片会自己调,主体里另放钢印的由主体来调。
    void thump();

signals:
    void closed(ToastWindow* self);
    void clicked(ToastWindow* self);
    void secondaryClicked(ToastWindow* self);
    void resized(ToastWindow* self);

protected:
    void showEvent(QShowEvent* event) override;
    bool eventFilter(QObject* watched, QEvent* event) override;

private slots:
    void beginClose();

private:
    void refitHeight();
    int fittedHeight();
    void onCountdownFinished();
    void syncStamp();
    void kick();

    static constexpr int kMaxInsightHoldMs = 30000;
    static constexpr int kDefaultCardWidth = 412;
    static constexpr int kCodeCardWidth = 540;

    QWidget* m_codeSlot = nullptr;
    QWidget* m_insightSlot = nullptr;
    bool m_insightPending = false;
    bool m_expired = false;
    QWidget* m_threatRow = nullptr;
    QLabel* m_threatPill = nullptr;
    ElidingLabel* m_threatName = nullptr; // must stay ElidingLabel*: setText() is not virtual
    QColor m_accent;
    QString m_description;
    CountdownBar* m_bar = nullptr;
    RobotWidget* m_bot = nullptr;
    QWidget* m_card = nullptr;
    QWidget* m_stampHole = nullptr;
    StampLabel* m_stamp = nullptr;
    QHBoxLayout* m_actions = nullptr;
    QPropertyAnimation* m_fade = nullptr;
    QPropertyAnimation* m_slide = nullptr;
    int m_lifetimeMs = 6000;
    bool m_shown = false;
    bool m_closing = false;
};
