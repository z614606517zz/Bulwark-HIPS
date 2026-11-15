#pragma once
#include "design/Robot.h"

#include <QAbstractButton>
#include <QColor>
#include <QString>
#include <QWidget>

#include <functional>

class ElidingLabel;
class QHBoxLayout;
class QPainter;
class QPushButton;
class QSpacerItem;
class QVariantAnimation;
class StickerText;

// 驾驶舱顶栏的器件:键帽导航、键组(带警示条标题)、六角窗口按钮、品牌面板。

class KeyCap : public QAbstractButton
{
    Q_OBJECT
public:
    KeyCap(const QString& stickerIcon, const QString& text, QWidget* parent = nullptr);

    void setCompact(bool compact);
    bool isCompact() const { return m_compact; }
    // 某种形态下的宽度,与当前形态无关:顶栏按它决定放不放得下。
    int widthFor(bool compact) const;
    void setBadge(int count);
    int badge() const { return m_badge; }
    // 金刚的键帽用线条图标(AppIcon 的名字),另外两套皮肤仍然用贴纸图标。
    void setLineIcon(const QString& name);

    QSize sizeHint() const override;
    QSize minimumSizeHint() const override { return sizeHint(); }

protected:
    void paintEvent(QPaintEvent*) override;
    void enterEvent(QEnterEvent*) override;
    void leaveEvent(QEvent*) override;
    void focusInEvent(QFocusEvent* e) override;
    void focusOutEvent(QFocusEvent* e) override;

private:
    void syncAccessible();
    void syncPress();
    void paintTitan(QPainter& p);

    QString m_icon;
    QString m_lineIcon;
    bool m_compact = false;
    bool m_hover = false;
    bool m_keyboardFocus = false;
    int m_badge = 0;
    qreal m_press = 0.0;
    qreal m_badgeT = 1.0;
    QVariantAnimation* m_pressAnim = nullptr;
    QVariantAnimation* m_badgeAnim = nullptr;
};

class KeyGroup : public QWidget
{
public:
    explicit KeyGroup(const QString& title, QWidget* parent = nullptr);
    void addKey(KeyCap* key);
    void setCompact(bool compact);
    // 金刚:组名铭牌右边的英文代号(MONITOR / CONTROL / MISC)。
    void setCode(const QString& code);
    // 某种形态下整组的宽度(含组自己的边距和键距),与当前形态无关。
    int widthFor(bool compact) const;

protected:
    void paintEvent(QPaintEvent*) override;

private:
    QString m_title;
    QString m_code;
    QHBoxLayout* m_row = nullptr;
    bool m_compact = false;
};

class HexButton : public QAbstractButton
{
public:
    HexButton(const QString& stickerIcon, const QColor& fill, const QString& tip, QWidget* parent = nullptr);
    void setIconName(const QString& name);
    QSize sizeHint() const override { return {34, 30}; }

protected:
    void paintEvent(QPaintEvent*) override;
    void enterEvent(QEnterEvent*) override;
    void leaveEvent(QEvent*) override;

private:
    QString m_icon;
    QColor m_fill;
    bool m_hover = false;
};

// 左上角:小垒的头 + 「磐垒」贴纸字 + 防护状态。
class BrandPanel : public QWidget
{
    Q_OBJECT
public:
    explicit BrandPanel(QWidget* parent = nullptr);

    void setProtection(robot::Mood mood, const QString& text, const QColor& color, const QString& tip);
    // 金刚:第二扇风挡上的两行字(状态 + 小字)和指示灯的颜色。
    void setTitanStatus(const QString& title, const QString& sub, const QColor& lamp);
    void setService(bool connected);
    void setServiceStarting(bool starting);
    void setStartServiceHandler(std::function<void()> fn) { m_onStart = std::move(fn); }
    void setCompact(bool compact);
    int widthFor(bool compact) const;

signals:
    void clicked();

protected:
    void paintEvent(QPaintEvent*) override;
    void mouseReleaseEvent(QMouseEvent* e) override;

private:
    void syncAction();
    void paintTitan(QPainter& p);
    int titanGap(bool compact) const;
    void syncTitanLayout();

    RobotWidget* m_bot = nullptr;
    StickerText* m_name = nullptr;
    ElidingLabel* m_state = nullptr;
    QPushButton* m_start = nullptr;
    QWidget* m_text = nullptr;
    QSpacerItem* m_gap = nullptr;
    QString m_titanTitle;
    QString m_titanSub;
    QColor m_titanLamp;
    bool m_compact = false;
    bool m_connected = false;
    bool m_starting = false;
    std::function<void()> m_onStart;
};
