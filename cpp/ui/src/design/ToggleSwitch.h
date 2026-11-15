#pragma once
#include <QAbstractButton>

class QVariantAnimation;

class ToggleSwitch : public QAbstractButton
{
    Q_OBJECT
public:
    explicit ToggleSwitch(bool on = true, QWidget* parent = nullptr);
    QSize sizeHint() const override;
    // 开着有代价的开关(静默模式、退出即停止防护):金刚里开时槽里通琥珀色,不是能量蓝。另外两套皮肤不变。
    void setCaution(bool on);

protected:
    void paintEvent(QPaintEvent*) override;
    void checkStateSet() override;
    void nextCheckState() override;
    void enterEvent(QEnterEvent*) override;
    void leaveEvent(QEvent*) override;
    void focusInEvent(QFocusEvent*) override;
    void focusOutEvent(QFocusEvent*) override;

private:
    qreal m_pos = 1.0;
    bool m_hover = false;
    bool m_keyboardFocus = false;
    bool m_caution = false;
    QVariantAnimation* m_anim = nullptr;
};
