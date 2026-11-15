#pragma once
#include <QAbstractButton>
#include <QColor>

class QVariantAnimation;

class NavButton : public QAbstractButton
{
    Q_OBJECT
public:
    NavButton(const QString& iconName, const QString& text, QWidget* parent = nullptr);
    QSize sizeHint() const override;

    void setCompact(bool compact);
    bool isCompact() const { return m_compact; }

    void setBadge(int count, const QColor& color = QColor());
    int badge() const { return m_badge; }

    void setIdentity(const QColor& hue);
    QColor identity() const { return m_identity; }

protected:
    void paintEvent(QPaintEvent*) override;
    void enterEvent(QEnterEvent*) override;
    void leaveEvent(QEvent*) override;
    void focusInEvent(QFocusEvent*) override;
    void focusOutEvent(QFocusEvent*) override;

private:
    void fadeHover(qreal to);
    void animateSelection(bool on);
    void syncAccessible();

    QString m_icon;
    qreal m_hover = 0.0;
    qreal m_select = 0.0;
    bool m_selecting = false;
    bool m_keyboardFocus = false;
    bool m_compact = false;
    int m_badge = 0;
    QColor m_badgeColor;
    QColor m_identity;
    QVariantAnimation* m_anim = nullptr;
    QVariantAnimation* m_selAnim = nullptr;
};
