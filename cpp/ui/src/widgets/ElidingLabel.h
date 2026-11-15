#pragma once
#include <QFontMetrics>
#include <QLabel>
#include <QResizeEvent>
#include <QSize>

class ElidingLabel : public QLabel
{
public:
    explicit ElidingLabel(const QString& text = QString(), QWidget* parent = nullptr)
        : QLabel(parent), m_full(text)
    {
        QLabel::setText(text);
        if (!text.isEmpty())
            setToolTip(text);
        setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    }

    void setElideMode(Qt::TextElideMode mode)
    {
        m_mode = mode;
        reElide();
    }

    void setText(const QString& text)
    {
        m_full = text;
        setToolTip(text);
        reElide();
    }

    QString fullText() const { return m_full; }

    QSize minimumSizeHint() const override
    {
        QSize s = QLabel::minimumSizeHint();
        s.setWidth(qMin(s.width(), 24));
        return s;
    }

protected:
    void resizeEvent(QResizeEvent* e) override
    {
        QLabel::resizeEvent(e);
        reElide();
    }

private:
    void reElide()
    {
        if (m_inElide)
            return;
        m_inElide = true;
        const int w = width();
        const QString shown = (w > 4) ? fontMetrics().elidedText(m_full, m_mode, w) : m_full;
        QLabel::setText(shown);
        m_inElide = false;
    }

    QString m_full;
    Qt::TextElideMode m_mode = Qt::ElideRight;
    bool m_inElide = false;
};
