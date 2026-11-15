#pragma once
#include "design/Tone.h"

#include <QElapsedTimer>
#include <QFrame>
#include <QList>
#include <QPoint>
#include <QPointer>
#include <QString>

#include <functional>

class QHBoxLayout;
class QLabel;
class QPushButton;
class QTimer;
class QVBoxLayout;

class Banner : public QFrame
{
    Q_OBJECT
public:
    Banner(ui::Tone tone, const QString& text, QWidget* parent = nullptr);

    ui::Tone tone() const { return m_tone; }
    QString text() const;
    void setText(const QString& text);
    void setAction(const QString& text, std::function<void()> fn);
    void setTimeout(int ms);
    void dismiss();

signals:
    void dismissed();

protected:
    void paintEvent(QPaintEvent*) override;

private:
    void syncHoverPause();

    ui::Tone m_tone;
    QLabel* m_text = nullptr;
    QPushButton* m_action = nullptr;
    std::function<void()> m_fn;
    QTimer* m_timer = nullptr;
    int m_remaining = 0;
    QElapsedTimer m_since;
    bool m_closing = false;

    QTimer* m_hoverWatch = nullptr;
    QPoint m_lastCursor;
    bool m_hoverArmed = false;
    bool m_holding = false;
};

class BannerHost : public QWidget
{
    Q_OBJECT
public:
    explicit BannerHost(QWidget* parent = nullptr);

    Banner* post(ui::Tone tone, const QString& text, int timeoutMs = -1);
    void clear(bool animated = true);

    static BannerHost* find(QWidget* from);

private:
    QVBoxLayout* m_stack = nullptr;
    QList<QPointer<Banner>> m_banners;
};

namespace ui {

Banner* notify(QWidget* context, Tone tone, const QString& text, int timeoutMs = -1);

}
