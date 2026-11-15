#pragma once
#include <QElapsedTimer>
#include <QList>
#include <QObject>
#include <QPointer>

class Backdrop;
class QEvent;
class QVariantAnimation;
class QWidget;

class PageTransition : public QObject
{
public:
    PageTransition(Backdrop* host, QWidget* header, const QList<QWidget*>& body);
    ~PageTransition() override;

    bool start();
    void finish();
    bool isRunning() const;

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    void reveal();

    Backdrop* m_host;
    QPointer<QWidget> m_header;
    QList<QPointer<QWidget>> m_body;
    QPointer<QWidget> m_cover;
    QVariantAnimation* m_anim = nullptr;
    QElapsedTimer m_lastResize;
};
