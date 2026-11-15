#pragma once
#include <QColor>
#include <QString>
#include <QWidget>

#include <functional>

class QLabel;
class QPushButton;
class RobotWidget;

class EmptyState : public QWidget
{
public:
    explicit EmptyState(QWidget* parent = nullptr);

    void setContent(const QString& icon, const QColor& color, const QString& title,
                    const QString& body);
    void setAction(const QString& text, std::function<void()> fn, const char* variant = "ghost");

private:
    RobotWidget* m_bot = nullptr;
    QLabel* m_title = nullptr;
    QLabel* m_body = nullptr;
    QPushButton* m_action = nullptr;
    std::function<void()> m_fn;
};
