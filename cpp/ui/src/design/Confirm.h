#pragma once
#include <QString>
#include <QStringList>

#include <optional>

class QWidget;

namespace ui {

enum class Risk { Info, Caution, Danger };

struct ConfirmSpec {
    Risk risk = Risk::Caution;
    QString title;
    QString summary;
    QStringList consequences;
    QString subjectLabel;
    QString subject;
    QString confirmText;
    QString cancelText;
    std::optional<bool> requireAck;
    QString ackText;
    // 从置顶的通知卡片发起、又没有可挂靠的父窗口时用:确认框也置顶,不会被那些卡片或别的窗口盖住。
    bool stayOnTop = false;
};

bool confirm(QWidget* parent, const ConfirmSpec& spec);

enum class NoticeTone { Info, Warning, Danger };
void notice(QWidget* parent, NoticeTone tone, const QString& title, const QString& body,
            const QString& detail = QString());

}
