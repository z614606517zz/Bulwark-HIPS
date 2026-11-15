#pragma once
#include <QString>
#include <QStringList>

#include <functional>

class QWidget;

namespace ui {

void acceptFileDrops(QWidget* target, const QString& hint,
                     std::function<void(const QStringList& paths)> onDrop,
                     std::function<bool(const QString& path)> accept = {});

}
