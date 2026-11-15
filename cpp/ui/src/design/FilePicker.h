#pragma once
#include <QString>

class QWidget;

namespace ui {

QString pickExistingFile(QWidget* parent, const QString& title, const QString& filter);
QString pickExistingFolder(QWidget* parent, const QString& title);

}
