#pragma once
#include <QIcon>
#include <QPixmap>
#include <QString>

namespace fileicon {

QPixmap pixmapForPath(const QString& path, int logicalSize, qreal dpr = 1.0);

QIcon iconForPath(const QString& path, int logicalSize, qreal dpr = 1.0);

}
