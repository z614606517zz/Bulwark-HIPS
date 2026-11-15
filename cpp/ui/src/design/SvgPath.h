#pragma once
#include <QPainterPath>
#include <QPolygonF>
#include <QString>

// SVG 路径数据(d 属性)的最小解析器:M L H V C S Q T A Z 及其相对写法。
// 机器人与贴纸图标直接沿用设计稿里的路径串,保证与设计稿一致。
namespace svg {

QPainterPath path(QStringView d);
inline QPainterPath path(const char* d) { return path(QString::fromLatin1(d)); }

QPolygonF points(QStringView pts);
inline QPolygonF points(const char* pts) { return points(QString::fromLatin1(pts)); }

}
