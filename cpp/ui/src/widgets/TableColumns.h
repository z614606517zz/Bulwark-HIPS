#pragma once
#include <QList>
#include <QString>

class QTableWidget;

namespace ui {

struct ColSpec {
    int  width;
    int  grow     = 0;
    bool pathLike = false;
};

void columns(QTableWidget* table, const QString& key, const QList<ColSpec>& spec);

}
