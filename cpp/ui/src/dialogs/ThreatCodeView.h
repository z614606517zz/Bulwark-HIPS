#pragma once
#include "bulwark/models/SecurityEvent.h"

#include <QColor>
#include <QString>
#include <QVector>

class QWidget;

namespace threatcode {

struct Options {
    int maxSnippets = 3;
    int maxRows = 6;
    bool commandLineFallback = true;
    QString moreHint;
};

QVector<bulwark::ThreatSnippet> snippetsFor(const bulwark::SecurityEvent& e, bool commandLineFallback);

QWidget* build(const bulwark::SecurityEvent& e, const QColor& accent, const Options& opt = {});

}
