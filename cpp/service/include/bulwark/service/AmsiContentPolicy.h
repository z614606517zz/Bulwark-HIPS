#pragma once

#include <QByteArray>
#include <QString>

#include "bulwark/engine/ScriptAnalyzer.h"

namespace bulwark::service::amsi_content {

inline QString decodeContent(const QByteArray& raw, bool hintUtf16) {
    if (raw.isEmpty())
        return QString();

    if (raw.size() >= 2) {
        const auto b0 = static_cast<unsigned char>(raw[0]);
        const auto b1 = static_cast<unsigned char>(raw[1]);
        if (b0 == 0xFF && b1 == 0xFE)
            return QString::fromUtf16(reinterpret_cast<const char16_t*>(raw.constData() + 2),
                                      (raw.size() - 2) / 2);
        if (raw.size() >= 3 && b0 == 0xEF && b1 == 0xBB
            && static_cast<unsigned char>(raw[2]) == 0xBF)
            return QString::fromUtf8(raw.constData() + 3, raw.size() - 3);
    }

    const qsizetype sample = qMin<qsizetype>(raw.size() & ~qsizetype(1), 512);
    qsizetype odd = 0, zeroOdd = 0;
    for (qsizetype i = 1; i < sample; i += 2) {
        ++odd;
        if (raw[i] == '\0')
            ++zeroOdd;
    }
    const bool looksUtf16 = (odd > 0 && zeroOdd * 4 >= odd * 3);
    if (looksUtf16 || (odd == 0 && hintUtf16))
        return QString::fromUtf16(reinterpret_cast<const char16_t*>(raw.constData()),
                                  raw.size() / 2);
    return QString::fromUtf8(raw);
}

inline bulwark::engine::ScriptType scriptTypeFor(const QString& appName,
                                                 const QString& contentName) {
    using bulwark::engine::ScriptType;
    const QString a = appName.toLower();
    if (a.contains(QLatin1String("powershell")) || a.contains(QLatin1String("pwsh"))
        || a.contains(QLatin1String("coreshell")))
        return ScriptType::PowerShell;
    if (a.contains(QLatin1String("vbscript")))
        return ScriptType::Vbscript;
    if (a.contains(QLatin1String("jscript")) || a.contains(QLatin1String("javascript")))
        return ScriptType::Javascript;
    if (!contentName.isEmpty()) {
        const ScriptType t = bulwark::engine::ScriptAnalyzer::scriptTypeFromPath(contentName);
        if (t != ScriptType::Unknown)
            return t;
    }
    return ScriptType::Unknown;
}

}
