#pragma once
#include <QString>
#include <QStringList>
#include <QVector>
#include "bulwark/models/ThreatSnippet.h"

namespace bulwark::engine {

enum class ScriptType {
    Unknown = 0,
    PowerShell,
    Vbscript,
    Javascript,
    Batch,
    Hta,
};

struct ScriptAnalyzer {
    struct Result {
        int score = 0;
        bool hardSignal = false;
        QStringList hits;
        QStringList reasons;
        QVector<ThreatSnippet> snippets;
        bool empty() const { return score == 0 && hits.isEmpty(); }
    };

    static constexpr qint64 kScanPrefixBytes = 256 * 1024;

    static ScriptType scriptTypeFromPath(const QString& path);
    static ScriptType scriptTypeForHost(const QString& hostImageName);

    // 从脚本宿主的命令行里找出被执行的脚本文件;找不到返回空串。
    static QString extractScriptFilePath(const QString& commandLine);

    static Result analyze(const QString& content, ScriptType type, const QString& snippetTitle);

    static ThreatSnippet snippetForContent(const QString& content, const QString& title);
};

}
