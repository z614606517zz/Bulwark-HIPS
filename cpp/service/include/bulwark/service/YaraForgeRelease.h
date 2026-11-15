#pragma once

#include "bulwark/ipc/Payloads.h"

#include <QByteArray>
#include <QDateTime>
#include <QList>
#include <QString>
#include <QStringList>

#include <optional>

namespace bulwark::service::yara {

struct ReleaseAsset {
    QString tag;
    QDateTime publishedUtc;
    QString name;
    QString url;
    qint64 size = 0;
    QString sha256;   // 小写十六进制;发布页没给摘要时为空
};

// 解析 GitHub「最新发布」接口的回复,挑出 yara-forge-rules-<package>.zip。
// 下载地址必须以 allowedPrefix 开头:接口回复不能把下载引到别的地方。
std::optional<ReleaseAsset> parseLatestRelease(const QByteArray& json, const QString& package,
                                               const QString& allowedPrefix, QString* error);

struct CompileReport {
    bool ok = false;
    QString error;
    QString engine;
    QString sourceName;
    qint64 sourceBytes = 0;
    QString packageName;
    QString packageCreated;
    int packageDeclaredRules = 0;
    int rulesFound = 0;
    int rulesCompiled = 0;
    int rulesSkipped = 0;
    qint64 compileMs = 0;
    qint64 outputBytes = 0;
    QList<bulwark::ipc::YaraRuleSourcePayload> sources;
    QList<bulwark::ipc::YaraSkippedRulePayload> skipped;
    QStringList hardening;
};

// bulwark_yarac 写出的报告;结构不对返回 nullopt。
std::optional<CompileReport> parseCompileReport(const QByteArray& json);

// 新编出的规则条数是否可信:至少 50 条,且不少于上一版的一半。上游发错包时宁可沿用旧规则。
bool plausibleRuleCount(int compiled, int previous);

}
