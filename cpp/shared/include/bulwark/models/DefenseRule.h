#pragma once
#include <QString>
#include <QDateTime>
#include <QUuid>
#include <QSet>
#include <QJsonObject>
#include <optional>
#include "bulwark/models/Enums.h"
#include "bulwark/Clock.h"

namespace bulwark {

struct SecurityEvent;

struct DefenseRule {
    static QString trustNoteTag();

    QUuid id = QUuid::createUuid();
    QString actorPath;
    QString actorPattern;
    std::optional<EventType> type;
    QString targetPattern;
    QString commandLinePattern;
    QString parentPattern;
    bool requireUnsigned = false;
    bool requireSigned = false;
    bool requireTargetUnsigned = false;
    bool requireTargetSigned = false;
    bool requireHostSigned = false;
    // 仅当被加载的模块与宿主程序在同一目录时命中(DLL 搜索顺序侧载的形态)。
    // 安装器按完整路径加载自己解到临时子目录里的插件,与宿主不同目录,不命中。
    bool requireTargetBesideActor = false;
    // 目标在外接 / 可移动存储上时不命中:制作启动盘、格式化 U 盘的工具要直接写这类磁盘。
    bool exemptRemovableTarget = false;
    // 仅当事件的注册表操作方向匹配时才命中。默认 nullopt = 不过滤(含 Unknown)。
    // 用于区分「删值/删键(常是加固)」与「设值(可能是削弱防护)」。
    std::optional<RegistryOperation> requireRegOp;
    // 仅当事件带 REG_DWORD 值且等于该值时命中。默认 nullopt = 不过滤。
    // 用于区分「设 0 加固」与「设 1 削弱」。值不可得时不过滤(避免漏检)。
    std::optional<quint32> requireRegDword;
    bool exemptTrustedOsComponent = false;
    bool hardOverride = false;
    // Ask 规则默认可被开发工具快捷通道降为 Allow；置位时必须保留 Ask，不能靠备注文本识别。
    bool disableDevToolAutoAllow = false;
    bool disableSignedAutoAllow = false;
    QSet<QString> actorHashes;
    VerdictAction action = VerdictAction::Allow;
    QString note;
    QDateTime createdUtc = nowUtc();
    std::optional<QDateTime> expiresUtc;
    bool sessionOnly = false;
    bool enabled = true;

    bool isExpired(const QDateTime& nowUtc) const {
        return expiresUtc.has_value() && *expiresUtc <= nowUtc;
    }
    bool isTrustEntry() const {
        return !note.isEmpty() && note.startsWith(trustNoteTag());
    }

    bool matches(const SecurityEvent& e) const;
    int specificityScore() const;

    // commandLinePattern 的匹配:原文,外加仅对 Block / Ask 规则的还原文本与解码正文。
    // 放行规则永远只看原文,见实现里的注释。
    bool matchesCommandLine(const SecurityEvent& e) const;

    bool identifiesSubject() const;

    static DefenseRule createTrust(const QString& actorPath, const QString& note = QString());
    static DefenseRule createTrustDirectory(const QString& dirPath, const QString& note = QString());

    static bool wildcardMatch(const QString& pattern, const QString& input);

    QJsonObject toJson() const;
    static DefenseRule fromJson(const QJsonObject& o);
};

}
