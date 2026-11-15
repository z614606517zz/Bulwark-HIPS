#pragma once
#include <QMap>
#include <QString>
#include <QStringList>

namespace bulwark::service::hijack {

struct Verdict {
    bool suspicious = false;
    QString why;
};

using EntryData = QMap<QString, QString>;

bool isLoopbackHost(const QString& host);
bool isPrivateAddress(const QString& ip);
bool isWellKnownResolver(const QString& ip);
QStringList proxyHosts(const QString& proxyServer);
QStringList splitAddressList(const QString& list);
bool isBrowserExe(const QString& pathOrName);

Verdict proxyVerdict(const EntryData& oldE, const EntryData& newE);
Verdict policyVerdict(const EntryData& oldE, const EntryData& newE);
Verdict dnsVerdict(const QString& oldNameServer, const QString& newNameServer);
Verdict shortcutVerdict(const QString& oldTarget, const QString& oldArgs,
                        const QString& newTarget, const QString& newArgs);

QString describeProxy(const EntryData& e, bool annotate = false);
QString describePolicy(const EntryData& e);
QString describeDns(const QString& nameServer);
QString describeShortcut(const QString& target, const QString& args);

}
