#include "bulwark/service/HijackPolicy.h"

#include <QRegularExpression>
#include <QSet>

namespace bulwark::service::hijack {

namespace {

QString shorten(const QString& s, int n = 120) {
    const QString t = s.trimmed();
    return t.size() <= n ? t : t.left(n - 1) + QStringLiteral("…");
}

QString baseNameLower(const QString& p) {
    QString s = p.trimmed();
    s.remove(QLatin1Char('"'));
    const int i = qMax(s.lastIndexOf(QLatin1Char('\\')), s.lastIndexOf(QLatin1Char('/')));
    return (i >= 0 ? s.mid(i + 1) : s).toLower();
}

QString dirLower(const QString& p) {
    QString s = p.trimmed();
    s.remove(QLatin1Char('"'));
    const int i = qMax(s.lastIndexOf(QLatin1Char('\\')), s.lastIndexOf(QLatin1Char('/')));
    return (i >= 0 ? s.left(i) : QString()).toLower();
}

bool parseIPv4(const QString& s, int o[4]) {
    const QStringList p = s.trimmed().split(QLatin1Char('.'));
    if (p.size() != 4)
        return false;
    for (int i = 0; i < 4; ++i) {
        bool ok = false;
        const int v = p[i].toInt(&ok);
        if (!ok || v < 0 || v > 255 || p[i].isEmpty() || p[i].size() > 3)
            return false;
        o[i] = v;
    }
    return true;
}

QString cleanHost(QString h) {
    h = h.trimmed().toLower();
    if (h.startsWith(QLatin1Char('[')) && h.endsWith(QLatin1Char(']')))
        h = h.mid(1, h.size() - 2);
    return h;
}

const QStringList& riskFlags() {
    static const QStringList f = {
        QStringLiteral("--load-extension"),       QStringLiteral("--proxy-server"),
        QStringLiteral("--proxy-pac-url"),        QStringLiteral("--host-resolver-rules"),
        QStringLiteral("--remote-debugging-port"), QStringLiteral("--remote-debugging-pipe"),
        QStringLiteral("--disable-web-security"), QStringLiteral("--no-sandbox"),
        QStringLiteral("--ignore-certificate-errors"),
    };
    return f;
}

QStringList argFlags(const QString& args) {
    QStringList out;
    for (const QString& tok : args.toLower().split(QRegularExpression(QStringLiteral("\\s+")),
                                                   Qt::SkipEmptyParts)) {
        if (!tok.startsWith(QStringLiteral("--")))
            continue;
        const int eq = tok.indexOf(QLatin1Char('='));
        out << (eq > 0 ? tok.left(eq) : tok);
    }
    return out;
}

QStringList extractUrls(const QString& args) {
    static const QRegularExpression re(
        QStringLiteral("(?:https?|ftp|file)://[^\\s\"']+|(?<![\\w.\\-])www\\.[^\\s\"']+"),
        QRegularExpression::CaseInsensitiveOption);
    QStringList out;
    auto it = re.globalMatch(args);
    while (it.hasNext())
        out << it.next().captured(0).toLower();
    return out;
}

bool userWritableDir(const QString& dirLow) {
    static const char* kNeedles[] = {
        "\\appdata\\", "\\temp\\", "\\users\\public", "\\downloads", "\\programdata\\",
    };
    const QString d = dirLow + QLatin1Char('\\');
    for (const char* n : kNeedles)
        if (d.contains(QLatin1String(n)))
            return true;
    return false;
}

bool pacIsLocal(const QString& url) {
    static const QRegularExpression re(QStringLiteral("^https?://(\\[[^\\]]+\\]|[^/:]+)"),
                                       QRegularExpression::CaseInsensitiveOption);
    const auto m = re.match(url.trimmed());
    return m.hasMatch() && isLoopbackHost(m.captured(1));
}

}

bool isLoopbackHost(const QString& host) {
    const QString h = cleanHost(host);
    if (h.isEmpty())
        return false;
    if (h == QLatin1String("localhost") || h == QLatin1String("ip6-localhost")
        || h == QLatin1String("::1") || h == QLatin1String("0.0.0.0")
        || h == QLatin1String("::"))
        return true;
    int o[4];
    return parseIPv4(h, o) && o[0] == 127;
}

bool isPrivateAddress(const QString& ip) {
    const QString a = cleanHost(ip);
    int o[4];
    if (parseIPv4(a, o)) {
        if (o[0] == 10 || o[0] == 127)
            return true;
        if (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
            return true;
        if (o[0] == 192 && o[1] == 168)
            return true;
        if (o[0] == 169 && o[1] == 254)
            return true;
        return false;
    }
    return a == QLatin1String("::1") || a.startsWith(QLatin1String("fe80"))
           || a.startsWith(QLatin1String("fc")) || a.startsWith(QLatin1String("fd"));
}

bool isWellKnownResolver(const QString& ip) {
    static const QSet<QString> k = {
        QStringLiteral("1.1.1.1"), QStringLiteral("1.0.0.1"), QStringLiteral("1.1.1.2"),
        QStringLiteral("1.0.0.2"), QStringLiteral("1.1.1.3"), QStringLiteral("1.0.0.3"),
        QStringLiteral("2606:4700:4700::1111"), QStringLiteral("2606:4700:4700::1001"),
        QStringLiteral("8.8.8.8"), QStringLiteral("8.8.4.4"),
        QStringLiteral("2001:4860:4860::8888"), QStringLiteral("2001:4860:4860::8844"),
        QStringLiteral("9.9.9.9"), QStringLiteral("149.112.112.112"), QStringLiteral("9.9.9.10"),
        QStringLiteral("9.9.9.11"), QStringLiteral("2620:fe::fe"), QStringLiteral("2620:fe::9"),
        QStringLiteral("208.67.222.222"), QStringLiteral("208.67.220.220"),
        QStringLiteral("208.67.222.123"), QStringLiteral("208.67.220.123"),
        QStringLiteral("223.5.5.5"), QStringLiteral("223.6.6.6"),
        QStringLiteral("119.29.29.29"), QStringLiteral("182.254.116.116"),
        QStringLiteral("114.114.114.114"), QStringLiteral("114.114.115.115"),
        QStringLiteral("114.114.114.119"), QStringLiteral("114.114.115.119"),
        QStringLiteral("180.76.76.76"), QStringLiteral("1.2.4.8"), QStringLiteral("210.2.4.8"),
        QStringLiteral("4.2.2.1"), QStringLiteral("4.2.2.2"), QStringLiteral("4.2.2.3"),
        QStringLiteral("4.2.2.4"), QStringLiteral("94.140.14.14"), QStringLiteral("94.140.15.15"),
    };
    return k.contains(cleanHost(ip));
}

QStringList proxyHosts(const QString& proxyServer) {
    QStringList hosts;
    const QStringList toks =
        proxyServer.split(QRegularExpression(QStringLiteral("[;\\s]+")), Qt::SkipEmptyParts);
    for (QString t : toks) {
        const int eq = t.indexOf(QLatin1Char('='));
        if (eq > 0 && !t.left(eq).contains(QLatin1Char(':')))
            t = t.mid(eq + 1);
        const int scheme = t.indexOf(QStringLiteral("://"));
        if (scheme >= 0)
            t = t.mid(scheme + 3);
        const int slash = t.indexOf(QLatin1Char('/'));
        if (slash >= 0)
            t = t.left(slash);
        QString host;
        if (t.startsWith(QLatin1Char('['))) {
            const int close = t.indexOf(QLatin1Char(']'));
            host = close > 0 ? t.mid(1, close - 1) : t;
        } else if (t.count(QLatin1Char(':')) == 1) {
            host = t.left(t.indexOf(QLatin1Char(':')));
        } else {
            host = t;
        }
        host = host.trimmed();
        if (!host.isEmpty())
            hosts << host;
    }
    return hosts;
}

QStringList splitAddressList(const QString& list) {
    QStringList out;
    for (const QString& s : list.split(QRegularExpression(QStringLiteral("[,;\\s]+")),
                                       Qt::SkipEmptyParts))
        out << cleanHost(s);
    return out;
}

bool isBrowserExe(const QString& pathOrName) {
    static const QSet<QString> k = {
        QStringLiteral("chrome.exe"),       QStringLiteral("msedge.exe"),
        QStringLiteral("firefox.exe"),      QStringLiteral("brave.exe"),
        QStringLiteral("opera.exe"),        QStringLiteral("vivaldi.exe"),
        QStringLiteral("iexplore.exe"),     QStringLiteral("chromium.exe"),
        QStringLiteral("360chrome.exe"),    QStringLiteral("360chromex.exe"),
        QStringLiteral("360se.exe"),        QStringLiteral("qqbrowser.exe"),
        QStringLiteral("sogouexplorer.exe"), QStringLiteral("2345explorer.exe"),
        QStringLiteral("liebao.exe"),       QStringLiteral("maxthon.exe"),
        QStringLiteral("ucbrowser.exe"),    QStringLiteral("baidubrowser.exe"),
        QStringLiteral("theworld.exe"),     QStringLiteral("yandex.exe"),
    };
    return k.contains(baseNameLower(pathOrName));
}

Verdict proxyVerdict(const EntryData& oldE, const EntryData& newE) {
    const bool oldEnable = oldE.value(QStringLiteral("ProxyEnable")).trimmed() == QLatin1String("1");
    const bool newEnable = newE.value(QStringLiteral("ProxyEnable")).trimmed() == QLatin1String("1");
    const QString oldServer = oldE.value(QStringLiteral("ProxyServer")).trimmed();
    const QString newServer = newE.value(QStringLiteral("ProxyServer")).trimmed();
    const QString oldPac = oldE.value(QStringLiteral("AutoConfigURL")).trimmed();
    const QString newPac = newE.value(QStringLiteral("AutoConfigURL")).trimmed();

    Verdict v;
    if (!newPac.isEmpty() && newPac != oldPac && !pacIsLocal(newPac)) {
        v.suspicious = true;
        v.why = QStringLiteral(
            "系统的「自动配置脚本(PAC)」被设成了 %1。PAC 可以把指定网站的流量悄悄转给别人的代理,"
            "浏览器和大多数程序都会照办。你自己的代理 / VPN 工具通常指向本机(127.0.0.1),不会触发这一条。")
                    .arg(shorten(newPac));
        return v;
    }
    if (newEnable && !newServer.isEmpty() && (!oldEnable || newServer != oldServer)) {
        QStringList remote;
        for (const QString& h : proxyHosts(newServer))
            if (!isLoopbackHost(h))
                remote << h;
        if (!remote.isEmpty()) {
            v.suspicious = true;
            v.why = QStringLiteral(
                "系统代理被启用并指向非本机地址 %1。此后浏览器和大多数程序的网络流量都会先经过它,"
                "对方可以窥探或篡改。你自己的代理 / VPN 工具通常指向本机(127.0.0.1),不会触发这一条。")
                        .arg(remote.join(QStringLiteral("、")));
        }
    }
    return v;
}

Verdict policyVerdict(const EntryData& oldE, const EntryData& newE) {
    QStringList changed;
    for (auto it = newE.constBegin(); it != newE.constEnd(); ++it) {
        const auto o = oldE.constFind(it.key());
        if (o == oldE.constEnd() || o.value() != it.value())
            changed << it.key();
    }
    Verdict v;
    if (changed.isEmpty())
        return v;
    EntryData shown;
    for (const QString& k : changed)
        shown.insert(k, newE.value(k));
    v.suspicious = true;
    v.why = QStringLiteral(
        "浏览器的企业策略键下新增或改动了 %1 个值:%2。个人电脑上通常根本没有这类策略;"
        "它常被用来锁定主页、改写默认搜索引擎或强制安装扩展(浏览器会提示「由你的组织管理」)。"
        "如果是公司 / 学校统一下发的,可以接受。")
                .arg(changed.size())
                .arg(describePolicy(shown));
    return v;
}

Verdict dnsVerdict(const QString& oldNameServer, const QString& newNameServer) {
    const QStringList oldList = splitAddressList(oldNameServer);
    QStringList bad;
    for (const QString& ip : splitAddressList(newNameServer)) {
        if (oldList.contains(ip))
            continue;
        if (isPrivateAddress(ip) || isWellKnownResolver(ip))
            continue;
        bad << ip;
    }
    Verdict v;
    if (!bad.isEmpty()) {
        v.suspicious = true;
        v.why = QStringLiteral(
            "新增的 DNS 服务器 %1 既不是常见的公共 DNS,也不在内网地址段。DNS 被改掉后,你访问的网站"
            "可以被悄悄指向假站点(钓鱼 / 广告劫持)。如果这是你或运营商要求你手动设置的,可以接受。")
                    .arg(bad.join(QStringLiteral("、")));
    }
    return v;
}

Verdict shortcutVerdict(const QString& oldTarget, const QString& oldArgs, const QString& newTarget,
                        const QString& newArgs) {
    Verdict v;
    const QStringList oldUrls = extractUrls(oldArgs);
    QStringList addedUrls;
    for (const QString& u : extractUrls(newArgs))
        if (!oldUrls.contains(u))
            addedUrls << u;
    if (!addedUrls.isEmpty()) {
        v.suspicious = true;
        v.why = QStringLiteral(
            "浏览器快捷方式的启动参数里多了网址 %1。每次从这个快捷方式打开浏览器,都会被带到那个页面"
            "(锁定主页 / 导航站的常见手法)。")
                    .arg(shorten(addedUrls.join(QStringLiteral("、")), 160));
        return v;
    }
    const QStringList oldFlags = argFlags(oldArgs);
    QStringList addedRisk;
    for (const QString& f : argFlags(newArgs))
        if (riskFlags().contains(f) && !oldFlags.contains(f) && !addedRisk.contains(f))
            addedRisk << f;
    if (!addedRisk.isEmpty()) {
        v.suspicious = true;
        v.why = QStringLiteral(
            "浏览器快捷方式的启动参数里多了 %1。这类开关可以让浏览器走别人的代理、加载未经你同意的扩展、"
            "打开可被外部程序读取 cookie 的调试端口,或关闭浏览器自身的进程隔离保护。")
                    .arg(addedRisk.join(QStringLiteral("、")));
        return v;
    }
    const QString ob = baseNameLower(oldTarget);
    const QString nb = baseNameLower(newTarget);
    if (!newTarget.trimmed().isEmpty() && ob != nb && !isBrowserExe(nb)) {
        v.suspicious = true;
        v.why = QStringLiteral("快捷方式的目标由 %1 换成了 %2,后者不是浏览器。点这个图标会运行另一个程序。")
                    .arg(ob.isEmpty() ? QStringLiteral("(原目标)") : ob, nb);
        return v;
    }
    const QString od = dirLower(oldTarget);
    const QString nd = dirLower(newTarget);
    if (!newTarget.trimmed().isEmpty() && od != nd && !userWritableDir(od) && userWritableDir(nd)) {
        v.suspicious = true;
        v.why = QStringLiteral("快捷方式的目标由 %1 挪到了用户可写目录 %2。正规浏览器的安装目录不会这样变,"
                               "更像是有人放了一个同名的程序来冒充。")
                    .arg(od.isEmpty() ? QStringLiteral("(原目录)") : od, nd);
    }
    return v;
}

QString describeProxy(const EntryData& e, bool annotate) {
    const bool en = e.value(QStringLiteral("ProxyEnable")).trimmed() == QLatin1String("1");
    const QString srv = e.value(QStringLiteral("ProxyServer")).trimmed();
    const QString pac = e.value(QStringLiteral("AutoConfigURL")).trimmed();
    QStringList parts;
    if (!srv.isEmpty()) {
        QString p = QStringLiteral("代理 %1").arg(shorten(srv, 80));
        if (!en)
            p += QStringLiteral("(未启用)");
        else if (annotate) {
            bool allLocal = true;
            for (const QString& h : proxyHosts(srv))
                allLocal = allLocal && isLoopbackHost(h);
            p += allLocal ? QStringLiteral("(本机代理,正常)") : QStringLiteral("(非本机)");
        }
        parts << p;
    }
    if (!pac.isEmpty()) {
        QString p = QStringLiteral("PAC %1").arg(shorten(pac, 80));
        if (annotate)
            p += pacIsLocal(pac) ? QStringLiteral("(本机)") : QStringLiteral("(非本机)");
        parts << p;
    }
    return parts.isEmpty() ? QStringLiteral("未设置代理") : parts.join(QStringLiteral(";"));
}

QString describePolicy(const EntryData& e) {
    if (e.isEmpty())
        return QStringLiteral("无");
    QStringList rows;
    int n = 0;
    for (auto it = e.constBegin(); it != e.constEnd(); ++it) {
        if (++n > 6)
            break;
        QString key = it.key();
        const int bar = key.indexOf(QLatin1Char('|'));
        if (bar >= 0)
            key = key.left(bar).isEmpty() ? key.mid(bar + 1)
                                          : key.left(bar) + QLatin1Char('\\') + key.mid(bar + 1);
        rows << QStringLiteral("%1 = %2").arg(key, shorten(it.value(), 60));
    }
    QString out = rows.join(QStringLiteral(";"));
    if (e.size() > 6)
        out += QStringLiteral(" 等共 %1 项").arg(e.size());
    return out;
}

QString describeDns(const QString& nameServer) {
    const QString s = nameServer.trimmed();
    return s.isEmpty() ? QStringLiteral("未设置(跟随 DHCP)") : s;
}

QString describeShortcut(const QString& target, const QString& args) {
    QString s = shorten(target, 140);
    if (!args.trimmed().isEmpty())
        s += QStringLiteral("  参数:") + shorten(args, 140);
    return s;
}

}
