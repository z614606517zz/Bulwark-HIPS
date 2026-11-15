#include "bulwark/service/HijackGuard.h"

#include "bulwark/service/AtomicFile.h"
#include "bulwark/service/RegistryUtil.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>

#include <algorithm>
#include <utility>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <objbase.h>
#include <shlobj.h>

namespace bulwark::service {

namespace {

using regutil::Hive;

constexpr int kTickMs = 4000;
constexpr int kShortcutEveryTicks = 4;
constexpr int kLnkParseBudget = 80;
constexpr int kMaxLnkFiles = 1500;
constexpr int kMaxAlerts = 40;
constexpr int kPolicyMaxEntries = 300;
constexpr int kPolicyMaxDepth = 3;

QString surfaceId(const QString& key) {
    return QString::fromLatin1(
        QCryptographicHash::hash(key.toUtf8(), QCryptographicHash::Sha1).toHex().left(12));
}

QString entryKeyOf(const QString& sub, const QString& name) {
    return sub.isEmpty() ? name : sub + QLatin1Char('|') + name;
}

QString joinSub(const QString& a, const QString& b) {
    if (a.isEmpty()) return b;
    if (b.isEmpty()) return a;
    return a + QLatin1Char('\\') + b;
}

QString clip(const QString& s, int n = 100) {
    const QString t = s.trimmed();
    return t.size() <= n ? t : t.left(n - 1) + QStringLiteral("…");
}

QString expandEnv(const QString& p) {
    if (p.isEmpty()) return p;
    wchar_t buf[2048] = {};
    const DWORD n = ::ExpandEnvironmentStringsW(reinterpret_cast<LPCWSTR>(p.utf16()), buf, 2048);
    return (n == 0 || n > 2048) ? p : QString::fromWCharArray(buf);
}

bool readLnk(const QString& path, QString* target, QString* args) {
    IShellLinkW* link = nullptr;
    if (FAILED(::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW,
                                  reinterpret_cast<void**>(&link))))
        return false;
    bool ok = false;
    IPersistFile* pf = nullptr;
    if (SUCCEEDED(link->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&pf)))) {
        if (SUCCEEDED(pf->Load(reinterpret_cast<LPCOLESTR>(path.utf16()), STGM_READ))) {
            wchar_t tgt[MAX_PATH] = {};
            wchar_t arg[4096] = {};
            if (SUCCEEDED(link->GetPath(tgt, MAX_PATH, nullptr, SLGP_UNCPRIORITY)))
                *target = expandEnv(QString::fromWCharArray(tgt));
            if (SUCCEEDED(link->GetArguments(arg, 4096)))
                *args = QString::fromWCharArray(arg);
            ok = true;
        }
        pf->Release();
    }
    link->Release();
    return ok;
}

bool writeLnk(const QString& path, const QString& target, const QString& args, QString* err) {
    IShellLinkW* link = nullptr;
    HRESULT hr = ::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW,
                                    reinterpret_cast<void**>(&link));
    if (FAILED(hr)) {
        *err = QStringLiteral("无法创建 ShellLink 对象(0x%1)").arg(static_cast<quint32>(hr), 8, 16);
        return false;
    }
    bool ok = false;
    IPersistFile* pf = nullptr;
    if (SUCCEEDED(link->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&pf)))) {
        hr = pf->Load(reinterpret_cast<LPCOLESTR>(path.utf16()), STGM_READWRITE);
        if (SUCCEEDED(hr)) {
            hr = link->SetPath(reinterpret_cast<LPCWSTR>(target.utf16()));
            if (SUCCEEDED(hr))
                hr = link->SetArguments(reinterpret_cast<LPCWSTR>(args.utf16()));
            if (SUCCEEDED(hr))
                hr = pf->Save(reinterpret_cast<LPCOLESTR>(path.utf16()), TRUE);
            ok = SUCCEEDED(hr);
        }
        if (!ok)
            *err = QStringLiteral("写回快捷方式失败(0x%1)").arg(static_cast<quint32>(hr), 8, 16);
        pf->Release();
    } else {
        *err = QStringLiteral("ShellLink 不支持 IPersistFile");
    }
    link->Release();
    return ok;
}

void walkLnk(const QString& dir, int depth, QStringList* out) {
    if (out->size() >= kMaxLnkFiles) return;
    const QDir d(dir);
    for (const QFileInfo& fi : d.entryInfoList(QStringList{QStringLiteral("*.lnk")}, QDir::Files)) {
        if (out->size() >= kMaxLnkFiles) return;
        *out << fi.absoluteFilePath();
    }
    if (depth <= 1) return;
    for (const QFileInfo& sub : d.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot))
        walkLnk(sub.absoluteFilePath(), depth - 1, out);
}

}

HijackGuard::HijackGuard(QObject* parent) : QObject(parent) {}

HijackGuard::~HijackGuard() { stop(); }

bool HijackGuard::start() {
    if (timer_)
        return true;
    if (statePath_.isEmpty())
        statePath_ = programDataDir() + QStringLiteral("/hijack-state.json");
    loadState();
    timer_ = new QTimer(this);
    timer_->setInterval(kTickMs);
    connect(timer_, &QTimer::timeout, this, &HijackGuard::onTick);
    timer_->start();
    QTimer::singleShot(0, this, [this] { scan(true); });
    log_.info(QStringLiteral("劫持防护已启动:监视系统代理 / PAC、浏览器企业策略、网卡 DNS、浏览器快捷方式"
                             "(基线 %1 项,待处理告警 %2 条;状态文件 %3)。")
                  .arg(baseline_.size())
                  .arg(pendingCount())
                  .arg(statePath_));
    return true;
}

void HijackGuard::stop() {
    if (!timer_)
        return;
    timer_->stop();
    timer_->deleteLater();
    timer_ = nullptr;
    if (dirty_)
        saveState();
}

bool HijackGuard::isRunning() const { return timer_ && timer_->isActive(); }

bool HijackGuard::isActive() const {
    return isRunning() && (!activeProbe_ || activeProbe_());
}

void HijackGuard::onTick() {
    ++tick_;
    scan((tick_ % kShortcutEveryTicks) == 0);
}

void HijackGuard::scanNow() { scan(true); }

QMap<QString, HijackGuard::Surface> HijackGuard::collectRegistrySurfaces() const {
    QMap<QString, Surface> out;

    for (const QString& sid : regutil::interactiveUserSids()) {
        Surface s;
        s.key = QStringLiteral("proxy|") + sid;
        s.kind = QStringLiteral("proxy");
        s.title = QStringLiteral("系统代理 / PAC");
        s.hive = QStringLiteral("HKU");
        s.rootSub = sid + QStringLiteral("\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
        s.location = QStringLiteral("HKU\\") + s.rootSub;
        for (const char* n : {"ProxyEnable", "ProxyServer", "AutoConfigURL"}) {
            const QString name = QString::fromLatin1(n);
            const regutil::Value v = regutil::readValue(Hive::Users, s.rootSub, name);
            if (!v.present)
                continue;
            Entry e;
            e.name = name;
            e.type = v.type;
            e.data = v.text;
            e.supported = v.supported;
            s.entries.insert(entryKeyOf(QString(), name), e);
        }
        out.insert(s.key, s);
    }

    struct PolicyRoot {
        QString key;
        QString sub;
        QString title;
    };
    const PolicyRoot roots[] = {
        {QStringLiteral("policy|chrome"), QStringLiteral("SOFTWARE\\Policies\\Google\\Chrome"),
         QStringLiteral("Chrome 企业策略")},
        {QStringLiteral("policy|edge"), QStringLiteral("SOFTWARE\\Policies\\Microsoft\\Edge"),
         QStringLiteral("Edge 企业策略")},
        {QStringLiteral("policy|brave"), QStringLiteral("SOFTWARE\\Policies\\BraveSoftware\\Brave-Browser"),
         QStringLiteral("Brave 企业策略")},
        {QStringLiteral("policy|firefox"), QStringLiteral("SOFTWARE\\Policies\\Mozilla\\Firefox"),
         QStringLiteral("Firefox 企业策略")},
    };
    for (const PolicyRoot& r : roots) {
        Surface s;
        s.key = r.key;
        s.kind = QStringLiteral("policy");
        s.title = r.title;
        s.hive = QStringLiteral("HKLM");
        s.rootSub = r.sub;
        s.location = QStringLiteral("HKLM\\") + r.sub;
        std::function<void(const QString&, int)> walk = [&](const QString& rel, int depth) {
            if (s.entries.size() >= kPolicyMaxEntries)
                return;
            const QString full = joinSub(s.rootSub, rel);
            for (const regutil::Named& nv : regutil::values(Hive::Machine, full)) {
                if (s.entries.size() >= kPolicyMaxEntries)
                    break;
                Entry e;
                e.sub = rel;
                e.name = nv.name;
                e.type = nv.value.type;
                e.data = nv.value.text;
                e.supported = nv.value.supported;
                s.entries.insert(entryKeyOf(rel, nv.name), e);
            }
            if (depth >= kPolicyMaxDepth)
                return;
            for (const QString& sk : regutil::subKeys(Hive::Machine, full))
                walk(joinSub(rel, sk), depth + 1);
        };
        walk(QString(), 0);
        out.insert(s.key, s);
    }

    struct DnsStack {
        QString tag;
        QString sub;
        QString label;
    };
    const DnsStack stacks[] = {
        {QStringLiteral("v4"), QStringLiteral("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"),
         QStringLiteral("IPv4")},
        {QStringLiteral("v6"), QStringLiteral("SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces"),
         QStringLiteral("IPv6")},
    };
    for (const DnsStack& st : stacks) {
        for (const QString& iface : regutil::subKeys(Hive::Machine, st.sub)) {
            Surface s;
            s.key = QStringLiteral("dns|") + st.tag + QLatin1Char('|') + iface.toLower();
            s.kind = QStringLiteral("dns");
            s.title = QStringLiteral("DNS 服务器(%1)").arg(st.label);
            s.hive = QStringLiteral("HKLM");
            s.rootSub = joinSub(st.sub, iface);
            s.location = QStringLiteral("HKLM\\") + s.rootSub;
            const regutil::Value v = regutil::readValue(Hive::Machine, s.rootSub, QStringLiteral("NameServer"));
            if (v.present && !v.text.trimmed().isEmpty()) {
                Entry e;
                e.name = QStringLiteral("NameServer");
                e.type = v.type;
                e.data = v.text;
                e.supported = v.supported;
                s.entries.insert(e.name, e);
            }
            out.insert(s.key, s);
        }
    }
    return out;
}

HijackGuard::Surface HijackGuard::readRegistrySurface(const Surface& like) const {
    const QMap<QString, Surface> all = collectRegistrySurfaces();
    const auto it = all.constFind(like.key);
    return it == all.constEnd() ? Surface{} : it.value();
}

HijackGuard::Surface HijackGuard::currentOf(const Surface& like) {
    if (like.kind != QLatin1String("shortcut"))
        return readRegistrySurface(like);
    Surface s = like;
    s.entries.clear();
    if (!QFileInfo::exists(like.location))
        return Surface{};
    const HRESULT hrInit = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    QString t, a;
    const bool ok = readLnk(like.location, &t, &a);
    if (hrInit == S_OK || hrInit == S_FALSE)
        ::CoUninitialize();
    if (!ok)
        return Surface{};
    Entry et;
    et.name = QStringLiteral("target");
    et.data = t;
    Entry ea;
    ea.name = QStringLiteral("args");
    ea.data = a;
    s.entries.insert(et.name, et);
    s.entries.insert(ea.name, ea);
    return s;
}

QStringList HijackGuard::shortcutRoots(QList<int>* depths) const {
    QStringList roots;
    const auto add = [&](const QString& p, int d) {
        if (p.isEmpty() || !QFileInfo(p).isDir())
            return;
        const QString n = QDir::toNativeSeparators(QDir::cleanPath(p));
        for (const QString& r : std::as_const(roots))
            if (r.compare(n, Qt::CaseInsensitive) == 0)
                return;
        roots << n;
        depths->append(d);
    };
    const QString plKey = QStringLiteral("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList");
    for (const QString& sid : regutil::subKeys(Hive::Machine, plKey)) {
        if (!(sid.startsWith(QStringLiteral("S-1-5-21-")) || sid.startsWith(QStringLiteral("S-1-12-1-"))))
            continue;
        const QString profile = expandEnv(
            regutil::readValue(Hive::Machine, plKey + QLatin1Char('\\') + sid,
                               QStringLiteral("ProfileImagePath")).text);
        if (profile.isEmpty())
            continue;
        QString desktop;
        const regutil::Value v = regutil::readValue(
            Hive::Users,
            sid + QStringLiteral("\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"),
            QStringLiteral("Desktop"));
        if (v.present && !v.text.isEmpty()) {
            desktop = v.text;
            desktop.replace(QStringLiteral("%USERPROFILE%"), profile, Qt::CaseInsensitive);
            desktop = expandEnv(desktop);
        }
        add(desktop, 1);
        add(profile + QStringLiteral("\\Desktop"), 1);
        add(profile + QStringLiteral("\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs"), 3);
        add(profile + QStringLiteral("\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch"), 3);
    }
    add(qEnvironmentVariable("PUBLIC", QStringLiteral("C:\\Users\\Public")) + QStringLiteral("\\Desktop"), 1);
    add(qEnvironmentVariable("ProgramData", QStringLiteral("C:\\ProgramData"))
            + QStringLiteral("\\Microsoft\\Windows\\Start Menu\\Programs"), 3);
    return roots;
}

void HijackGuard::collectShortcutSurfaces(QMap<QString, Surface>* out) {
    QList<int> depths;
    const QStringList roots = shortcutRoots(&depths);
    QStringList files;
    for (int i = 0; i < roots.size() && files.size() < kMaxLnkFiles; ++i)
        walkLnk(roots[i], depths[i], &files);

    const HRESULT hrInit = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    int budget = kLnkParseBudget;
    QSet<QString> seen;
    for (const QString& f : files) {
        const QString low = QDir::toNativeSeparators(f).toLower();
        seen.insert(low);
        const QFileInfo fi(f);
        const qint64 mt = fi.lastModified().toMSecsSinceEpoch();
        const qint64 sz = fi.size();
        auto cit = lnkCache_.find(low);
        const bool fresh = cit != lnkCache_.end() && cit->parsed && cit->mtimeMs == mt && cit->size == sz;
        if (!fresh) {
            if (budget <= 0) {
                // 本轮来不及:沿用基线里的旧状态(若有),下一轮接着解析 —— 绝不能把「还没解析」
                // 当成「被删了」或「变了」。
                const QString key = QStringLiteral("lnk|") + low;
                const auto b = baseline_.constFind(key);
                if (b != baseline_.constEnd())
                    out->insert(key, b.value());
                continue;
            }
            --budget;
            LnkInfo li;
            li.mtimeMs = mt;
            li.size = sz;
            li.parsed = true;   // 解析失败也标记为已解析:同一个文件没变就不要每轮重试
            QString t, a;
            if (readLnk(f, &t, &a)) {
                li.target = t;
                li.args = a;
                li.browser = hijack::isBrowserExe(t);
            }
            lnkCache_.insert(low, li);
            cit = lnkCache_.find(low);
        }
        if (!cit->browser)
            continue;
        Surface s;
        s.key = QStringLiteral("lnk|") + low;
        s.kind = QStringLiteral("shortcut");
        s.title = QStringLiteral("浏览器快捷方式");
        s.location = QDir::toNativeSeparators(f);
        Entry et;
        et.name = QStringLiteral("target");
        et.data = cit->target;
        Entry ea;
        ea.name = QStringLiteral("args");
        ea.data = cit->args;
        s.entries.insert(et.name, et);
        s.entries.insert(ea.name, ea);
        out->insert(s.key, s);
    }
    if (hrInit == S_OK || hrInit == S_FALSE)
        ::CoUninitialize();

    for (auto it = lnkCache_.begin(); it != lnkCache_.end();) {
        if (!seen.contains(it.key()))
            it = lnkCache_.erase(it);
        else
            ++it;
    }
}

bool HijackGuard::sameEntries(const Surface& a, const Surface& b) {
    if (a.entries.size() != b.entries.size())
        return false;
    for (auto it = a.entries.constBegin(); it != a.entries.constEnd(); ++it) {
        const auto o = b.entries.constFind(it.key());
        if (o == b.entries.constEnd() || o->type != it->type || o->data != it->data)
            return false;
    }
    return true;
}

hijack::EntryData HijackGuard::asData(const Surface& s) {
    hijack::EntryData d;
    for (auto it = s.entries.constBegin(); it != s.entries.constEnd(); ++it)
        d.insert(it.key(), it->data);
    return d;
}

hijack::Verdict HijackGuard::judge(const Surface& oldS, const Surface& newS) {
    if (newS.kind == QLatin1String("proxy"))
        return hijack::proxyVerdict(asData(oldS), asData(newS));
    if (newS.kind == QLatin1String("policy"))
        return hijack::policyVerdict(asData(oldS), asData(newS));
    if (newS.kind == QLatin1String("dns"))
        return hijack::dnsVerdict(oldS.entries.value(QStringLiteral("NameServer")).data,
                                  newS.entries.value(QStringLiteral("NameServer")).data);
    if (newS.kind == QLatin1String("shortcut"))
        return hijack::shortcutVerdict(oldS.entries.value(QStringLiteral("target")).data,
                                       oldS.entries.value(QStringLiteral("args")).data,
                                       newS.entries.value(QStringLiteral("target")).data,
                                       newS.entries.value(QStringLiteral("args")).data);
    return hijack::Verdict{};
}

ipc::HijackAlertPayload HijackGuard::buildAlert(const Surface& oldS, const Surface& newS,
                                                const hijack::Verdict& v, bool preexisting) const {
    ipc::HijackAlertPayload p;
    p.id = surfaceId(newS.key);
    p.surface = newS.kind;
    p.location = newS.location;
    p.state = QStringLiteral("pending");
    p.whenUtc = QDateTime::currentDateTimeUtc();
    p.preexisting = preexisting;
    p.detail = (preexisting ? QStringLiteral("(这是监视开始之前就已存在的状态,没有「改动前的值」可以还原。)") : QString())
               + v.why;

    // 能不能还原:基线里每一个要写回的值都必须是可原样写回的类型。
    bool restorable = !preexisting;
    for (auto it = oldS.entries.constBegin(); it != oldS.entries.constEnd(); ++it)
        if (!it->supported)
            restorable = false;
    p.restorable = restorable;

    if (newS.kind == QLatin1String("proxy")) {
        const hijack::EntryData o = asData(oldS), n = asData(newS);
        const QString pacNew = n.value(QStringLiteral("AutoConfigURL")).trimmed();
        const QString pacOld = o.value(QStringLiteral("AutoConfigURL")).trimmed();
        if (!pacNew.isEmpty() && pacNew != pacOld)
            p.title = QStringLiteral("自动配置脚本(PAC)被设为 %1").arg(clip(pacNew, 80));
        else
            p.title = QStringLiteral("系统代理被改为 %1").arg(clip(n.value(QStringLiteral("ProxyServer")), 80));
        p.oldValue = preexisting ? QStringLiteral("(无记录)") : hijack::describeProxy(o);
        p.newValue = hijack::describeProxy(n);
    } else if (newS.kind == QLatin1String("policy")) {
        hijack::EntryData changed;
        for (auto it = newS.entries.constBegin(); it != newS.entries.constEnd(); ++it) {
            const auto o = oldS.entries.constFind(it.key());
            if (o == oldS.entries.constEnd() || o->data != it->data)
                changed.insert(it.key(), it->data);
        }
        p.title = QStringLiteral("%1被写入或改动(%2 项)").arg(newS.title).arg(changed.size());
        p.oldValue = preexisting ? QStringLiteral("(无记录)") : QStringLiteral("基线:%1 项").arg(oldS.entries.size());
        p.newValue = hijack::describePolicy(changed);
    } else if (newS.kind == QLatin1String("dns")) {
        const QString nn = newS.entries.value(QStringLiteral("NameServer")).data;
        const QString iface = newS.rootSub.mid(newS.rootSub.lastIndexOf(QLatin1Char('\\')) + 1);
        p.title = QStringLiteral("网卡 %1 的 DNS 被改为 %2").arg(iface, clip(nn, 60));
        p.oldValue = hijack::describeDns(oldS.entries.value(QStringLiteral("NameServer")).data);
        p.newValue = hijack::describeDns(nn);
    } else {
        const QString name = QFileInfo(newS.location).fileName();
        p.title = QStringLiteral("浏览器快捷方式被改写:%1").arg(name);
        p.oldValue = hijack::describeShortcut(oldS.entries.value(QStringLiteral("target")).data,
                                              oldS.entries.value(QStringLiteral("args")).data);
        p.newValue = hijack::describeShortcut(newS.entries.value(QStringLiteral("target")).data,
                                              newS.entries.value(QStringLiteral("args")).data);
    }
    return p;
}

HijackGuard::AlertRec* HijackGuard::findAlert(const QString& id) {
    for (AlertRec& a : alerts_)
        if (a.p.id == id)
            return &a;
    return nullptr;
}

void HijackGuard::raiseAlert(const Surface& oldS, const Surface& newS, const hijack::Verdict& v,
                             bool preexisting) {
    ipc::HijackAlertPayload p = buildAlert(oldS, newS, v, preexisting);
    if (AlertRec* ex = findAlert(p.id)) {
        if (ex->p.state == QLatin1String("pending")) {
            if (ex->p.newValue == p.newValue)
                return;
            ex->p = p;
            ex->surfaceKey = newS.key;
        } else {
            ex->p = p;
            ex->surfaceKey = newS.key;
        }
    } else {
        AlertRec rec;
        rec.surfaceKey = newS.key;
        rec.p = p;
        alerts_.prepend(rec);
        while (alerts_.size() > kMaxAlerts) {
            int drop = -1;
            for (int i = alerts_.size() - 1; i >= 0; --i)
                if (alerts_[i].p.state != QLatin1String("pending")) {
                    drop = i;
                    break;
                }
            alerts_.removeAt(drop >= 0 ? drop : alerts_.size() - 1);
        }
    }
    dirty_ = true;
    saveState();
    log_.warning(QStringLiteral("【劫持防护】%1 —— %2 → %3(%4)")
                     .arg(p.title, p.oldValue, p.newValue, p.location));
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    const auto last = lastNotifyMs_.constFind(p.id);
    if (last != lastNotifyMs_.constEnd() && nowMs - last.value() < 60 * 1000)
        return;
    lastNotifyMs_.insert(p.id, nowMs);
    emit alertRaised(p);
}

void HijackGuard::resolvePending(const QString& surfaceKey, const QString& state, bool keepPreexisting) {
    for (AlertRec& a : alerts_) {
        if (a.surfaceKey != surfaceKey || a.p.state != QLatin1String("pending"))
            continue;
        if (keepPreexisting && a.p.preexisting)
            continue;
        a.p.state = state;
        dirty_ = true;
        const ipc::HijackAlertPayload copy = a.p;
        log_.info(QStringLiteral("【劫持防护】告警已结案(%1):%2").arg(state, copy.title));
        emit alertResolved(copy);
    }
}

void HijackGuard::evaluate(const Surface& cur) {
    auto it = baseline_.find(cur.key);
    if (it == baseline_.end()) {
        baseline_.insert(cur.key, cur);
        dirty_ = true;
        if (cur.kind == QLatin1String("proxy") || cur.kind == QLatin1String("policy")) {
            Surface empty = cur;
            empty.entries.clear();
            const hijack::Verdict v = judge(empty, cur);
            if (v.suspicious)
                raiseAlert(empty, cur, v, true);
        }
        return;
    }
    const Surface& base = it.value();
    if (sameEntries(base, cur)) {
        resolvePending(cur.key, QStringLiteral("restored"), true);
        return;
    }
    const hijack::Verdict v = judge(base, cur);
    if (v.suspicious) {
        raiseAlert(base, cur, v, false);
        return;
    }
    resolvePending(cur.key, QStringLiteral("restored"), false);
    it.value() = cur;
    dirty_ = true;
}

void HijackGuard::scan(bool includeShortcuts) {
    if (!isActive())
        return;
    const QMap<QString, Surface> reg = collectRegistrySurfaces();
    for (auto it = reg.constBegin(); it != reg.constEnd(); ++it)
        evaluate(it.value());
    for (auto it = baseline_.begin(); it != baseline_.end();) {
        if (it->kind == QLatin1String("dns") && !reg.contains(it.key())) {
            resolvePending(it.key(), QStringLiteral("gone"), false);
            it = baseline_.erase(it);
            dirty_ = true;
        } else {
            ++it;
        }
    }
    if (includeShortcuts) {
        QMap<QString, Surface> lnks;
        collectShortcutSurfaces(&lnks);
        for (auto it = lnks.constBegin(); it != lnks.constEnd(); ++it)
            evaluate(it.value());
        for (auto it = baseline_.begin(); it != baseline_.end();) {
            if (it->kind == QLatin1String("shortcut") && !lnks.contains(it.key())
                && !QFileInfo::exists(it->location)) {
                resolvePending(it.key(), QStringLiteral("gone"), false);
                it = baseline_.erase(it);
                dirty_ = true;
            } else {
                ++it;
            }
        }
    }
    if (dirty_) {
        saveState();
        dirty_ = false;
    }
}

bool HijackGuard::restoreRegistry(const Surface& base, QString* err) {
    const Hive h = base.hive == QLatin1String("HKU") ? Hive::Users : Hive::Machine;
    const Surface cur = readRegistrySurface(base);
    if (cur.key.isEmpty()) {
        *err = QStringLiteral("读不到该位置的现状(用户可能已注销)。");
        return false;
    }
    bool allOk = true;
    QStringList failures;
    for (auto it = base.entries.constBegin(); it != base.entries.constEnd(); ++it) {
        const auto c = cur.entries.constFind(it.key());
        if (c != cur.entries.constEnd() && c->type == it->type && c->data == it->data)
            continue;
        if (!it->supported) {
            failures << QStringLiteral("%1(类型不支持原样写回)").arg(it.key());
            allOk = false;
            continue;
        }
        const QString full = joinSub(base.rootSub, it->sub);
        if (!regutil::keyExists(h, full)) {
            QStringList created;
            quint32 e = 0;
            if (!regutil::createKeyPath(h, full, &created, &e)) {
                failures << QStringLiteral("%1(无法创建键,错误 %2)").arg(it.key()).arg(e);
                allOk = false;
                continue;
            }
        }
        quint32 e = 0;
        if (!regutil::writeValue(h, full, it->name, it->type, it->data, &e)) {
            failures << QStringLiteral("%1(写入失败,错误 %2)").arg(it.key()).arg(e);
            allOk = false;
        }
    }
    QStringList subsToTidy;
    for (auto it = cur.entries.constBegin(); it != cur.entries.constEnd(); ++it) {
        if (base.entries.contains(it.key()))
            continue;
        quint32 e = 0;
        if (!regutil::deleteValue(h, joinSub(base.rootSub, it->sub), it->name, &e)) {
            failures << QStringLiteral("%1(删除失败,错误 %2)").arg(it.key()).arg(e);
            allOk = false;
        }
        if (!it->sub.isEmpty() && !subsToTidy.contains(it->sub))
            subsToTidy << it->sub;
    }
    std::sort(subsToTidy.begin(), subsToTidy.end(),
              [](const QString& a, const QString& b) { return a.size() > b.size(); });
    QSet<QString> baseSubs;
    for (auto it = base.entries.constBegin(); it != base.entries.constEnd(); ++it)
        baseSubs.insert(it->sub);
    for (const QString& sub : std::as_const(subsToTidy))
        if (!baseSubs.contains(sub))
            regutil::deleteKeyIfEmpty(h, joinSub(base.rootSub, sub));
    if (!allOk)
        *err = QStringLiteral("部分项没能还原:%1").arg(failures.join(QStringLiteral(";")));
    return allOk;
}

bool HijackGuard::restoreShortcut(const Surface& base, QString* err) {
    if (!QFileInfo::exists(base.location)) {
        *err = QStringLiteral("快捷方式已不存在。");
        return false;
    }
    const QString target = base.entries.value(QStringLiteral("target")).data;
    const QString args = base.entries.value(QStringLiteral("args")).data;
    if (target.isEmpty()) {
        *err = QStringLiteral("基线里没有记录目标,无法还原。");
        return false;
    }
    const HRESULT hrInit = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool ok = writeLnk(base.location, target, args, err);
    if (hrInit == S_OK || hrInit == S_FALSE)
        ::CoUninitialize();
    if (ok) {
        lnkCache_.remove(QDir::toNativeSeparators(base.location).toLower());
    }
    return ok;
}

HijackGuard::ActionResult HijackGuard::restore(const QString& alertId) {
    AlertRec* a = findAlert(alertId);
    if (!a)
        return {false, QStringLiteral("找不到这条告警(可能已经处理过了)。")};
    if (a->p.state != QLatin1String("pending"))
        return {false, QStringLiteral("这条告警已经处理过了。")};
    if (!a->p.restorable) {
        return {false, a->p.preexisting
                           ? QStringLiteral("这是监视开始之前就已存在的状态,没有「改动前的值」可以还原。"
                                            "如果它确实不该在这里,请手工修改;如果是你自己配的,选「接受」。")
                           : QStringLiteral("基线里有无法原样写回的值,不能自动还原。请手工处理,或选「接受」。")};
    }
    const auto bit = baseline_.constFind(a->surfaceKey);
    if (bit == baseline_.constEnd())
        return {false, QStringLiteral("没有这一项的基线,无法还原。")};
    const Surface base = bit.value();
    const QString title = a->p.title;
    QString err;
    bool ok = base.kind == QLatin1String("shortcut") ? restoreShortcut(base, &err)
                                                     : restoreRegistry(base, &err);
    if (ok) {
        const Surface now = currentOf(base);
        if (now.key.isEmpty() || !sameEntries(base, now)) {
            ok = false;
            err = QStringLiteral("已执行写回,但回读发现现状仍与基线不一致(可能有别的程序在反复改写)。");
        }
    }
    if (!ok) {
        log_.warning(QStringLiteral("【劫持防护】还原失败:%1 —— %2").arg(title, err));
        return {false, err.isEmpty() ? QStringLiteral("还原失败。") : err};
    }
    a = findAlert(alertId);
    if (a) {
        a->p.state = QStringLiteral("restored");
        const ipc::HijackAlertPayload copy = a->p;
        dirty_ = true;
        saveState();
        dirty_ = false;
        emit alertResolved(copy);
    }
    log_.warning(QStringLiteral("【劫持防护】已按基线还原:%1").arg(title));
    return {true, QStringLiteral("已还原。已经打开的浏览器 / 程序可能要重新打开才会读到新设置。")};
}

HijackGuard::ActionResult HijackGuard::accept(const QString& alertId) {
    AlertRec* a = findAlert(alertId);
    if (!a)
        return {false, QStringLiteral("找不到这条告警(可能已经处理过了)。")};
    if (a->p.state != QLatin1String("pending"))
        return {false, QStringLiteral("这条告警已经处理过了。")};
    const auto bit = baseline_.find(a->surfaceKey);
    if (bit == baseline_.end())
        return {false, QStringLiteral("没有这一项的基线。")};
    const Surface now = currentOf(bit.value());
    if (now.key.isEmpty())
        return {false, QStringLiteral("读不到该位置的现状(用户可能已注销),稍后再试。")};
    const QString title = a->p.title;
    bit.value() = now;
    a->p.state = QStringLiteral("accepted");
    const ipc::HijackAlertPayload copy = a->p;
    saveState();
    dirty_ = false;
    log_.warning(QStringLiteral("【劫持防护】用户接受了改动,基线已更新:%1").arg(title));
    emit alertResolved(copy);
    return {true, QStringLiteral("已接受,基线更新为当前状态;之后只在它再次变化时提醒。")};
}

QList<ipc::HijackAlertPayload> HijackGuard::alerts() const {
    QList<ipc::HijackAlertPayload> pending, done;
    for (const AlertRec& a : alerts_)
        (a.p.state == QLatin1String("pending") ? pending : done).append(a.p);
    const auto newer = [](const ipc::HijackAlertPayload& x, const ipc::HijackAlertPayload& y) {
        return x.whenUtc > y.whenUtc;
    };
    std::stable_sort(pending.begin(), pending.end(), newer);
    std::stable_sort(done.begin(), done.end(), newer);
    return pending + done;
}

int HijackGuard::pendingCount() const {
    int n = 0;
    for (const AlertRec& a : alerts_)
        if (a.p.state == QLatin1String("pending"))
            ++n;
    return n;
}

QVector<ipc::HardeningItemPayload> HijackGuard::monitorItems() const {
    QVector<ipc::HardeningItemPayload> out;
    const bool active = isActive();
    const auto pendingOf = [this](const QString& kind) {
        int n = 0;
        for (const AlertRec& a : alerts_)
            if (a.p.state == QLatin1String("pending") && a.p.surface == kind)
                ++n;
        return n;
    };
    const auto finish = [&](ipc::HardeningItemPayload& it, const QString& kind) {
        it.group = QStringLiteral("monitor");
        const int pend = pendingOf(kind);
        it.satisfied = (pend == 0);
        it.severity = pend == 0 ? QStringLiteral("ok") : QStringLiteral("warn");
        if (pend > 0)
            it.note = QStringLiteral("有 %1 条待处理的告警,见页面上方。").arg(pend);
        else if (!active)
            it.note = QStringLiteral("劫持防护此刻没有运行(待机,或「注册表防护」被关闭),期间的改动会在恢复后与基线比对。");
    };

    {
        ipc::HardeningItemPayload it;
        it.id = QStringLiteral("mon.proxy");
        it.title = QStringLiteral("系统代理 / PAC");
        QStringList lines;
        int users = 0;
        for (auto b = baseline_.constBegin(); b != baseline_.constEnd(); ++b)
            if (b->kind == QLatin1String("proxy"))
                ++users;
        for (auto b = baseline_.constBegin(); b != baseline_.constEnd(); ++b) {
            if (b->kind != QLatin1String("proxy"))
                continue;
            const QString desc = hijack::describeProxy(asData(b.value()), true);
            const QString sid = b.key().mid(QStringLiteral("proxy|").size());
            lines << (users > 1 ? QStringLiteral("…%1:%2").arg(sid.right(5), desc) : desc);
        }
        it.current = lines.isEmpty() ? QStringLiteral("还没有建立基线(当前没有已登录的用户)。")
                                     : lines.join(QLatin1Char('\n'));
        it.recommended = QStringLiteral("监视每个已登录用户的 ProxyEnable / ProxyServer / AutoConfigURL。"
                                        "指向本机(127.0.0.1)的代理视为正常、不告警;指向非本机地址的代理或 PAC 才告警。");
        it.cost = QStringLiteral("只能发现「被改了」,不知道是谁改的;约每 4 秒轮询一次,是事后发现而不是写入前拦截。"
                                 "监视开始前就已存在的非本机代理只会作为「存量告警」提示一次。");
        finish(it, QStringLiteral("proxy"));
        out << it;
    }
    {
        ipc::HardeningItemPayload it;
        it.id = QStringLiteral("mon.policy");
        it.title = QStringLiteral("浏览器企业策略(Chrome / Edge / Brave / Firefox)");
        int values = 0;
        QStringList withValues;
        for (auto b = baseline_.constBegin(); b != baseline_.constEnd(); ++b) {
            if (b->kind != QLatin1String("policy"))
                continue;
            values += b->entries.size();
            if (!b->entries.isEmpty())
                withValues << QStringLiteral("%1(%2 项)").arg(b->title).arg(b->entries.size());
        }
        it.current = values == 0 ? QStringLiteral("没有任何策略值(个人电脑的正常状态)。")
                                 : QStringLiteral("基线里有 %1 个策略值:%2").arg(values).arg(withValues.join(QStringLiteral("、")));
        it.recommended = QStringLiteral("监视 HKLM\\SOFTWARE\\Policies 下四个浏览器的整棵子树。新增或改动任何值都告警,"
                                        "因为这是锁定主页、改写默认搜索、强制安装扩展的常用后门。");
        it.cost = QStringLiteral("公司 / 学校统一下发的策略也会触发,选「接受」即可。只看 HKLM 的策略,"
                                 "不覆盖浏览器自己的 Preferences 文件(那需要文件写入归因,见驱动 / ETW 侧)。");
        finish(it, QStringLiteral("policy"));
        out << it;
    }
    {
        ipc::HardeningItemPayload it;
        it.id = QStringLiteral("mon.dns");
        it.title = QStringLiteral("网卡静态 DNS");
        int ifaces = 0;
        QStringList statics;
        for (auto b = baseline_.constBegin(); b != baseline_.constEnd(); ++b) {
            if (b->kind != QLatin1String("dns"))
                continue;
            ++ifaces;
            const QString ns = b->entries.value(QStringLiteral("NameServer")).data;
            if (!ns.trimmed().isEmpty())
                statics << ns.trimmed();
        }
        it.current = statics.isEmpty()
                         ? QStringLiteral("盯着 %1 个网卡接口;都没有手动设置 DNS(跟随 DHCP)。").arg(ifaces)
                         : QStringLiteral("盯着 %1 个网卡接口;手动设置的 DNS:%2").arg(ifaces).arg(statics.join(QStringLiteral(";")));
        it.recommended = QStringLiteral("监视各网卡的静态 DNS(NameServer)。改成公共 DNS(Cloudflare / Google / 阿里 / 腾讯 …)"
                                        "或内网地址不告警,改成其它公网地址才告警。");
        it.cost = QStringLiteral("只覆盖【手动设置】的 DNS。路由器 / DHCP 下发的 DNS 被劫持,在本机看不到。"
                                 "运营商要求你手动填的 DNS 也会触发一次,选「接受」即可。");
        finish(it, QStringLiteral("dns"));
        out << it;
    }
    {
        ipc::HardeningItemPayload it;
        it.id = QStringLiteral("mon.shortcut");
        it.title = QStringLiteral("浏览器快捷方式");
        int n = 0;
        for (auto b = baseline_.constBegin(); b != baseline_.constEnd(); ++b)
            if (b->kind == QLatin1String("shortcut"))
                ++n;
        it.current = QStringLiteral("盯着 %1 个目标是浏览器的快捷方式(桌面 / 开始菜单 / 任务栏)。").arg(n);
        it.recommended = QStringLiteral("只在参数里多了网址或危险开关(--load-extension / --proxy-server / "
                                        "--remote-debugging-port …),或目标被换成非浏览器时告警。");
        it.cost = QStringLiteral("约每 16 秒扫一次;只盯目标是已知浏览器的 .lnk,新建的快捷方式直接收进基线,"
                                 "不会因为「新增」告警。还原会重写这个 .lnk 的目标与参数。");
        finish(it, QStringLiteral("shortcut"));
        out << it;
    }
    return out;
}

void HijackGuard::loadState() {
    baseline_.clear();
    alerts_.clear();
    QFile f(statePath_);
    if (!f.exists())
        return;
    if (!f.open(QIODevice::ReadOnly)) {
        log_.warning(QStringLiteral("劫持防护:读不了状态文件,将以当前现状重建基线:%1").arg(statePath_));
        return;
    }
    QJsonParseError pe;
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
        log_.warning(QStringLiteral("劫持防护:状态文件损坏(%1),将以当前现状重建基线。").arg(pe.errorString()));
        return;
    }
    const QJsonObject o = doc.object();
    for (const QJsonValue& sv : o.value(QLatin1String("baseline")).toArray()) {
        const QJsonObject so = sv.toObject();
        Surface s;
        s.key = so.value(QLatin1String("key")).toString();
        if (s.key.isEmpty())
            continue;
        s.kind = so.value(QLatin1String("kind")).toString();
        s.title = so.value(QLatin1String("title")).toString();
        s.location = so.value(QLatin1String("location")).toString();
        s.hive = so.value(QLatin1String("hive")).toString();
        s.rootSub = so.value(QLatin1String("rootSub")).toString();
        for (const QJsonValue& ev : so.value(QLatin1String("entries")).toArray()) {
            const QJsonObject eo = ev.toObject();
            Entry e;
            e.sub = eo.value(QLatin1String("sub")).toString();
            e.name = eo.value(QLatin1String("name")).toString();
            e.type = static_cast<quint32>(eo.value(QLatin1String("type")).toInt());
            e.data = eo.value(QLatin1String("data")).toString();
            e.supported = eo.value(QLatin1String("supported")).toBool(true);
            s.entries.insert(s.kind == QLatin1String("shortcut") ? e.name : entryKeyOf(e.sub, e.name), e);
        }
        baseline_.insert(s.key, s);
    }
    for (const QJsonValue& av : o.value(QLatin1String("alerts")).toArray()) {
        const QJsonObject ao = av.toObject();
        AlertRec r;
        r.surfaceKey = ao.value(QLatin1String("surfaceKey")).toString();
        r.p = ipc::HijackAlertPayload::fromJson(ao.value(QLatin1String("payload")).toObject());
        if (!r.surfaceKey.isEmpty() && !r.p.id.isEmpty())
            alerts_.append(r);
    }
}

void HijackGuard::saveState() {
    if (statePath_.isEmpty())
        return;
    QJsonArray bl;
    for (auto it = baseline_.constBegin(); it != baseline_.constEnd(); ++it) {
        const Surface& s = it.value();
        QJsonObject so;
        so["key"] = s.key;
        so["kind"] = s.kind;
        so["title"] = s.title;
        so["location"] = s.location;
        so["hive"] = s.hive;
        so["rootSub"] = s.rootSub;
        QJsonArray es;
        for (auto e = s.entries.constBegin(); e != s.entries.constEnd(); ++e) {
            QJsonObject eo;
            eo["sub"] = e->sub;
            eo["name"] = e->name;
            eo["type"] = static_cast<int>(e->type);
            eo["data"] = e->data;
            eo["supported"] = e->supported;
            es.append(eo);
        }
        so["entries"] = es;
        bl.append(so);
    }
    QJsonArray al;
    for (const AlertRec& a : alerts_) {
        QJsonObject ao;
        ao["surfaceKey"] = a.surfaceKey;
        ao["payload"] = a.p.toJson();
        al.append(ao);
    }
    QJsonObject root;
    root["version"] = 1;
    root["baseline"] = bl;
    root["alerts"] = al;
    if (!writeFileAtomically(statePath_, QJsonDocument(root).toJson(QJsonDocument::Compact),
                             QStringLiteral("劫持防护基线")))
        log_.warning(QStringLiteral("劫持防护:状态文件写入失败(内存里的基线仍有效,重启后会丢):%1").arg(statePath_));
}

}
