#include "bulwark/service/UserModeExecBlock.h"
#include "bulwark/service/AtomicFile.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMutexLocker>
#include <QTimer>

#include <windows.h>

namespace bulwark::service {

namespace {

constexpr int kRearmIntervalMs = 30000;

inline const wchar_t* wstr(const QString& s) {
    return reinterpret_cast<const wchar_t*>(s.utf16());
}

QString nowIso() {
    return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
}

QString normalize(const QString& p) {
    QString s = p.trimmed();
    s.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return s;
}

// 系统固定盘符列表(C:\ D:\ ...)。needle 是去盘符子串,必须逐盘试。
QStringList fixedDrives() {
    QStringList out;
    wchar_t buf[512] = {};
    const DWORD n = ::GetLogicalDriveStringsW(511, buf);
    if (n == 0 || n > 511)
        return out;
    for (const wchar_t* p = buf; *p; p += ::wcslen(p) + 1) {
        if (::GetDriveTypeW(p) != DRIVE_FIXED)
            continue;
        QString d = QString::fromWCharArray(p);
        if (d.endsWith(QLatin1Char('\\')))
            d.chop(1);
        out << d;
    }
    return out;
}

}

UserModeExecBlock::UserModeExecBlock(int maxEntries, QObject* parent)
    : QObject(parent), maxEntries_(maxEntries > 0 ? maxEntries : 256) {
    rearm_ = new QTimer(this);
    rearm_->setInterval(kRearmIntervalMs);
    connect(rearm_, &QTimer::timeout, this, &UserModeExecBlock::rearmPending);
    rearm_->start();
}

UserModeExecBlock::~UserModeExecBlock() {
    QMutexLocker lock(&mx_);
    for (Entry& e : entries_)
        releaseLocked(e);
}

QString UserModeExecBlock::manifestPath() const {
    return QDir(programDataDir()).filePath(QStringLiteral("usermode_execblock.json"));
}

QStringList UserModeExecBlock::resolveNeedle(const QString& needle) const {
    const QString n = normalize(needle);
    QStringList out;
    if (n.isEmpty())
        return out;

    if ((n.size() >= 2 && n[1] == QLatin1Char(':')) || n.startsWith(QStringLiteral("\\\\"))) {
        if (QFileInfo(n).isFile())
            out << QDir::toNativeSeparators(n);
        return out;
    }

    if (!n.startsWith(QLatin1Char('\\')))
        return out;
    for (const QString& d : fixedDrives()) {
        const QString cand = d + n;
        if (QFileInfo(cand).isFile())
            out << QDir::toNativeSeparators(cand);
    }
    return out;
}

bool UserModeExecBlock::isRefusedPath(const QString& absPath) const {
    const QString p = QDir::toNativeSeparators(absPath).toLower();
    if (p.isEmpty())
        return true;

    const QFileInfo fi(absPath);
    if (!fi.isFile())
        return true;

    const QString sysRoot =
        QDir::toNativeSeparators(qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows")))
            .toLower();
    const QStringList refusedPrefixes = {
        sysRoot + QStringLiteral("\\system32"),
        sysRoot + QStringLiteral("\\syswow64"),
        sysRoot + QStringLiteral("\\winsxs"),
        sysRoot + QStringLiteral("\\servicing"),
        QDir::toNativeSeparators(QCoreApplication::applicationDirPath()).toLower(),
    };
    for (const QString& pre : refusedPrefixes) {
        if (!pre.isEmpty() && p.startsWith(pre))
            return true;
    }
    return false;
}

bool UserModeExecBlock::armLocked(Entry& e) {
    releaseLocked(e);

    const QStringList targets = resolveNeedle(e.needle);
    for (const QString& t : targets) {
        if (isRefusedPath(t)) {
            log_.warning(QStringLiteral("用户态禁止执行:拒绝对该路径加锁(系统目录 / 本产品自身):%1").arg(t));
            continue;
        }
        const HANDLE h = ::CreateFileW(wstr(t), GENERIC_READ, 0, nullptr,
                                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            const DWORD err = ::GetLastError();
            // 如实记录失败原因。ERROR_SHARING_VIOLATION 说明别人(可能就是样本自己)正以
            // 冲突模式占着;此时我们没有拦截能力,绝不假装有。
            log_.warning(QStringLiteral("用户态禁止执行:抢不到独占句柄(winerr=%1),该文件此刻【未被拦截】:%2")
                             .arg(err)
                             .arg(t));
            continue;
        }
        e.resolved << t;
        e.handles << static_cast<void*>(h);
    }
    return !e.handles.isEmpty();
}

void UserModeExecBlock::releaseLocked(Entry& e) {
    for (void* h : e.handles) {
        if (h && h != INVALID_HANDLE_VALUE)
            ::CloseHandle(static_cast<HANDLE>(h));
    }
    e.handles.clear();
    e.resolved.clear();
}

bool UserModeExecBlock::addEntry(const QString& needle, bool exec) {
    const QString n = normalize(needle);
    if (n.isEmpty())
        return false;
    if (n.size() < 6)
        return false;

    const QString key = n.toLower();
    QMutexLocker lock(&mx_);

    auto it = entries_.find(key);
    if (it == entries_.end()) {
        if (entries_.size() >= maxEntries_) {
            log_.warning(QStringLiteral("用户态禁止执行名单已达上限 %1 条,拒绝新增:%2"
                                        "(请先在界面加白/清理已有条目;绝不静默挤掉旧条目)")
                             .arg(maxEntries_)
                             .arg(n));
            return false;
        }
        Entry e;
        e.needle = n;
        e.since = nowIso();
        it = entries_.insert(key, e);
    }

    if (exec)
        it->inExec = true;
    else
        it->inModule = true;

    const bool armed = it->handles.isEmpty() ? armLocked(*it) : true;
    save();

    if (armed) {
        log_.warning(QStringLiteral("用户态%1:已独占锁定 %2 个路径,该映像此后无法启动/加载(亦无法被改名或删除):%3")
                         .arg(exec ? QStringLiteral("禁止执行") : QStringLiteral("禁止加载"))
                         .arg(it->resolved.size())
                         .arg(it->resolved.join(QStringLiteral(" | "))));
    } else {
        log_.warning(QStringLiteral("用户态%1:条目已登记但【当前未生效】(文件不存在或抢不到独占句柄),"
                                    "每 %2 秒重试:%3")
                         .arg(exec ? QStringLiteral("禁止执行") : QStringLiteral("禁止加载"))
                         .arg(kRearmIntervalMs / 1000)
                         .arg(n));
    }
    return armed;
}

bool UserModeExecBlock::blockExecPath(const QString& needle) {
    return addEntry(needle, true);
}

bool UserModeExecBlock::blockModuleLoad(const QString& needle) {
    return addEntry(needle, false);
}

bool UserModeExecBlock::clearListLocked(bool exec) {
    int released = 0;
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (exec)
            it->inExec = false;
        else
            it->inModule = false;
        if (!it->inExec && !it->inModule) {
            if (!it->handles.isEmpty())
                ++released;
            releaseLocked(*it);
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
    save();
    log_.warning(QStringLiteral("用户态「%1」名单已整表清空(释放 %2 条独占锁)—— 加白对账随后会重下发未加白条目。")
                     .arg(exec ? QStringLiteral("禁止执行") : QStringLiteral("禁止加载"))
                     .arg(released));
    return true;
}

bool UserModeExecBlock::clearExecBlock() {
    QMutexLocker lock(&mx_);
    return clearListLocked(true);
}

bool UserModeExecBlock::clearModuleNoLoad() {
    QMutexLocker lock(&mx_);
    return clearListLocked(false);
}

QStringList UserModeExecBlock::persistedExecBlockList() const {
    QMutexLocker lock(&mx_);
    QStringList out;
    for (const Entry& e : entries_)
        if (e.inExec)
            out << e.needle;
    return out;
}

QStringList UserModeExecBlock::persistedModuleNoLoadList() const {
    QMutexLocker lock(&mx_);
    QStringList out;
    for (const Entry& e : entries_)
        if (e.inModule)
            out << e.needle;
    return out;
}

int UserModeExecBlock::suspendForRemediation(const QString& absPath) {
    QMutexLocker lock(&mx_);
    const QString want = QDir::toNativeSeparators(normalize(absPath)).toLower();
    int n = 0;
    for (Entry& e : entries_) {
        if (e.handles.isEmpty())
            continue;
        bool hit = want.isEmpty();
        if (!hit) {
            for (const QString& r : e.resolved) {
                if (r.toLower() == want) {
                    hit = true;
                    break;
                }
            }
        }
        if (!hit)
            continue;
        n += e.handles.size();
        releaseLocked(e);
    }
    if (n > 0) {
        log_.info(QStringLiteral("用户态禁止执行:为处置(隔离/取哈希/删除)临时放开 %1 个独占句柄:%2")
                      .arg(n)
                      .arg(want.isEmpty() ? QStringLiteral("(全部)") : absPath));
    }
    return n;
}

void UserModeExecBlock::setSuspended(bool suspended) {
    if (suspended_ == suspended)
        return;
    suspended_ = suspended;

    if (suspended) {
        if (rearm_)
            rearm_->stop();
        int handles = 0, armed = 0;
        {
            QMutexLocker lock(&mx_);
            for (Entry& e : entries_) {
                if (e.handles.isEmpty())
                    continue;
                ++armed;
                handles += static_cast<int>(e.handles.size());
                releaseLocked(e);
            }
        }
        log_.warning(QStringLiteral("用户态禁止执行:已进入待机 —— 放开 %1 条(%2 个独占句柄)并停止重试,"
                                    "名单原样保留。待机期间这些文件【可以被执行】。")
                         .arg(armed)
                         .arg(handles));
        return;
    }

    int armed = 0, pending = 0;
    {
        QMutexLocker lock(&mx_);
        for (Entry& e : entries_) {
            if (!e.handles.isEmpty())
                continue;
            if (armLocked(e))
                ++armed;
            else
                ++pending;
        }
    }
    if (rearm_)
        rearm_->start();
    log_.info(QStringLiteral("用户态禁止执行:已退出待机 —— 重新武装 %1 条,待武装 %2 条(重试表已恢复)。")
                  .arg(armed)
                  .arg(pending));
}

void UserModeExecBlock::rearmPending() {
    if (suspended_)
        return;
    QMutexLocker lock(&mx_);
    int armed = 0, pending = 0;
    for (Entry& e : entries_) {
        if (!e.handles.isEmpty())
            continue;
        if (armLocked(e))
            ++armed;
        else
            ++pending;
    }
    if (armed > 0) {
        log_.warning(QStringLiteral("用户态禁止执行:%1 条待武装条目已重新生效(文件重新出现或占用已解除);"
                                    "仍有 %2 条待武装。")
                         .arg(armed)
                         .arg(pending));
    }
}

int UserModeExecBlock::armedCount() const {
    QMutexLocker lock(&mx_);
    int n = 0;
    for (const Entry& e : entries_)
        if (!e.handles.isEmpty())
            ++n;
    return n;
}

int UserModeExecBlock::pendingCount() const {
    QMutexLocker lock(&mx_);
    int n = 0;
    for (const Entry& e : entries_)
        if (e.handles.isEmpty())
            ++n;
    return n;
}

void UserModeExecBlock::save() const {
    QJsonArray arr;
    for (const Entry& e : entries_) {
        QJsonObject o;
        o[QStringLiteral("needle")] = e.needle;
        o[QStringLiteral("exec")] = e.inExec;
        o[QStringLiteral("module")] = e.inModule;
        o[QStringLiteral("since")] = e.since;
        arr.append(o);
    }
    QJsonObject root;
    root[QStringLiteral("version")] = 1;
    root[QStringLiteral("entries")] = arr;
    writeFileAtomically(manifestPath(),
                        QJsonDocument(root).toJson(QJsonDocument::Indented),
                        QStringLiteral("用户态禁止执行名单"));
}

int UserModeExecBlock::replay() {
    QFile f(manifestPath());
    if (!f.open(QIODevice::ReadOnly)) {
        log_.info(QStringLiteral("用户态禁止执行:无历史名单,从空开始。"));
        return 0;
    }
    const QByteArray bytes = f.readAll();
    f.close();

    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(bytes, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) {
        log_.warning(QStringLiteral("用户态禁止执行:名单解析失败(%1),本次从空开始(原文件保留以便排查)。")
                         .arg(err.errorString()));
        return 0;
    }

    const QJsonArray arr = doc.object().value(QStringLiteral("entries")).toArray();
    int armed = 0, pending = 0, skipped = 0;
    {
        QMutexLocker lock(&mx_);
        for (const QJsonValue& v : arr) {
            const QJsonObject o = v.toObject();
            const QString n = normalize(o.value(QStringLiteral("needle")).toString());
            if (n.size() < 6)
                continue;
            const bool ex = o.value(QStringLiteral("exec")).toBool();
            const bool mo = o.value(QStringLiteral("module")).toBool();
            if (!ex && !mo)
                continue;
            if (entries_.size() >= maxEntries_) {
                ++skipped;
                continue;
            }
            Entry e;
            e.needle = n;
            e.inExec = ex;
            e.inModule = mo;
            e.since = o.value(QStringLiteral("since")).toString(nowIso());
            auto it = entries_.insert(n.toLower(), e);
            if (armLocked(*it))
                ++armed;
            else
                ++pending;
        }
    }

    log_.warning(QStringLiteral("用户态禁止执行:名单重放完成 —— 已生效 %1 条,待武装 %2 条%3。"
                                "注意:服务未运行期间(含开机到本服务启动之间)这些文件【可以被执行】,"
                                "跨重启的持久拦截需要内核驱动或文件 DACL 拒绝执行。")
                     .arg(armed)
                     .arg(pending)
                     .arg(skipped > 0 ? QStringLiteral(",因超上限跳过 %1 条").arg(skipped) : QString()));
    return armed;
}

}
