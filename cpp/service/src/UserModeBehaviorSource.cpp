#include "bulwark/service/UserModeBehaviorSource.h"
#include "bulwark/service/ThreatRemediator.h"
#include "bulwark/engine/RuleEngine.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFileSystemWatcher>
#include <QStandardPaths>
#include <QStringList>
#include <QTimer>
#include <QUuid>

#include <optional>

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

constexpr int kSyntheticActorPid = 0x0B00000;
const QString kCanaryName = QStringLiteral("~$Bulwark_\xE8\xAF\xB7\xE5\x8B\xBF\xE5\x88\xA0\xE9\x99\xA4_DoNotDelete.docx");
// 不编入索引:Windows 搜索建索引时带写属性权限打开文件,驱动按写入上报。
// 不加 SYSTEM 属性:不少勒索跳过系统文件,加了诱饵就碰不到它们。
constexpr DWORD kCanaryAttributes = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;

const QByteArray kCanaryContent = QString::fromUtf8(
    "\xE6\xAD\xA4\xE6\x96\x87\xE4\xBB\xB6\xE4\xB8\xBA\xE7\xA3\x90\xE5\x9E\x92\xE4\xB8\xBB\xE5\x8A\xA8\xE9\x98\xB2"
    "\xE5\xBE\xA1\xE7\x9A\x84\xE5\x8B\x92\xE7\xB4\xA2\xE8\xAF\xB1\xE9\xA5\xB5\xEF\xBC\x8C\xE8\xAF\xB7\xE5\x8B"
    "\xBF\xE5\x88\xA0\xE9\x99\xA4\xE6\x88\x96\xE4\xBF\xAE\xE6\x94\xB9\xE3\x80\x82\r\n"
    "This is a Bulwark ransomware canary (honeypot) file. Do not delete or modify.\r\n").toUtf8();

#ifdef BULWARK_ENABLE_SELFTEST
constexpr auto kSelfTestCanaryParent = "BulwarkSelfTestRansomware";
constexpr auto kSelfTestCanaryPrefix = "~$Bulwark_SelfTest_";

bool isCanonicalSelfTestRunId(const QString& runId) {
    const QUuid parsed(runId);
    return !parsed.isNull()
        && parsed.toString(QUuid::WithoutBraces).compare(runId, Qt::CaseInsensitive) == 0;
}

bool isReparsePoint(const QString& path) {
    const DWORD attributes = ::GetFileAttributesW(reinterpret_cast<LPCWSTR>(path.utf16()));
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

std::optional<QString> selfTestCanaryRootFor(const QString& runId, QString* whyOut = nullptr) {
    const auto fail = [whyOut](const QString& why) -> std::optional<QString> {
        if (whyOut) *whyOut = why;
        return std::nullopt;
    };
    if (!isCanonicalSelfTestRunId(runId))
        return fail(QStringLiteral("RunId 必须是无花括号的 UUID。"));

    const QString temp = QDir::cleanPath(QDir::tempPath());
    if (temp.isEmpty() || !QDir::isAbsolutePath(temp))
        return fail(QStringLiteral("系统临时目录不是绝对路径。"));
    if (isReparsePoint(temp))
        return fail(QStringLiteral("系统临时目录是重解析点，拒绝在其中创建测试诱饵。"));

    const QString parent = QDir::cleanPath(QDir(temp).filePath(QLatin1String(kSelfTestCanaryParent)));
    const QString root = QDir::cleanPath(QDir(parent).filePath(runId.toLower()));
    QString parentKey = parent;
    QString rootKey = root;
    parentKey.replace(QLatin1Char('\\'), QLatin1Char('/'));
    rootKey.replace(QLatin1Char('\\'), QLatin1Char('/'));
    if (!rootKey.startsWith(parentKey + QLatin1Char('/'), Qt::CaseInsensitive))
        return fail(QStringLiteral("测试诱饵根目录越出固定父目录。"));
    if (QFileInfo::exists(parent) && isReparsePoint(parent))
        return fail(QStringLiteral("测试诱饵父目录是重解析点。"));
    if (!QDir(temp).mkpath(QLatin1String(kSelfTestCanaryParent)))
        return fail(QStringLiteral("无法创建测试诱饵父目录。"));
    if (isReparsePoint(parent))
        return fail(QStringLiteral("测试诱饵父目录创建后成为重解析点。"));
    if (QFileInfo::exists(root) && !QFileInfo(root).isDir())
        return fail(QStringLiteral("测试诱饵根路径已存在且不是目录。"));
    if (!QDir(parent).mkpath(runId.toLower()))
        return fail(QStringLiteral("无法创建测试诱饵根目录。"));
    if (isReparsePoint(root))
        return fail(QStringLiteral("测试诱饵根目录是重解析点。"));
    return QDir::toNativeSeparators(root);
}
#endif

QString expandEnv(const QString& p) {
    if (p.isEmpty()) return p;
    wchar_t buf[1024] = {};
    const DWORD n = ::ExpandEnvironmentStringsW(reinterpret_cast<LPCWSTR>(p.utf16()), buf, 1024);
    return (n == 0 || n > 1024) ? p : QString::fromWCharArray(buf);
}

QString resolveLnk(const QString& lnkPath) {
    QString result;
    const HRESULT hrInit = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    IShellLinkW* link = nullptr;
    if (SUCCEEDED(::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                                     IID_IShellLinkW, reinterpret_cast<void**>(&link)))) {
        IPersistFile* pf = nullptr;
        if (SUCCEEDED(link->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&pf)))) {
            if (SUCCEEDED(pf->Load(reinterpret_cast<LPCOLESTR>(lnkPath.utf16()), STGM_READ))) {
                wchar_t target[MAX_PATH] = {};
                if (SUCCEEDED(link->GetPath(target, MAX_PATH, nullptr, SLGP_UNCPRIORITY)))
                    result = QString::fromWCharArray(target);
            }
            pf->Release();
        }
        link->Release();
    }
    if (hrInit == S_OK || hrInit == S_FALSE)
        ::CoUninitialize();
    return result;
}

QString resolveAutorunTarget(const QString& data) {
    if (data.trimmed().isEmpty()) return QString();
    QString s = expandEnv(data.trimmed());
    if (s.endsWith(QStringLiteral(".lnk"), Qt::CaseInsensitive)) {
        const QString t = resolveLnk(s);
        if (!t.isEmpty()) return t;
    }
    if (s.startsWith(QLatin1Char('"'))) {
        const int end = s.indexOf(QLatin1Char('"'), 1);
        if (end > 1) return s.mid(1, end - 1);
    }
    if (QFileInfo::exists(s)) return s;
    const int sp = s.indexOf(QLatin1Char(' '));
    if (sp > 0) {
        const QString first = s.left(sp);
        if (QFileInfo::exists(first)) return first;
    }
    return s;
}

QString regReadString(HKEY key, const wchar_t* valueName);

QStringList userProfileDirs() {
    QStringList out;
    HKEY key = nullptr;
    if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
                        0, KEY_READ, &key) != ERROR_SUCCESS)
        return out;
    DWORD idx = 0;
    wchar_t sid[512];
    for (;;) {
        DWORD n = 512;
        const LONG r = ::RegEnumKeyExW(key, idx++, sid, &n, nullptr, nullptr, nullptr, nullptr);
        if (r == ERROR_NO_MORE_ITEMS || r != ERROR_SUCCESS)
            break;
        const QString sidStr = QString::fromWCharArray(sid, static_cast<int>(n));
        if (!sidStr.startsWith(QStringLiteral("S-1-5-21-")))
            continue;
        HKEY sub = nullptr;
        if (::RegOpenKeyExW(key, sid, 0, KEY_READ, &sub) != ERROR_SUCCESS)
            continue;
        const QString path = expandEnv(regReadString(sub, L"ProfileImagePath"));
        ::RegCloseKey(sub);
        if (!path.isEmpty() && QFileInfo::exists(path))
            out << QDir::toNativeSeparators(path);
    }
    ::RegCloseKey(key);
    return out;
}

QStringList canaryFolders() {
    QStringList out;
    for (const QString& prof : userProfileDirs()) {
        for (const char* leaf : { "Documents", "Desktop", "Pictures" }) {
            const QString d = QDir(prof).filePath(QLatin1String(leaf));
            if (QFileInfo::exists(d))
                out << QDir::toNativeSeparators(d);
        }
    }
    if (out.isEmpty()) {
        for (auto loc : { QStandardPaths::DocumentsLocation, QStandardPaths::DesktopLocation,
                          QStandardPaths::PicturesLocation }) {
            const QString d = QStandardPaths::writableLocation(loc);
            if (!d.isEmpty() && QFileInfo::exists(d))
                out << QDir::toNativeSeparators(d);
        }
    }
    return out;
}

QStringList startupFolders() {
    QStringList out;
    static const QString kRel =
        QStringLiteral("AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    for (const QString& prof : userProfileDirs()) {
        const QString d = QDir(prof).filePath(kRel);
        if (QFileInfo::exists(d))
            out << QDir::toNativeSeparators(d);
    }
    const QString progData = qEnvironmentVariable("ProgramData");
    if (!progData.isEmpty()) {
        const QString d = progData + QStringLiteral("\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
        if (QFileInfo::exists(d))
            out << QDir::toNativeSeparators(d);
    }
    const QString appData = qEnvironmentVariable("APPDATA");
    if (!appData.isEmpty()) {
        const QString d = QDir::toNativeSeparators(
            appData + QStringLiteral("\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
        if (QFileInfo::exists(d) && !out.contains(d, Qt::CaseInsensitive))
            out << d;
    }
    return out;
}

struct RegLoc {
    HKEY root;
    QString sub;
    QString display;
};

QStringList loadedUserHives() {
    QStringList out;
    HKEY k = nullptr;
    if (::RegOpenKeyExW(HKEY_USERS, L"", 0, KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &k)
        != ERROR_SUCCESS)
        return out;
    for (DWORD i = 0;; ++i) {
        wchar_t name[512] = {};
        DWORD n = 511;
        if (::RegEnumKeyExW(k, i, name, &n, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        const QString s = QString::fromWCharArray(name, static_cast<int>(n));
        if (s.endsWith(QStringLiteral("_Classes"), Qt::CaseInsensitive))
            continue;
        out << s;
    }
    ::RegCloseKey(k);
    return out;
}

QList<RegLoc> autorunRegLocations() {
    QList<RegLoc> v;
    static const wchar_t* kMachine[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    };
    for (const wchar_t* s : kMachine) {
        const QString sub = QString::fromWCharArray(s);
        v.push_back({ HKEY_LOCAL_MACHINE, sub, QStringLiteral("HKLM\\") + sub });
    }
    static const wchar_t* kPerUser[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    };
    for (const QString& sid : loadedUserHives()) {
        for (const wchar_t* s : kPerUser) {
            const QString tail = QString::fromWCharArray(s);
            v.push_back({ HKEY_USERS, sid + QLatin1Char('\\') + tail,
                          QStringLiteral("HKU\\") + sid + QLatin1Char('\\') + tail });
        }
    }
    return v;
}

QString regReadString(HKEY key, const wchar_t* valueName) {
    DWORD type = 0, cb = 0;
    if (::RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &cb) != ERROR_SUCCESS)
        return QString();
    if ((type != REG_SZ && type != REG_EXPAND_SZ) || cb == 0)
        return QString();
    if (cb > 1024 * 1024)
        return QString();
    const DWORD cap = cb + 4;
    QByteArray buf(static_cast<int>(cap), '\0');
    DWORD got = cap;
    if (::RegQueryValueExW(key, valueName, nullptr, &type,
                           reinterpret_cast<LPBYTE>(buf.data()), &got) != ERROR_SUCCESS)
        return QString();
    if (got > cap)          // 理论上不会,但这是最后一道:宁可截断也不越界解释
        got = cap;
    int chars = static_cast<int>(got / sizeof(wchar_t));
    const wchar_t* w = reinterpret_cast<const wchar_t*>(buf.constData());
    while (chars > 0 && w[chars - 1] == L'\0')
        --chars;
    QString s = QString::fromWCharArray(w, chars);
    return (type == REG_EXPAND_SZ) ? expandEnv(s) : s;
}

QHash<QString, QString> readAutorunValues(HKEY root, const wchar_t* sub) {
    QHash<QString, QString> out;
    HKEY key = nullptr;
    if (::RegOpenKeyExW(root, sub, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return out;
    DWORD idx = 0;
    wchar_t nameBuf[16384] = {};
    constexpr DWORD kNameCap = 16384;
    for (;;) {
        DWORD nameLen = kNameCap;
        const LONG r = ::RegEnumValueW(key, idx++, nameBuf, &nameLen, nullptr, nullptr, nullptr, nullptr);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r == ERROR_MORE_DATA)
            continue;
        if (r != ERROR_SUCCESS) break;
        if (nameLen > kNameCap - 1)   // 兜底:绝不按大于容量的长度去解释缓冲区
            nameLen = kNameCap - 1;
        const QString name = QString::fromWCharArray(nameBuf, static_cast<int>(nameLen));
        if (name.isEmpty()) continue;
        out.insert(name, regReadString(key, reinterpret_cast<LPCWSTR>(name.utf16())));
    }
    ::RegCloseKey(key);
    return out;
}

}

UserModeBehaviorSource::UserModeBehaviorSource(bulwark::engine::RuleEngine& engine, QObject* parent)
    : EventSource(parent), engine_(engine) {
    startupDirs_ = startupFolders();
    watcher_ = new QFileSystemWatcher(this);
    connect(watcher_, &QFileSystemWatcher::directoryChanged, this, &UserModeBehaviorSource::onDirectoryChanged);
    connect(watcher_, &QFileSystemWatcher::fileChanged, this, &UserModeBehaviorSource::onFileChanged);
    regTimer_ = new QTimer(this);
    regTimer_->setInterval(4000);
    connect(regTimer_, &QTimer::timeout, this, &UserModeBehaviorSource::pollRegistry);
}

UserModeBehaviorSource::~UserModeBehaviorSource() { stop(); }

#ifdef BULWARK_ENABLE_SELFTEST
bool UserModeBehaviorSource::setSelfTestCanaryRunId(const QString& runId) {
    if (started_) {
        log_.warning(QStringLiteral("测试诱饵 RunId 必须在行为源启动前设置，已拒绝:%1").arg(runId));
        return false;
    }
    QString why;
    if (!selfTestCanaryRootFor(runId, &why)) {
        log_.warning(QStringLiteral("拒绝测试诱饵 RunId:%1 (%2)").arg(runId, why));
        return false;
    }
    selfTestCanaryRunId_ = runId.toLower();
    return true;
}
#endif

}

namespace bulwark::service {

void UserModeBehaviorSource::start() {
    if (started_) return;
    started_ = true;
    startStartupWatchers();
    deployCanaries();
    snapshotStartup();
    scanRegistryDelta(false);
    regTimer_->start();
    {
        const QStringList hives = loadedUserHives();
        const int total = autorunRegLocations().size();
        if (hives.isEmpty()) {
            log_.warning(QStringLiteral("自启动注册表监视:HKEY_USERS 下【没有枚举到任何用户 hive】——"
                                        "每用户的 Run / RunOnce 持久化当前不在监视范围内。"));
        } else {
            log_.info(QStringLiteral("自启动注册表监视:%1 个键(机器范围 5 个 + %2 个已加载用户 "
                                     "hive × 4)。已覆盖的 hive:%3。"
                                     "未登录用户的 hive 不挂在 HKEY_USERS 里,故不覆盖 ——"
                                     "他登录时 hive 即加载,那时就进监视范围。")
                          .arg(total)
                          .arg(hives.size())
                          .arg(hives.join(QStringLiteral(", "))));
        }
    }
    log_.info(QStringLiteral("用户态持续行为监控已启动(自启动持久化 + 勒索诱饵)。"));
}

void UserModeBehaviorSource::stop() {
    if (regTimer_) regTimer_->stop();
    if (watcher_) {
        const QStringList dirs = watcher_->directories();
        const QStringList files = watcher_->files();
        if (!dirs.isEmpty()) watcher_->removePaths(dirs);
        if (!files.isEmpty()) watcher_->removePaths(files);
    }
    started_ = false;
}

void UserModeBehaviorSource::startStartupWatchers() {
    for (const QString& dir : startupDirs_) {
        if (QFileInfo::exists(dir)) {
            watcher_->addPath(dir);
            log_.info(QStringLiteral("监视启动文件夹:%1").arg(dir));
        }
    }
}

void UserModeBehaviorSource::snapshotStartup() {
    for (const QString& dir : startupDirs_) {
        QSet<QString> set;
        QDir d(dir);
        if (d.exists())
            for (const QFileInfo& fi : d.entryInfoList(QDir::Files | QDir::NoDotAndDotDot))
                set.insert(QStringLiteral("%1|%2|%3").arg(fi.fileName())
                               .arg(fi.size()).arg(fi.lastModified().toMSecsSinceEpoch()));
        startupBaseline_.insert(dir, set);
    }
}

void UserModeBehaviorSource::deployCanaries() {
    if (!canaryEnabled_) return;
    for (const QString& dir : canaryFolders()) {
        if (!QFileInfo::exists(dir)) continue;
        const QString path = QDir(dir).filePath(kCanaryName);
        if (!QFileInfo::exists(path)) {
            QFile f(path);
            if (!f.open(QIODevice::WriteOnly)) continue;
            f.write(kCanaryContent);
            f.close();
        }
        ::SetFileAttributesW(reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(path).utf16()),
                             kCanaryAttributes);
        const QString native = QDir::toNativeSeparators(path);
        canaryFiles_.insert(native);
        engine_.addCanaryFile(native);
        watcher_->addPath(path);
        if (canarySink_)
            canarySink_(native, QString());
    }
#ifdef BULWARK_ENABLE_SELFTEST
    if (!selfTestCanaryRunId_.isEmpty()) {
        QString why;
        const auto root = selfTestCanaryRootFor(selfTestCanaryRunId_, &why);
        if (!root) {
            log_.warning(QStringLiteral("未投放测试诱饵(RunId=%1):%2")
                             .arg(selfTestCanaryRunId_, why));
        } else {
            const QString path = QDir(*root).filePath(
                QLatin1String(kSelfTestCanaryPrefix) + selfTestCanaryRunId_ + QStringLiteral(".txt"));
            QString rootKey = QDir::cleanPath(*root);
            QString pathKey = QDir::cleanPath(path);
            rootKey.replace(QLatin1Char('\\'), QLatin1Char('/'));
            pathKey.replace(QLatin1Char('\\'), QLatin1Char('/'));
            if (!pathKey.startsWith(rootKey + QLatin1Char('/'), Qt::CaseInsensitive)) {
                log_.critical(QStringLiteral("测试诱饵路径越出固定根目录，已拒绝:%1").arg(path));
            } else if (QFileInfo::exists(path) && isReparsePoint(path)) {
                log_.critical(QStringLiteral("测试诱饵文件是重解析点，已拒绝:%1").arg(path));
            } else {
                bool usable = true;
                bool needsWrite = !QFileInfo::exists(path);
                if (!needsWrite) {
                    QFile existing(path);
                    if (!existing.open(QIODevice::ReadOnly)) {
                        log_.warning(QStringLiteral("无法读取已有测试诱饵，已拒绝复用:%1").arg(path));
                        usable = false;
                    } else {
                        needsWrite = existing.readAll() != kCanaryContent;
                    }
                }
                if (usable && needsWrite) {
                    QFile file(path);
                    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                        log_.warning(QStringLiteral("无法创建测试诱饵:%1").arg(path));
                        usable = false;
                    } else {
                        file.write(kCanaryContent);
                        file.close();
                    }
                }
                if (usable && QFileInfo::exists(path) && !isReparsePoint(path)) {
                    const QString native = QDir::toNativeSeparators(path);
                    canaryFiles_.insert(native);
                    canaryCorrelationIds_.insert(native, selfTestCanaryRunId_);
                    engine_.addCanaryFile(native);
                    watcher_->addPath(path);
                    if (canarySink_)
                        canarySink_(native, selfTestCanaryRunId_);
                    log_.info(QStringLiteral("已投放仅测试构建的受限诱饵(RunId=%1):%2")
                                  .arg(selfTestCanaryRunId_, native));
                }
            }
        }
    }
#endif
    ThreatRemediator::setOwnCanaryFiles(QStringList(canaryFiles_.cbegin(), canaryFiles_.cend()));

    if (!canaryFiles_.isEmpty()) {
        log_.info(QStringLiteral("已投放 %1 个勒索诱饵文件并登记蜜罐%2(并已登记为清理豁免,"
                                 "避免把诱饵自己当成恶意释放物)。")
                      .arg(canaryFiles_.size())
                      .arg(canarySink_ ? QStringLiteral("(已登记写入归因)") : QString()));
    } else {
        log_.warning(QStringLiteral("未投放任何勒索诱饵:没有找到可用的用户文档目录 —— "
                                    "勒索蜜罐这一维当前【不生效】(引擎诱饵集合为空,"
                                    "诱饵命中判据永远不成立)。若本服务以 LocalSystem 运行,"
                                    "请确认能读到 ProfileList 且用户配置文件目录存在。"));
    }
}

void UserModeBehaviorSource::onDirectoryChanged(const QString& dir) {
    if (!enabled_) return;
    QDir d(dir);
    QSet<QString> current;
    for (const QFileInfo& fi : d.entryInfoList(QDir::Files | QDir::NoDotAndDotDot)) {
        const QString sig = QStringLiteral("%1|%2|%3").arg(fi.fileName())
                                .arg(fi.size()).arg(fi.lastModified().toMSecsSinceEpoch());
        current.insert(sig);
        if (startupBaseline_.value(dir).contains(sig)) continue;
        const QString full = QDir::toNativeSeparators(fi.absoluteFilePath());
        if (canaryFiles_.contains(full)) continue;
        const QString target = resolveAutorunTarget(fi.absoluteFilePath());
        emitAutorunFile(full, target.isEmpty() ? full : target);
    }
    startupBaseline_[dir] = current;
}

void UserModeBehaviorSource::onFileChanged(const QString& path) {
    if (!enabled_ || !canaryEnabled_) return;
    const QString full = QDir::toNativeSeparators(path);
    if (!canaryFiles_.contains(full)) return;

    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    auto last = canaryLastEventMs_.find(full);
    if (last != canaryLastEventMs_.end() && nowMs - last.value() < kCanaryDebounceMs) {
        ++canarySuppressed_;
        if (canarySuppressed_ % 3 == 1) {
            log_.info(QStringLiteral("勒索诱饵:已合并同一次触碰的重复变更通知(%1 ms 内,"
                                     "累计压制 %2 条)——Windows 一次写会产生多个通知,"
                                     "逐条处置会把同一件事刷成 4 遍:%3")
                          .arg(kCanaryDebounceMs)
                          .arg(canarySuppressed_)
                          .arg(full));
        }
        return;
    }
    canaryLastEventMs_.insert(full, nowMs);

    bulwark::SecurityEvent e;
    e.type = QFileInfo::exists(path) ? bulwark::EventType::FileWrite : bulwark::EventType::FileDelete;
    e.actorPid = kSyntheticActorPid;
    e.actorPath = QString::fromUtf8("(\xE7\x94\xA8\xE6\x88\xB7\xE6\x80\x81\xE8\xA1\x8C\xE4\xB8\xBA\xE7\x9B\x91"
                                    "\xE6\x8E\xA7\xC2\xB7\xE5\x8B\x92\xE7\xB4\xA2\xE8\xAF\xB1\xE9\xA5\xB5)");
    e.target = full;
    e.correlationId = canaryCorrelationIds_.value(full);
    e.userModeObserved = false;
    e.detail = QString::fromUtf8("\xE5\x8B\x92\xE7\xB4\xA2\xE8\xAF\xB1\xE9\xA5\xB5\xE6\x96\x87\xE4\xBB\xB6\xE8\xA2\xAB"
                                 "\xE6\x94\xB9\xE5\x86\x99/\xE5\x88\xA0\xE9\x99\xA4\xEF\xBC\x88\xE7\x96\x91\xE4\xBC"
                                 "\xBC\xE5\x8B\x92\xE7\xB4\xA2\xE6\x89\xB9\xE9\x87\x8F\xE5\x8A\xA0\xE5\xAF\x86\xEF\xBC\x89");
    const bool defer = shouldDeferSynthetic(attributionActive_ && attributionActive_());
    if (!defer) {
        emit eventProduced(e);
        log_.warning(QStringLiteral("勒索诱饵被触碰:%1 —— 疑似勒索行为!").arg(full));
    } else {
        log_.warning(QStringLiteral("勒索诱饵被触碰:%1 —— 疑似勒索行为!(写入归因已开启:%2 ms 后核对"
                                    "是否已有带真实写入者的事件,有则不再发出本条合成事件)")
                         .arg(full).arg(kSyntheticDeferMs));
        const QString lower = full.toLower();
        QTimer::singleShot(kSyntheticDeferMs, this, [this, e, lower, full]() {
            if (!enabled_ || !canaryEnabled_)
                return;
            const bool seen = attributionSeen_ && attributionSeen_(lower, kAttributionWindowMs);
            if (!shouldEmitSyntheticAfterDefer(seen)) {
                log_.info(QStringLiteral("勒索诱饵触碰已由写入归因事件(带真实写入者 PID)处置,"
                                         "合成事件不再发出:%1").arg(full));
                return;
            }
            log_.warning(QStringLiteral("勒索诱饵触碰:%1 ms 内 ETW 没有观测到对应的写入事件"
                                        "(写入归因未起来或事件被丢),按仅告警兜底发出合成事件:%2")
                             .arg(kSyntheticDeferMs).arg(full));
            emit eventProduced(e);
        });
    }

    bool needsRewrite = !QFileInfo::exists(path);
    if (!needsRewrite) {
        QFile check(path);
        if (check.open(QIODevice::ReadOnly)) {
            needsRewrite = (check.readAll() != kCanaryContent);
            check.close();
        }
    }
    if (needsRewrite) {
        QFile f(path);
        if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            f.write(kCanaryContent);
            f.close();
            ::SetFileAttributesW(reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(path).utf16()),
                                 kCanaryAttributes);
        }
    }
    if (QFileInfo::exists(path) && !watcher_->files().contains(path))
        watcher_->addPath(path);
}

void UserModeBehaviorSource::pollRegistry() {
    if (!enabled_) return;
    scanRegistryDelta(true);
}

void UserModeBehaviorSource::scanRegistryDelta(bool emitEvents) {
    const QList<RegLoc> locs = autorunRegLocations();
    for (const RegLoc& loc : locs) {
        const QString keyId = loc.display;
        const QHash<QString, QString> current =
            readAutorunValues(loc.root, reinterpret_cast<const wchar_t*>(loc.sub.utf16()));
        auto it = regBaseline_.find(keyId);
        if (it == regBaseline_.end()) {
            regBaseline_.insert(keyId, current);
            continue;
        }
        if (emitEvents) {
            const QHash<QString, QString> baseline = it.value();
            for (auto ci = current.constBegin(); ci != current.constEnd(); ++ci) {
                auto bi = baseline.find(ci.key());
                const bool isNew = (bi == baseline.end());
                const bool changed = !isNew && bi.value().compare(ci.value(), Qt::CaseInsensitive) != 0;
                if (isNew || changed) {
                    const QString regPath = keyId + QStringLiteral("\\") + ci.key();
                    const QString target = resolveAutorunTarget(ci.value());
                    emitAutorunReg(regPath, ci.key(), ci.value(), target.isEmpty() ? ci.value() : target);
                }
            }
        }
        it.value() = current;
    }
}

void UserModeBehaviorSource::emitAutorunFile(const QString& filePath, const QString& target) {
    bulwark::SecurityEvent e;
    e.type = bulwark::EventType::FileWrite;
    e.actorPid = 0;
    e.actorPath = target;
    e.target = filePath;
    e.userModeObserved = false;
    e.detail = QString::fromUtf8("\xE5\x90\x91\xE5\x90\xAF\xE5\x8A\xA8\xE6\x96\x87\xE4\xBB\xB6\xE5\xA4\xB9\xE5\x86\x99"
                                 "\xE5\x85\xA5\xE8\x87\xAA\xE5\x90\xAF\xE5\x8A\xA8\xE7\xA8\x8B\xE5\xBA\x8F\xEF\xBC\x88"
                                 "\xE6\x8C\x81\xE4\xB9\x85\xE5\x8C\x96\xEF\xBC\x89");
    emit eventProduced(e);
    log_.info(QStringLiteral("检测到启动文件夹新增/变更:%1").arg(filePath));
}

void UserModeBehaviorSource::emitAutorunReg(const QString& regPath, const QString& valueName,
                                            const QString& valueData, const QString& target) {
    bulwark::SecurityEvent e;
    e.type = bulwark::EventType::RegistryWrite;
    e.actorPid = 0;
    e.actorPath = target;
    e.target = regPath;
    e.userModeObserved = false;
    e.detail = QStringLiteral("\xE6\x96\xB0\xE5\xA2\x9E/\xE5\x8F\x98\xE6\x9B\xB4\xE8\x87\xAA\xE5\x90\xAF\xE5\x8A\xA8"
                              "\xE9\xA1\xB9\xEF\xBC\x9A%1 = %2").arg(valueName, valueData);
    emit eventProduced(e);
    log_.info(QStringLiteral("检测到自启动注册表变更:%1").arg(regPath));
}

}
