#include "bulwark/service/FilelessGuard.h"
#include "bulwark/service/FilelessPolicy.h"

#include <QDateTime>
#include <QFileInfo>
#include <QTimer>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#endif

namespace bulwark::service {

#ifdef _WIN32

namespace {

const wchar_t* const kJitModules[] = {
    L"clrjit.dll", L"coreclr.dll", L"mscorwks.dll", L"mscorjit.dll", L"clr.dll",
    L"jvm.dll",
    L"jscript9.dll", L"chakra.dll", L"chakracore.dll",
    L"v8.dll", L"node.exe", L"libnode.dll",
    L"msedge.dll",
    L"chrome.dll",
    L"chrome_elf.dll",
    L"embeddedbrowserwebview.dll",
    L"msedgewebview2.exe",
    L"libcef.dll",
    L"nw.dll",
    L"mono-2.0-sgen.dll", L"mono-2.0-bdwgc.dll",
    L"luajit.dll",
    L"xtajit.dll", L"xtajit64.dll",
};

bool hasExecute(DWORD protect) {
    const DWORD p = protect & 0xFF;
    return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE ||
           p == PAGE_EXECUTE_WRITECOPY;
}

bool isRwx(DWORD protect) {
    const DWORD p = protect & 0xFF;
    return p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

QString protectName(DWORD protect) {
    switch (protect & 0xFF) {
    case PAGE_EXECUTE:           return QStringLiteral("X");
    case PAGE_EXECUTE_READ:      return QStringLiteral("RX");
    case PAGE_EXECUTE_READWRITE: return QStringLiteral("RWX");
    case PAGE_EXECUTE_WRITECOPY: return QStringLiteral("RWXc");
    default:                     return QStringLiteral("0x%1").arg(protect, 0, 16);
    }
}

bool remoteImageLooksLikeGo(HANDLE proc) {
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!::EnumProcessModulesEx(proc, mods, sizeof(mods), &needed, LIST_MODULES_ALL))
        return false;
    if (needed < sizeof(HMODULE)) return false;

    unsigned char buf[65536];
    SIZE_T got = 0;
    if (!::ReadProcessMemory(proc, mods[0], buf, sizeof(buf), &got) || got < 32)
        return false;

    static const unsigned char kMagic[] = {
        'G','o',' ','b','u','i','l','d','i','n','f',':'
    };
    for (SIZE_T i = 0; i + sizeof(kMagic) <= got; ++i) {
        if (std::memcmp(buf + i, kMagic, sizeof(kMagic)) == 0)
            return true;
    }
    return false;
}

bool processHasJit(HANDLE proc) {
    if (remoteImageLooksLikeGo(proc))
        return true;
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!::EnumProcessModulesEx(proc, mods, sizeof(mods), &needed, LIST_MODULES_ALL))
        return false;
    const DWORD count = std::min<DWORD>(needed / sizeof(HMODULE), 1024);
    wchar_t name[MAX_PATH];
    for (DWORD i = 0; i < count; ++i) {
        if (::GetModuleBaseNameW(proc, mods[i], name, MAX_PATH) == 0)
            continue;
        for (const wchar_t* jit : kJitModules) {
            if (::_wcsicmp(name, jit) == 0)
                return true;
        }
    }
    return false;
}

quintptr remoteModuleBase(HANDLE proc, const QString& moduleName) {
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!::EnumProcessModulesEx(proc, mods, sizeof(mods), &needed, LIST_MODULES_ALL))
        return 0;
    const DWORD count = std::min<DWORD>(needed / sizeof(HMODULE), 1024);
    wchar_t name[MAX_PATH];
    for (DWORD i = 0; i < count; ++i) {
        if (::GetModuleBaseNameW(proc, mods[i], name, MAX_PATH) == 0)
            continue;
        if (moduleName.compare(QString::fromWCharArray(name), Qt::CaseInsensitive) == 0)
            return reinterpret_cast<quintptr>(mods[i]);
    }
    return 0;
}

QString imagePathOf(HANDLE proc) {
    wchar_t buf[MAX_PATH * 2];
    DWORD n = MAX_PATH * 2;
    if (::QueryFullProcessImageNameW(proc, 0, buf, &n) && n > 0)
        return QString::fromWCharArray(buf, static_cast<int>(n));
    return {};
}

}

FilelessGuard::FilelessGuard(QObject* parent) : EventSource(parent) {}

FilelessGuard::~FilelessGuard() { stop(); }

bool FilelessGuard::looksLikeKnownBypassStub(const QByteArray& b) {
    return fileless_policy::isKnownBypassStub(b);
}

void FilelessGuard::captureBaselines() {
    struct Probe {
        const wchar_t* module; const char* fn; const char* label; const char* tech;
        const char* consequence;
    };
    static const Probe kProbes[] = {
        { L"amsi.dll",  "AmsiScanBuffer",  "AMSI 脚本内容扫描接口",     "T1562.001",
          "此后该进程执行的脚本内容不再被任何 AMSI 提供者看到。" },
        { L"amsi.dll",  "AmsiOpenSession", "AMSI 会话建立接口",         "T1562.001",
          "此后该进程根本建立不起 AMSI 会话,脚本送检这一步直接消失。" },
        { L"ntdll.dll", "EtwEventWrite",   "ETW 事件写入(遥测通道)",   "T1562.006",
          "此后该进程的行为遥测在用户态被摘断,依赖 ETW 的检测(含本产品的 ETW 源)"
          "再也看不到它做了什么。" },
        { L"ntdll.dll", "NtTraceEvent",    "ETW 内核跟踪系统调用",      "T1562.006",
          "此后该进程连内核跟踪这一层都写不进去,ETW 两条路径同时断掉。" },
    };

    for (const Probe& p : kProbes) {
        HMODULE h = ::GetModuleHandleW(p.module);
        bool loadedByUs = false;
        if (h == nullptr) {
            h = ::LoadLibraryExW(p.module, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
            loadedByUs = h != nullptr;
        }
        if (h == nullptr) {
            log_.info(QStringLiteral("无文件防护:本机没有 %1,跳过「%2」这一项补丁检测。")
                          .arg(QString::fromWCharArray(p.module))
                          .arg(QString::fromUtf8(p.label)));
            continue;
        }
        const FARPROC fn = ::GetProcAddress(h, p.fn);
        if (fn == nullptr) {
            if (loadedByUs) {}
            continue;
        }

        FnBaseline b;
        b.module = QString::fromWCharArray(p.module).toLower();
        b.fn = QString::fromLatin1(p.fn);
        b.rva = reinterpret_cast<quintptr>(fn) - reinterpret_cast<quintptr>(h);
        b.bytes = QByteArray(reinterpret_cast<const char*>(fn), kPrologueBytes);
        b.technique = QString::fromLatin1(p.tech);
        b.label = QString::fromUtf8(p.label);
        b.consequence = QString::fromUtf8(p.consequence);

        if (looksLikeKnownBypassStub(b.bytes)) {
            log_.critical(QStringLiteral(
                "无文件防护:本机 %1!%2 的函数序言【本身】就是已知绕过桩 —— 这意味着该模块在"
                "磁盘上或加载路径上已被篡改(不是单个进程被补丁)。已弃用该项基准以免把被补丁的"
                "进程误判为正常,请检查 %1 的完整性。")
                    .arg(b.module, b.fn));
            continue;
        }
        baselines_.push_back(b);
    }

    log_.info(QStringLiteral("无文件防护:已抓取 %1 项内存补丁基准(AMSI / ETW 函数序言)。")
                  .arg(baselines_.size()));
}

QVector<FilelessGuard::Finding> FilelessGuard::scanUnbackedMemory(void* process,
                                                                 bool jitHost) const {
    QVector<Finding> out;
    const HANDLE proc = static_cast<HANDLE>(process);

    MEMORY_BASIC_INFORMATION mbi{};
    quintptr addr = 0;
    int iterations = 0;
    bool reportedRwx = false, reportedPe = false, reportedUnbackedMap = false, reportedRx = false;

    while (::VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) ==
           sizeof(mbi)) {
        if (++iterations > kMaxRegions)
            break;

        const quintptr base = reinterpret_cast<quintptr>(mbi.BaseAddress);
        const quint64 size = static_cast<quint64>(mbi.RegionSize);
        addr = base + (size ? size : 0x1000);

        if (mbi.State != MEM_COMMIT || !hasExecute(mbi.Protect))
            continue;

        if (mbi.Type == MEM_IMAGE)
            continue;

        QByteArray head(0x40, Qt::Uninitialized);
        SIZE_T read = 0;
        const bool readOk = ::ReadProcessMemory(proc, mbi.BaseAddress, head.data(),
                                                static_cast<SIZE_T>(head.size()), &read) &&
                            read >= 0x40;

        bool hasPe = false;
        if (readOk && static_cast<quint8>(head.at(0)) == 'M' &&
            static_cast<quint8>(head.at(1)) == 'Z') {
            const qint32 lfanew = *reinterpret_cast<const qint32*>(head.constData() + 0x3C);
            if (lfanew > 0 && lfanew < 0x1000 && static_cast<quint64>(lfanew) + 4 <= size) {
                char sig[4] = {};
                SIZE_T r2 = 0;
                if (::ReadProcessMemory(proc,
                                        reinterpret_cast<LPCVOID>(base + static_cast<quintptr>(lfanew)),
                                        sig, 4, &r2) && r2 == 4) {
                    hasPe = sig[0] == 'P' && sig[1] == 'E' && sig[2] == 0 && sig[3] == 0;
                }
            }
        }

        const bool mappedNoFile = [&]() {
            if (mbi.Type != MEM_MAPPED)
                return false;
            wchar_t name[MAX_PATH] = {};
            return ::GetMappedFileNameW(proc, mbi.BaseAddress, name, MAX_PATH) == 0;
        }();

        const QString where = QStringLiteral("0x%1,%2,%3KB")
                                  .arg(base, 0, 16)
                                  .arg(protectName(mbi.Protect))
                                  .arg(size / 1024);

        if (hasPe && !reportedPe) {
            reportedPe = true;
            out.push_back({ fileless_policy::unbackedPeFinding(),
                            QStringLiteral("区域 %1 起始处是完整的 PE 头(MZ + PE\\0\\0),而该区域"
                                           "【没有任何磁盘文件作为后备】。合法模块一律是 MEM_IMAGE "
                                           "类型由加载器映射;自己把 PE 写进私有内存再执行,是反射式"
                                           "加载 / 手工映射的定义。").arg(where),
                            85, true, QStringLiteral("T1620") });
            continue;
        }

        if (mbi.Type == MEM_PRIVATE && isRwx(mbi.Protect) && size >= kMinRwxBytes
            && !reportedRwx && !jitHost) {
            reportedRwx = true;
            out.push_back({ QStringLiteral("进程内存中存在可写且可执行的私有内存(RWX)"),
                            QStringLiteral("区域 %1。正常代码页由加载器置为只读可执行;长期保持"
                                           "可写可执行是 shellcode / 载荷解密后原地执行的典型形态"
                                           "(且本进程未加载任何 JIT 运行时)。").arg(where),
                            70, false, QStringLiteral("T1055") });
            continue;
        }

        if (mappedNoFile && !reportedUnbackedMap && !jitHost) {
            reportedUnbackedMap = true;
            out.push_back({ QStringLiteral("进程内存中存在无文件后备的可执行映射节"),
                            QStringLiteral("区域 %1 为 MEM_MAPPED 但取不到映射文件名,说明它由页文件"
                                           "后备 —— 通过节对象投递 shellcode(Donut 等)正是这个形态。")
                                .arg(where),
                            70, false, QStringLiteral("T1055") });
            continue;
        }

        if (mbi.Type == MEM_PRIVATE && size >= kMinRxBytes && !reportedRx && !jitHost) {
            reportedRx = true;
            out.push_back({ QStringLiteral("进程内存中存在较大的未落地可执行私有内存"),
                            QStringLiteral("区域 %1。无磁盘文件后备的可执行内存,且本进程未加载任何"
                                           "JIT 运行时 —— 需要结合主体身份一并判断。").arg(where),
                            45, false, QStringLiteral("T1055") });
        }
    }

    return out;
}

QVector<FilelessGuard::Finding> FilelessGuard::scanHookPatches(void* process) const {
    QVector<Finding> out;
    const HANDLE proc = static_cast<HANDLE>(process);

    for (const FnBaseline& b : baselines_) {
        const quintptr base = remoteModuleBase(proc, b.module);
        if (base == 0)
            continue;

        QByteArray now(kPrologueBytes, Qt::Uninitialized);
        SIZE_T read = 0;
        if (!::ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(base + b.rva), now.data(),
                                 kPrologueBytes, &read) || read != kPrologueBytes)
            continue;

        if (now == b.bytes)
            continue;

        if (!looksLikeKnownBypassStub(now))
            continue;

        out.push_back({ QStringLiteral("%1 已被内存补丁禁用(%2!%3)")
                            .arg(b.label, b.module, b.fn),
                        QStringLiteral("该函数序言被改写为已知的绕过桩(当前字节 %1,干净基准 %2)。"
                                       "这不是绕过某一条规则,而是把整条检测/遥测通道在本进程内物理摘掉 —— %3")
                            .arg(QString::fromLatin1(now.left(8).toHex(' ')))
                            .arg(QString::fromLatin1(b.bytes.left(8).toHex(' ')))
                            .arg(b.consequence),
                        95, true, b.technique });
    }

    return out;
}

int FilelessGuard::scanProcess(int pid) {
    return scanProcessImpl(pid, false);
}

int FilelessGuard::scanProcessImpl(int pid, bool urgent) {
    if (pid <= 4 || selfPids_.contains(pid))
        return 0;

    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    const qint64 lastNormalMs = lastScanMs_.value(pid, -1);
    const qint64 lastUrgentMs = lastUrgentScanMs_.value(pid, -1);
    if (fileless_policy::scanIsCoolingDown(urgent, nowMs, lastNormalMs, lastUrgentMs,
                                           kCooldownMs, kUrgentCooldownMs))
        return 0;
    if (urgent)
        lastUrgentScanMs_.insert(pid, nowMs);
    else
        lastScanMs_.insert(pid, nowMs);
    // 紧急扫描也更新普通冷却，避免紧接着的周期轮转重复做同一份重活；反向不更新，
    // 所以启动预扫/周期扫描绝不会压掉随后到来的 RemoteThread 注入证据。
    if (urgent)
        lastScanMs_.insert(pid, nowMs);
    if (lastUrgentScanMs_.size() > 4096)
        lastUrgentScanMs_.clear();
    if (lastScanMs_.size() > 4096)
        lastScanMs_.clear();

    const HANDLE proc = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                                      static_cast<DWORD>(pid));
    if (proc == nullptr) {
        ++openFailures_;
        return 0;
    }

    const QString image = imagePathOf(proc);
    const bool jitHost = processHasJit(proc);

    QVector<Finding> findings = scanHookPatches(proc);
    findings += scanUnbackedMemory(proc, jitHost);
    ::CloseHandle(proc);

    for (const Finding& f : findings)
        emitFinding(pid, image, f);

    return findings.size();
}

void FilelessGuard::emitFinding(int pid, const QString& imagePath, const Finding& f) {
    const QString key = QStringLiteral("%1|%2|%3").arg(pid).arg(imagePath.toLower(), f.what);
    if (reported_.contains(key))
        return;
    if (reported_.size() > 2048)
        reported_.clear();
    reported_.insert(key);

    log_.warning(QStringLiteral("无文件攻击检测:PID=%1 %2 —— %3 (%4)")
                     .arg(pid).arg(QFileInfo(imagePath).fileName(), f.what, f.detail));

    bulwark::SecurityEvent e;
    e.type = bulwark::EventType::RemoteThread;
    e.actorPid = pid;
    e.actorPath = imagePath;
    e.target = QStringLiteral("PID %1 %2 · %3")
                   .arg(pid).arg(QFileInfo(imagePath).fileName(), f.what);
    e.detail = f.detail;
    e.userModeObserved = true;
    e.memoryInjection = true;
    e.riskScore = f.score;
    e.hasThreatIndicator = f.hard;
    if (!f.technique.isEmpty())
        e.techniques << f.technique;
    e.riskReasons << f.what;
    e.addEvidence(QStringLiteral("内存扫描"),
                  f.hard ? bulwark::EvidenceKind::HardIndicator
                         : bulwark::EvidenceKind::SoftSignal,
                  QStringLiteral("%1:%2").arg(f.what, f.detail), f.score, false,
                  bulwark::EvidenceSubject::Target);
    e.addEvidence(QStringLiteral("内存扫描"), bulwark::EvidenceKind::Info,
                  QStringLiteral("本判据只能确定这段内存 / 这处补丁位于 %1(PID %2)的地址空间内,"
                                 "【不能】确定是谁写进去的 —— 写入方可能是别的进程、也可能已经退出。"
                                 "该进程在本事件里的身份是承载方。")
                      .arg(QFileInfo(imagePath).fileName()).arg(pid),
                  0, false, bulwark::EvidenceSubject::Target);

    emit eventProduced(e);
}

void FilelessGuard::onObservedEvent(const bulwark::SecurityEvent& e) {
    if (e.memoryInjection && e.userModeObserved &&
        e.type == bulwark::EventType::RemoteThread &&
        e.target.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
        return;

    const auto push = [this](int pid, bool urgent) {
        if (pid <= 4 || selfPids_.contains(pid) || urgentTargeted_.contains(pid))
            return;

        if (urgent) {
            targeted_.removeOne(pid);
        } else if (targeted_.contains(pid)) {
            return;
        }

        if (targeted_.size() + urgentTargeted_.size() >= kTargetedQueueMax)
            return;
        if (urgent)
            urgentTargeted_.enqueue(pid);
        else
            targeted_.enqueue(pid);
    };

    if (e.type == bulwark::EventType::ProcessCreate &&
        fileless_policy::shouldTargetNewProcess(e.actorPath)) {
        push(e.actorPid, false);
        return;
    }

    const bool injectionHint =
        e.type == bulwark::EventType::RemoteThread ||
        e.memoryInjection ||
        (e.type == bulwark::EventType::SelfProtect && e.riskScore > 0);
    if (!injectionHint)
        return;

    push(e.actorPid, true);
    push(e.parentPid, true);
}

void FilelessGuard::onTargetedTick() {
    if (!urgentTargeted_.isEmpty()) {
        scanProcessImpl(urgentTargeted_.dequeue(), true);
        return;
    }
    if (!targeted_.isEmpty())
        scanProcess(targeted_.dequeue());
}

void FilelessGuard::onSweepTick() {
    QVector<int> pids;
    const HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (::Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID > 4)
                pids.push_back(static_cast<int>(pe.th32ProcessID));
        } while (::Process32NextW(snap, &pe));
    }
    ::CloseHandle(snap);
    if (pids.isEmpty())
        return;

    std::sort(pids.begin(), pids.end());

    const qint64 before = openFailures_;
    int scanned = 0, hits = 0;
    for (int i = 0; i < kProcPerSweep && i < pids.size(); ++i) {
        if (sweepCursor_ >= pids.size())
            sweepCursor_ = 0;
        hits += scanProcess(pids.at(sweepCursor_++));
        ++scanned;
    }

    if (hits > 0 || openFailures_ != before) {
        log_.info(QStringLiteral("无文件防护巡检:本轮扫 %1 个进程(共 %2),可疑 %3 项,"
                                 "打不开 %4 个(受保护进程 / PPL,属正常)。")
                      .arg(scanned).arg(pids.size()).arg(hits).arg(openFailures_ - before));
    }
}

void FilelessGuard::start() {
    if (started_)
        return;
    started_ = true;

    selfPids_.insert(static_cast<int>(::GetCurrentProcessId()));
    captureBaselines();
    available_ = true;

    sweepTimer_ = new QTimer(this);
    sweepTimer_->setInterval(kSweepIntervalMs);
    connect(sweepTimer_, &QTimer::timeout, this, &FilelessGuard::onSweepTick);
    sweepTimer_->start();

    targetedTimer_ = new QTimer(this);
    targetedTimer_->setInterval(kTargetedTickMs);
    connect(targetedTimer_, &QTimer::timeout, this, &FilelessGuard::onTargetedTick);
    targetedTimer_->start();

    log_.info(QStringLiteral("无文件(内存)攻击防护已启动:每 %1 秒轮转扫描 %2 个进程;"
                             "高风险脚本宿主/用户可写目录进程启动以及远程线程/反注入事件会触发"
                             "定向加扫。判据 = 未落地可执行内存(RWX / 内存 PE / 无文件后备映射)"
                             "+ AMSI/ETW 内存补丁。")
                  .arg(kSweepIntervalMs / 1000).arg(kProcPerSweep));

    QTimer::singleShot(15000, this, &FilelessGuard::onSweepTick);
}

void FilelessGuard::stop() {
    if (sweepTimer_) { sweepTimer_->stop(); sweepTimer_->deleteLater(); sweepTimer_ = nullptr; }
    if (targetedTimer_) { targetedTimer_->stop(); targetedTimer_->deleteLater(); targetedTimer_ = nullptr; }
    targeted_.clear();
    urgentTargeted_.clear();
    lastScanMs_.clear();
    lastUrgentScanMs_.clear();
    started_ = false;
}

#else

FilelessGuard::FilelessGuard(QObject* parent) : EventSource(parent) {}
FilelessGuard::~FilelessGuard() = default;
void FilelessGuard::start() { available_ = false; }
void FilelessGuard::stop() {}
int FilelessGuard::scanProcess(int) { return 0; }
void FilelessGuard::onObservedEvent(const bulwark::SecurityEvent&) {}
void FilelessGuard::onSweepTick() {}
void FilelessGuard::onTargetedTick() {}
void FilelessGuard::captureBaselines() {}
QVector<FilelessGuard::Finding> FilelessGuard::scanUnbackedMemory(void*, bool) const { return {}; }
QVector<FilelessGuard::Finding> FilelessGuard::scanHookPatches(void*) const { return {}; }
void FilelessGuard::emitFinding(int, const QString&, const Finding&) {}
bool FilelessGuard::looksLikeKnownBypassStub(const QByteArray&) { return false; }

#endif

}
