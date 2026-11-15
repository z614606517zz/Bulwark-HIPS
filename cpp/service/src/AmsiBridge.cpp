#include "bulwark/service/AmsiBridge.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <tlhelp32.h>

#include <QByteArray>
#include <QDateTime>
#include <QFileInfo>
#include <QHash>
#include <QMetaObject>
#include <QMutex>
#include <QMutexLocker>
#include <QPair>

#include <iterator>

#include "AmsiProtocol.h"
#include "bulwark/engine/AmsiScanPolicy.h"
#include "bulwark/engine/ScriptAnalyzer.h"
#include "bulwark/service/AmsiContentPolicy.h"

using bulwark::engine::AmsiBlockDecision;
using bulwark::engine::ScriptAnalyzer;
using bulwark::engine::ScriptType;

namespace bulwark::service {
namespace {

constexpr DWORD kRequestBudgetMs = 750;

constexpr DWORD kCloseGraceMs = 500;

constexpr DWORD kPipeBuffer = 64 * 1024;

constexpr wchar_t kPipeSddl[] =
    L"D:P(A;;0x00100183;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)S:(ML;;NW;;;LW)";

bool awaitIo(HANDLE pipe, OVERLAPPED& ov, BOOL started, DWORD* moved, ULONGLONG deadline) {
    if (!started && ::GetLastError() != ERROR_IO_PENDING)
        return false;
    const ULONGLONG now = ::GetTickCount64();
    const DWORD waitMs = (now >= deadline) ? 0 : static_cast<DWORD>(deadline - now);
    if (::WaitForSingleObject(ov.hEvent, waitMs) != WAIT_OBJECT_0) {
        ::CancelIoEx(pipe, &ov);
        DWORD discarded = 0;
        // 必须等取消真正完成:OVERLAPPED 在栈上,否则内核会写入已作废的栈。
        ::GetOverlappedResult(pipe, &ov, &discarded, TRUE);
        return false;
    }
    return ::GetOverlappedResult(pipe, &ov, moved, FALSE) != FALSE;
}

bool readAll(HANDLE pipe, HANDLE evt, void* buf, DWORD len, ULONGLONG deadline) {
    auto* p = static_cast<unsigned char*>(buf);
    DWORD done = 0;
    while (done < len) {
        ::ResetEvent(evt);
        OVERLAPPED ov = {};
        ov.hEvent = evt;
        DWORD n = 0;
        const BOOL started = ::ReadFile(pipe, p + done, len - done, &n, &ov);
        if (!awaitIo(pipe, ov, started, &n, deadline) || n == 0)
            return false;
        done += n;
    }
    return true;
}

bool writeAll(HANDLE pipe, HANDLE evt, const void* buf, DWORD len, ULONGLONG deadline) {
    const auto* p = static_cast<const unsigned char*>(buf);
    DWORD done = 0;
    while (done < len) {
        ::ResetEvent(evt);
        OVERLAPPED ov = {};
        ov.hEvent = evt;
        DWORD n = 0;
        const BOOL started = ::WriteFile(pipe, p + done, len - done, &n, &ov);
        if (!awaitIo(pipe, ov, started, &n, deadline) || n == 0)
            return false;
        done += n;
    }
    return true;
}

// 等客户端读完回复后自行断开,有上限。不能用 FlushFileBuffers:客户端不读它就永远不返回,
// 一个只发不收的客户端就能永久占住一个工作线程和管道实例。
void awaitClientClose(HANDLE pipe, HANDLE evt) {
    char sink = 0;
    ::ResetEvent(evt);
    OVERLAPPED ov = {};
    ov.hEvent = evt;
    DWORD moved = 0;
    const BOOL started = ::ReadFile(pipe, &sink, 1, &moved, &ov);
    (void)awaitIo(pipe, ov, started, &moved, ::GetTickCount64() + kCloseGraceMs);
}

QString imagePathOf(DWORD pid) {
    if (pid == 0)
        return QString();
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h == nullptr)
        return QString();
    wchar_t buf[MAX_PATH * 2] = {};
    DWORD chars = static_cast<DWORD>(std::size(buf));
    QString out;
    if (::QueryFullProcessImageNameW(h, 0, buf, &chars) && chars > 0)
        out = QString::fromWCharArray(buf, static_cast<int>(chars));
    ::CloseHandle(h);
    return out;
}

QHash<DWORD, DWORD> parentMap() {
    QHash<DWORD, DWORD> map;
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return map;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (::Process32FirstW(snap, &pe)) {
        do {
            map.insert(pe.th32ProcessID, pe.th32ParentProcessID);
        } while (::Process32NextW(snap, &pe));
    }
    ::CloseHandle(snap);
    return map;
}

QString decodeContent(const QByteArray& raw, uint32_t hint) {
    return amsi_content::decodeContent(raw, hint == BLW_AMSI_ENC_UTF16LE);
}
using amsi_content::scriptTypeFor;

constexpr qint64 kDescendantCacheTtlMs = 3000;
QMutex g_descCacheMutex;
QHash<DWORD, QPair<bool, qint64>> g_descCache;

}

AmsiBridge::AmsiBridge(QObject* parent) : QObject(parent) {}

AmsiBridge::~AmsiBridge() { stop(); }

void* AmsiBridge::createInstance(bool firstInstance) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            kPipeSddl, SDDL_REVISION_1, &sd, nullptr))
        return INVALID_HANDLE_VALUE;

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;

    DWORD openMode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if (firstInstance)
        openMode |= FILE_FLAG_FIRST_PIPE_INSTANCE;

    // PIPE_REJECT_REMOTE_CLIENTS 属于管道模式;放进打开方式会让创建以 ERROR_INVALID_PARAMETER 失败。
    HANDLE h = ::CreateNamedPipeW(BLW_AMSI_PIPE_NAME, openMode,
                                  PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                  kWorkers, kPipeBuffer, kPipeBuffer, 0, &sa);
    ::LocalFree(sd);
    return h;
}

bool AmsiBridge::start() {
    if (running_.load())
        return true;

    firstPipe_ = createInstance(true);
    if (firstPipe_ == INVALID_HANDLE_VALUE) {
        const DWORD err = ::GetLastError();
        if (err == ERROR_ACCESS_DENIED || err == ERROR_PIPE_BUSY) {
            // 不要降级继续:管道名被别人占住,宿主拿到的裁决可能来自抢占者,宁可明确不可用。
            log_.error(QStringLiteral(
                "AMSI 管道名已被其他进程占用(err=%1)—— 脚本内容防护【不启动】。"
                "这可能是一次管道抢占:抢占者可对所有送检回「放行」,等于静默关掉这一维。"
                "请排查是谁创建了 %2。")
                           .arg(err)
                           .arg(QString::fromWCharArray(BLW_AMSI_PIPE_NAME)));
        } else {
            log_.error(QStringLiteral("创建 AMSI 管道失败(err=%1),脚本内容防护不启动。")
                           .arg(err));
        }
        firstPipe_ = nullptr;
        return false;
    }

    stopEvent_ = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (stopEvent_ == nullptr) {
        ::CloseHandle(firstPipe_);
        firstPipe_ = nullptr;
        return false;
    }

    running_.store(true);
    void* handOff = firstPipe_;
    firstPipe_ = nullptr;
    for (int i = 0; i < kWorkers; ++i) {
        void* initial = (i == 0) ? handOff : INVALID_HANDLE_VALUE;
        workers_.emplace_back([this, initial] { serveLoop(initial); });
    }

    log_.info(QStringLiteral(
        "AMSI 脚本内容防护已就绪(%1 个管道实例)。注意:提供程序 DLL 必须经 Authenticode "
        "签名并注册,否则宿主不会加载它 —— 此时本端会一直收不到任何送检。"
        "注册见 cpp/scripts/register-amsi-provider.ps1。")
                 .arg(kWorkers));
    return true;
}

void AmsiBridge::stop() {
    if (!running_.exchange(false)) {
        if (firstPipe_ != nullptr && firstPipe_ != INVALID_HANDLE_VALUE) {
            ::CloseHandle(firstPipe_);
            firstPipe_ = nullptr;
        }
        return;
    }
    if (stopEvent_ != nullptr)
        ::SetEvent(stopEvent_);
    for (std::thread& t : workers_) {
        if (t.joinable())
            t.join();
    }
    workers_.clear();
    {
        QMutexLocker lock(&clientBudgetMutex_);
        clientBudgets_.clear();
    }
    if (stopEvent_ != nullptr) {
        ::CloseHandle(stopEvent_);
        stopEvent_ = nullptr;
    }
    log_.info(QStringLiteral("AMSI 脚本内容防护已停止(累计送检 %1,拦截 %2,非法帧 %3,超出单宿主预算 %4)。")
                  .arg(scans_.load()).arg(blocks_.load()).arg(rejects_.load())
                  .arg(overBudget_.load()));
}

void AmsiBridge::serveLoop(void* firstPipe) {
    HANDLE pipe = static_cast<HANDLE>(firstPipe);
    if (pipe == INVALID_HANDLE_VALUE || pipe == nullptr) {
        pipe = static_cast<HANDLE>(createInstance(false));
        if (pipe == INVALID_HANDLE_VALUE)
            return;
    }

    HANDLE evt = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (evt == nullptr) {
        ::CloseHandle(pipe);
        return;
    }

    while (running_.load()) {
        ::ResetEvent(evt);
        OVERLAPPED ov = {};
        ov.hEvent = evt;

        bool connected = false;
        if (::ConnectNamedPipe(pipe, &ov)) {
            connected = true;
        } else {
            const DWORD err = ::GetLastError();
            if (err == ERROR_PIPE_CONNECTED) {
                connected = true;
            } else if (err == ERROR_IO_PENDING) {
                HANDLE waits[2] = { evt, stopEvent_ };
                if (::WaitForMultipleObjects(2, waits, FALSE, INFINITE) == WAIT_OBJECT_0) {
                    DWORD moved = 0;
                    connected = ::GetOverlappedResult(pipe, &ov, &moved, FALSE) != FALSE;
                } else {
                    // 停机:必须等取消的 I/O 真正完成,ov 在栈上。
                    ::CancelIoEx(pipe, &ov);
                    DWORD discarded = 0;
                    ::GetOverlappedResult(pipe, &ov, &discarded, TRUE);
                    break;
                }
            } else {
                if (::WaitForSingleObject(stopEvent_, 200) == WAIT_OBJECT_0)
                    break;
            }
        }

        if (connected)
            serveOne(pipe);

        ::DisconnectNamedPipe(pipe);
    }

    ::CloseHandle(evt);
    ::CloseHandle(pipe);
}

bool AmsiBridge::beginClientRequest(unsigned long pid) {
    if (pid == 0)
        return false;
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    QMutexLocker lock(&clientBudgetMutex_);
    if (clientBudgets_.size() > 1024) {
        for (auto it = clientBudgets_.begin(); it != clientBudgets_.end();) {
            if (it->active == 0 && now - it->windowStartMs > 120000)
                it = clientBudgets_.erase(it);
            else
                ++it;
        }
    }
    ClientBudget& budget = clientBudgets_[static_cast<quint32>(pid)];
    if (budget.windowStartMs == 0 || now - budget.windowStartMs >= 60000) {
        budget.windowStartMs = now;
        budget.requests = 0;
    }
    if (budget.active >= 1 || budget.requests >= 120)
        return false;
    ++budget.active;
    ++budget.requests;
    return true;
}

void AmsiBridge::endClientRequest(unsigned long pid) {
    QMutexLocker lock(&clientBudgetMutex_);
    const auto it = clientBudgets_.find(static_cast<quint32>(pid));
    if (it != clientBudgets_.end() && it->active > 0)
        --it->active;
}

void AmsiBridge::serveOne(void* pipeHandle) {
    HANDLE pipe = static_cast<HANDLE>(pipeHandle);
    const ULONGLONG deadline = ::GetTickCount64() + kRequestBudgetMs;

    ULONG clientPid = 0;
    if (!::GetNamedPipeClientProcessId(pipe, &clientPid) || clientPid == 0) {
        rejects_.fetch_add(1);
        return;
    }
    // 预算只限制「拦截事件的上报」,送检本身无论是否超额都完整读取、判定并回复。超额时不回复
    // 会被提供程序记为失败,连续三次就熔断 60 秒放行一切 —— 等于让脚本自己关掉扫描。
    const bool withinBudget = beginClientRequest(clientPid);
    if (!withinBudget)
        overBudget_.fetch_add(1);

    HANDLE evt = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (evt == nullptr) {
        if (withinBudget)
            endClientRequest(clientPid);
        return;
    }

    auto bail = [&](bool countReject) {
        if (countReject)
            rejects_.fetch_add(1);
        if (withinBudget)
            endClientRequest(clientPid);
        ::CloseHandle(evt);
    };

    BLW_AMSI_REQUEST head = {};
    if (!readAll(pipe, evt, &head, sizeof(head), deadline)) {
        bail(false);
        return;
    }
    if (head.magic != BLW_AMSI_MAGIC || head.version != BLW_AMSI_VERSION
        || head.structSize != sizeof(BLW_AMSI_REQUEST)
        || head.hostPid != clientPid
        || head.appNameBytes > BLW_AMSI_MAX_NAME
        || head.contentNameBytes > BLW_AMSI_MAX_NAME
        || head.contentBytes > BLW_AMSI_MAX_CONTENT) {
        bail(true);
        return;
    }

    QByteArray appRaw(static_cast<int>(head.appNameBytes), Qt::Uninitialized);
    QByteArray nameRaw(static_cast<int>(head.contentNameBytes), Qt::Uninitialized);
    QByteArray contentRaw(static_cast<int>(head.contentBytes), Qt::Uninitialized);
    if ((head.appNameBytes > 0
         && !readAll(pipe, evt, appRaw.data(), head.appNameBytes, deadline))
        || (head.contentNameBytes > 0
            && !readAll(pipe, evt, nameRaw.data(), head.contentNameBytes, deadline))
        || (head.contentBytes > 0
            && !readAll(pipe, evt, contentRaw.data(), head.contentBytes, deadline))) {
        bail(false);
        return;
    }

    const QString appName = appRaw.isEmpty()
        ? QString()
        : QString::fromUtf16(reinterpret_cast<const char16_t*>(appRaw.constData()),
                             appRaw.size() / 2);
    const QString contentName = nameRaw.isEmpty()
        ? QString()
        : QString::fromUtf16(reinterpret_cast<const char16_t*>(nameRaw.constData()),
                             nameRaw.size() / 2);

    scans_.fetch_add(1);

    uint32_t verdict = BLW_AMSI_VERDICT_ALLOW;
    QString reason;
    QString content;
    AmsiBlockDecision decision;
    QString hostPath;

    if (enabled_.load() && head.contentBytes > 0) {
        content = decodeContent(contentRaw, head.encoding);
        decision = bulwark::engine::amsiShouldBlock(content);

        if (decision.block) {
            hostPath = imagePathOf(clientPid);

            const bool own = isOwnDescendant(clientPid);
            const bool trusted = (!own && trustProbe_ && !hostPath.isEmpty())
                               ? trustProbe_(hostPath)
                               : false;

            if (!own && !trusted) {
                verdict = BLW_AMSI_VERDICT_BLOCK;
                reason = decision.reasons.join(QStringLiteral("; "));
                blocks_.fetch_add(1);
            }
        }
    }

    // 先回复再上报:上报要做脚本分析与摘录,耗时可能超过提供程序的等待上限,晚到的「拦截」
    // 会被当成超时放行。
    BLW_AMSI_REPLY reply = {};
    reply.magic      = BLW_AMSI_MAGIC;
    reply.version    = BLW_AMSI_VERSION;
    reply.structSize = static_cast<uint32_t>(sizeof(BLW_AMSI_REPLY));
    reply.verdict    = verdict;

    QByteArray reasonRaw;
    if (!reason.isEmpty()) {
        const QString trimmed = reason.left(BLW_AMSI_MAX_REASON / sizeof(char16_t) - 1);
        reasonRaw = QByteArray(reinterpret_cast<const char*>(trimmed.utf16()),
                               trimmed.size() * static_cast<int>(sizeof(char16_t)));
        reply.reasonBytes = static_cast<uint32_t>(reasonRaw.size());
    }

    if (writeAll(pipe, evt, &reply, sizeof(reply), deadline) && !reasonRaw.isEmpty())
        writeAll(pipe, evt, reasonRaw.constData(),
                 static_cast<DWORD>(reasonRaw.size()), deadline);
    awaitClientClose(pipe, evt);

    if (verdict == BLW_AMSI_VERDICT_BLOCK && withinBudget) {
        const ScriptType type = scriptTypeFor(appName, contentName);

        bulwark::SecurityEvent e;
        e.type       = bulwark::EventType::ScriptScan;
        e.actorPid   = static_cast<int>(clientPid);
        e.actorPath  = hostPath;
        e.target     = contentName.isEmpty()
                         ? QStringLiteral("<内存中的脚本块>")
                         : contentName;
        e.detail     = appName;
        e.kernelBlocked      = true;
        e.hasThreatIndicator = true;
        e.techniques         = decision.techniques;

        const ScriptAnalyzer::Result soft =
            ScriptAnalyzer::analyze(content, type, QStringLiteral("被拒绝执行的脚本内容"));
        e.riskScore = 100;
        e.scriptFilePath          = contentName;
        e.scriptFileScore         = soft.score;
        e.scriptFileHardIndicator = true;
        e.scriptFileHits          = decision.hits;
        e.scriptFileReasons       = decision.reasons;

        for (const QString& r : decision.reasons)
            e.addEvidence(QStringLiteral("AmsiProvider"),
                          bulwark::EvidenceKind::HardIndicator, r);
        e.addEvidence(QStringLiteral("AmsiProvider"), bulwark::EvidenceKind::Decision,
                      QStringLiteral("内容在执行前被拒绝(AMSI 返回「已检出」),"
                                     "宿主进程未被处置 —— 拦的是这段内容,不是这个程序。"));
        if (soft.score > 0) {
            e.addEvidence(QStringLiteral("ScriptAnalyzer"),
                          bulwark::EvidenceKind::SoftSignal,
                          QStringLiteral("脚本内容软信号合计 %1 分:%2")
                              .arg(soft.score)
                              .arg(soft.reasons.join(QStringLiteral("、"))),
                          0, false);
        }

        e.addSnippet(ScriptAnalyzer::snippetForContent(content, QStringLiteral("被拒绝执行的脚本内容")));

        const QString host = hostPath;
        QMetaObject::invokeMethod(this, [this, e, host]() {
            log_.warning(QStringLiteral("脚本内容在执行前被拒绝:宿主=%1 判据=[%2]")
                             .arg(host.isEmpty() ? QStringLiteral("(未知)") : host)
                             .arg(e.scriptFileHits.join(QStringLiteral(","))));
            if (reporter_)
                reporter_(e, true);
        }, Qt::QueuedConnection);
    }
    bail(false);
}

bool AmsiBridge::isOwnDescendant(unsigned long pid) {
    const DWORD self = ::GetCurrentProcessId();
    if (pid == 0)
        return false;
    if (pid == self)
        return true;

    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    {
        QMutexLocker lock(&g_descCacheMutex);
        const auto it = g_descCache.constFind(static_cast<DWORD>(pid));
        if (it != g_descCache.constEnd() && nowMs - it->second < kDescendantCacheTtlMs)
            return it->first;
    }

    const QHash<DWORD, DWORD> parents = parentMap();
    bool own = false;
    DWORD cur = static_cast<DWORD>(pid);
    for (int hop = 0; hop < 16; ++hop) {
        const auto it = parents.constFind(cur);
        if (it == parents.constEnd())
            break;
        const DWORD parent = *it;
        if (parent == 0 || parent == cur)
            break;
        if (parent == self) {
            own = true;
            break;
        }
        cur = parent;
    }

    {
        QMutexLocker lock(&g_descCacheMutex);
        if (g_descCache.size() > 512)
            g_descCache.clear();
        g_descCache.insert(static_cast<DWORD>(pid), qMakePair(own, nowMs));
    }
    return own;
}

}
