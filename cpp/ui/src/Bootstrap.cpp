#include "Bootstrap.h"

#include "bulwark/ipc/PipeNames.h"

#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QFutureWatcher>
#include <QLocalSocket>
#include <QMetaObject>
#include <QPointer>
#include <QtConcurrent/QtConcurrentRun>
#include "design/Confirm.h"
#include <QProcess>

#include <utility>
#include <iterator>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>

namespace bulwark::ui::bootstrap {
namespace {

inline QString u(const char* s) { return QString::fromUtf8(s); }

bool isInteractiveUserSession() {
    DWORD sessionId = 0;
    if (!::ProcessIdToSessionId(::GetCurrentProcessId(), &sessionId) || sessionId == 0)
        return false;

    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    BYTE userBuffer[256] = {};
    DWORD userBytes = 0;
    const bool gotUser = ::GetTokenInformation(token, TokenUser, userBuffer,
                                                sizeof(userBuffer), &userBytes) != 0;
    ::CloseHandle(token);
    if (!gotUser)
        return false;

    BYTE systemSidBuffer[SECURITY_MAX_SID_SIZE] = {};
    DWORD systemSidBytes = sizeof(systemSidBuffer);
    if (!::CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSidBuffer, &systemSidBytes))
        return false;
    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(userBuffer);
    return !::EqualSid(tokenUser->User.Sid, systemSidBuffer);
}

bool isElevated() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    TOKEN_ELEVATION info = {};
    DWORD size = 0;
    const bool ok = ::GetTokenInformation(token, TokenElevation, &info, sizeof(info), &size) != 0;
    ::CloseHandle(token);
    return ok && info.TokenIsElevated != 0;
}

QString serviceExePath() {
    const QString p = QDir(QCoreApplication::applicationDirPath())
                          .filePath(QStringLiteral("bulwark_service.exe"));
    return QFileInfo::exists(p) ? QDir::toNativeSeparators(p) : QString();
}

bool pipeServerIsGenuine(qintptr fd) {
    ULONG pid = 0;
    if (!::GetNamedPipeServerProcessId(reinterpret_cast<HANDLE>(fd), &pid) || pid == 0)
        return false;
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process)
        return false;

    wchar_t image[MAX_PATH * 2] = {};
    DWORD imageChars = static_cast<DWORD>(std::size(image));
    const bool pathOk = ::QueryFullProcessImageNameW(process, 0, image, &imageChars) != FALSE;
    HANDLE token = nullptr;
    BYTE userBuffer[256] = {};
    DWORD userBytes = 0;
    const bool userOk = ::OpenProcessToken(process, TOKEN_QUERY, &token) != FALSE
        && ::GetTokenInformation(token, TokenUser, userBuffer, sizeof(userBuffer), &userBytes) != FALSE;
    if (token)
        ::CloseHandle(token);
    ::CloseHandle(process);
    if (!pathOk || !userOk)
        return false;

    BYTE systemSidBuffer[SECURITY_MAX_SID_SIZE] = {};
    DWORD systemSidBytes = sizeof(systemSidBuffer);
    if (!::CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSidBuffer, &systemSidBytes))
        return false;
    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(userBuffer);
    if (!::EqualSid(tokenUser->User.Sid, systemSidBuffer))
        return false;

    const QString actual = QDir::cleanPath(QString::fromWCharArray(image, static_cast<int>(imageChars)));
    const QString expected = QDir::cleanPath(serviceExePath());
    return !expected.isEmpty() && actual.compare(expected, Qt::CaseInsensitive) == 0;
}

enum class RunResult { Ok, Refused, Failed };

RunResult runElevated(const QString& exe, const QString& args) {
    const std::wstring wexe = exe.toStdWString();
    const std::wstring wargs = args.toStdWString();

    SHELLEXECUTEINFOW si = {};
    si.cbSize = sizeof(si);
    si.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    si.lpVerb = L"runas";
    si.lpFile = wexe.c_str();
    si.lpParameters = wargs.c_str();
    si.lpDirectory = nullptr;
    si.nShow = SW_HIDE;

    if (!::ShellExecuteExW(&si)) {
        return (::GetLastError() == ERROR_CANCELLED) ? RunResult::Refused : RunResult::Failed;
    }
    if (si.hProcess) {
        ::WaitForSingleObject(si.hProcess, 180000);
        ::CloseHandle(si.hProcess);
    }
    return RunResult::Ok;
}

RunResult runDirect(const QString& exe, const QStringList& args) {
    QProcess p;
    p.start(exe, args);
    if (!p.waitForStarted(10000))
        return RunResult::Failed;
    if (!p.waitForFinished(180000)) {
        p.kill();
        p.waitForFinished(2000);
        return RunResult::Failed;
    }
    return RunResult::Ok;
}

QString bootstrapStatus() {
    QString base = qEnvironmentVariable("BULWARK_DATA_DIR").trimmed();
    if (base.isEmpty()) {
        base = qEnvironmentVariable("ProgramData");
        if (base.isEmpty()) base = QStringLiteral("C:/ProgramData");
        base += QStringLiteral("/Bulwark");
    }
    QFile f(QDir(base).filePath(QStringLiteral("bootstrap-status.txt")));
    if (!f.open(QIODevice::ReadOnly))
        return QString();
    return QString::fromUtf8(f.readAll()).trimmed();
}

bool waitForBackend(int totalMs) {
    QElapsedTimer t;
    t.start();
    while (t.elapsed() < totalMs) {
        if (backendReachable(200))
            return true;
        ::Sleep(300);
    }
    return false;
}

}

bool backendReachable(int timeoutMs) {
    QLocalSocket probe;
    probe.connectToServer(bulwark::ipc::controlPipe());
    const bool connected = probe.waitForConnected(timeoutMs);
    const bool genuine = connected && pipeServerIsGenuine(probe.socketDescriptor());
    if (connected)
        probe.disconnectFromServer();
    return genuine;
}

BackendStartOutcome startBackend(int waitMs, QString* detail) {
    if (detail)
        detail->clear();
    if (backendReachable())
        return BackendStartOutcome::AlreadyRunning;

    const QString exe = serviceExePath();
    if (exe.isEmpty())
        return BackendStartOutcome::Missing;

    const RunResult r = isElevated()
        ? runDirect(exe, { QStringLiteral("--bootstrap") })
        : runElevated(exe, QStringLiteral("--bootstrap"));

    if (r == RunResult::Refused)
        return BackendStartOutcome::Refused;

    if (r == RunResult::Failed) {
        if (detail)
            *detail = bootstrapStatus();
        return BackendStartOutcome::Failed;
    }

    if (waitForBackend(waitMs))
        return BackendStartOutcome::Started;

    if (detail)
        *detail = bootstrapStatus();
    return BackendStartOutcome::Failed;
}

void startBackendAsync(QObject* guard, std::function<void(BackendStartOutcome, const QString&)> done) {
    if (!guard)
        return;
    using Result = QPair<BackendStartOutcome, QString>;
    auto* watcher = new QFutureWatcher<Result>(guard);
    const QPointer<QObject> safeGuard(guard);
    QObject::connect(watcher, &QFutureWatcher<Result>::finished, guard,
                     [watcher, safeGuard, done = std::move(done)] {
        const Result result = watcher->result();
        watcher->deleteLater();
        if (safeGuard)
            done(result.first, result.second);
    });
    watcher->setFuture(QtConcurrent::run([] {
        QString detail;
        const BackendStartOutcome outcome = startBackend(30000, &detail);
        return Result{outcome, detail};
    }));
}

bool ensureBackendRunning(QWidget* parent) {
    QString detail;
    switch (startBackend(30000, &detail)) {
    case BackendStartOutcome::AlreadyRunning:
    case BackendStartOutcome::Started:
        return true;
    case BackendStartOutcome::Missing:
        ::ui::notice(parent, ::ui::NoticeTone::Warning, u("找不到防护服务"),
            u("找不到 bulwark_service.exe。请确保它与本程序在同一目录,"
              "否则界面无法连上防护服务。界面会以「未连接」状态打开。"));
        return false;
    case BackendStartOutcome::Refused:
        ::ui::notice(parent, ::ui::NoticeTone::Info, u("已跳过启动防护服务"),
            u("需要管理员权限才能启动防护服务与内核驱动。"
              "本次已跳过 —— 界面会以「未连接」状态打开,不影响你查看历史记录。"
              "想启用防护,重新打开本程序并在提权提示里选「是」即可。"));
        return false;
    case BackendStartOutcome::Failed:
        ::ui::notice(parent, ::ui::NoticeTone::Danger, u("防护服务未能启动"),
            u("界面将以「未连接」状态打开,系统此刻不受本软件保护。"),
            detail.isEmpty() ? u("详见 %ProgramData%\\Bulwark\\service.log。") : detail);
        return false;
    }
    return false;
}

bool ensureUiAutoStart() {
    if (!isInteractiveUserSession())
        return false;
    const QString exe = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());
    if (exe.isEmpty())
        return false;
    const std::wstring want = (QLatin1Char('"') + exe + QStringLiteral("\" --tray")).toStdWString();

    HKEY key = nullptr;
    if (::RegOpenKeyExW(HKEY_CURRENT_USER,
                        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key) != ERROR_SUCCESS) {
        return false;
    }

    bool same = false;
    {
        wchar_t cur[1024] = {};
        DWORD size = sizeof(cur);
        DWORD type = 0;
        if (::RegQueryValueExW(key, L"Bulwark", nullptr, &type,
                               reinterpret_cast<LPBYTE>(cur), &size) == ERROR_SUCCESS
            && type == REG_SZ) {
            same = (::_wcsicmp(cur, want.c_str()) == 0);
        }
    }
    bool ok = same;
    if (!same) {
        ok = ::RegSetValueExW(key, L"Bulwark", 0, REG_SZ,
                              reinterpret_cast<const BYTE*>(want.c_str()),
                              static_cast<DWORD>((want.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
    }
    ::RegCloseKey(key);
    return ok;
}

}
