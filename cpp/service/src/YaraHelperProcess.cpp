#include "bulwark/service/YaraHelperProcess.h"

#include <QDir>
#include <QFileInfo>

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace bulwark::service::yarahelper {
namespace {

constexpr int kMaxLineBytes = 4 * 1024 * 1024;

std::wstring native(const QString& path) { return QDir::toNativeSeparators(path).toStdWString(); }

// MSVC 命令行转义:反斜杠只在紧挨引号或结尾时才需要成对。
QString quoteArg(const QString& a) {
    QString out = QStringLiteral("\"");
    int backslashes = 0;
    for (const QChar c : a) {
        if (c == QLatin1Char('\\')) {
            ++backslashes;
            continue;
        }
        if (c == QLatin1Char('"'))
            out += QString(backslashes * 2 + 1, QLatin1Char('\\'));
        else
            out += QString(backslashes, QLatin1Char('\\'));
        out += c;
        backslashes = 0;
    }
    out += QString(backslashes * 2, QLatin1Char('\\'));
    out += QLatin1Char('"');
    return out;
}

std::wstring commandLine(const QString& exe, const QStringList& args) {
    QString cmd = quoteArg(QDir::toNativeSeparators(exe));
    for (const QString& a : args)
        cmd += QLatin1Char(' ') + quoteArg(a);
    return cmd.toStdWString();
}

HANDLE createLimitedJob(int memoryLimitMb, DWORD* error) {
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (!job) {
        *error = GetLastError();
        return nullptr;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                                            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                                            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
                                            | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    limits.ProcessMemoryLimit = static_cast<SIZE_T>(std::max(256, memoryLimitMb)) * 1024u * 1024u;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        *error = GetLastError();
        CloseHandle(job);
        return nullptr;
    }
    return job;
}

// 挂起创建 -> 进 Job -> 放行。inherit 非空时只把这几个句柄交给子进程。
// stage 回填失败的那一步:三步的错误码含义完全不同,混成一个名字没法查。
bool launch(const QString& exe, const QStringList& args, HANDLE job, STARTUPINFOW* si,
            const std::vector<HANDLE>& inherit, PROCESS_INFORMATION* pi, DWORD* error,
            const char** stage) {
    std::wstring cmd = commandLine(exe, args);
    const std::wstring exePath = native(exe);
    const std::wstring workDir = native(QFileInfo(exe).absolutePath());

    STARTUPINFOEXW six{};
    six.StartupInfo = *si;
    six.StartupInfo.cb = inherit.empty() ? sizeof(STARTUPINFOW) : sizeof(STARTUPINFOEXW);
    std::vector<unsigned char> attrBuf;
    DWORD flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS;
    if (!inherit.empty()) {
        SIZE_T size = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
        attrBuf.resize(size);
        six.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());
        if (!InitializeProcThreadAttributeList(six.lpAttributeList, 1, 0, &size)
            || !UpdateProcThreadAttribute(six.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                          const_cast<HANDLE*>(inherit.data()), inherit.size() * sizeof(HANDLE),
                                          nullptr, nullptr)) {
            *error = GetLastError();
            *stage = "句柄继承清单";
            return false;
        }
        flags |= EXTENDED_STARTUPINFO_PRESENT;
    }
    const BOOL created = CreateProcessW(exePath.c_str(), cmd.data(), nullptr, nullptr, inherit.empty() ? FALSE : TRUE,
                                        flags, nullptr, workDir.c_str(), &six.StartupInfo, pi);
    if (six.lpAttributeList)
        DeleteProcThreadAttributeList(six.lpAttributeList);
    if (!created) {
        *error = GetLastError();
        *stage = "CreateProcess";
        return false;
    }
    if (!AssignProcessToJobObject(job, pi->hProcess)) {
        *error = GetLastError();
        *stage = "AssignProcessToJobObject";
        TerminateProcess(pi->hProcess, 1);
        CloseHandle(pi->hThread);
        CloseHandle(pi->hProcess);
        return false;
    }
    ResumeThread(pi->hThread);
    CloseHandle(pi->hThread);
    pi->hThread = nullptr;
    return true;
}

}

ExitResult runToExit(const QString& exe, const QStringList& args, int timeoutSeconds, int memoryLimitMb,
                     void* cancelEvent) {
    ExitResult r;
    DWORD error = 0;
    HANDLE job = createLimitedJob(memoryLimitMb, &error);
    if (!job) {
        r.error = error;
        return r;
    }
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    const char* stage = "CreateProcess";
    if (!launch(exe, args, job, &si, {}, &pi, &error, &stage)) {
        r.error = error;
        CloseHandle(job);
        return r;
    }
    r.started = true;

    const HANDLE waits[2] = {pi.hProcess, static_cast<HANDLE>(cancelEvent)};
    const DWORD waitMs = static_cast<DWORD>(std::max(10, timeoutSeconds)) * 1000u;
    const DWORD w = WaitForMultipleObjects(cancelEvent ? 2u : 1u, waits, FALSE, waitMs);
    if (w != WAIT_OBJECT_0) {
        r.timedOut = (w == WAIT_TIMEOUT);
        r.cancelled = (w == WAIT_OBJECT_0 + 1);
        TerminateJobObject(job, 1);
        WaitForSingleObject(pi.hProcess, 10000);
    }
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    r.exitCode = code;
    CloseHandle(pi.hProcess);
    CloseHandle(job);
    return r;
}

LineChannel::~LineChannel() { stop(false); }

bool LineChannel::start(const QString& exe, const QStringList& args, int memoryLimitMb, QString* error) {
    stop(false);
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE childIn = nullptr, parentIn = nullptr, parentOut = nullptr, childOut = nullptr;
    if (!CreatePipe(&childIn, &parentIn, &sa, 0)) {
        *error = QStringLiteral("CreatePipe %1").arg(GetLastError());
        return false;
    }
    if (!CreatePipe(&parentOut, &childOut, &sa, 64 * 1024)) {
        *error = QStringLiteral("CreatePipe %1").arg(GetLastError());
        CloseHandle(childIn);
        CloseHandle(parentIn);
        return false;
    }
    SetHandleInformation(parentIn, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(parentOut, HANDLE_FLAG_INHERIT, 0);

    DWORD code = 0;
    HANDLE job = createLimitedJob(memoryLimitMb, &code);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = childIn;
    si.hStdOutput = childOut;
    si.hStdError = nullptr;
    PROCESS_INFORMATION pi{};
    const char* stage = "CreateJobObject";
    const bool ok = job && launch(exe, args, job, &si, {childIn, childOut}, &pi, &code, &stage);
    CloseHandle(childIn);
    CloseHandle(childOut);
    if (!ok) {
        *error = QStringLiteral("%1 %2%3")
                     .arg(QString::fromUtf8(job ? stage : "CreateJobObject"))
                     .arg(code)
                     .arg(code == ERROR_FILE_NOT_FOUND
                              ? QStringLiteral(" —— 辅助程序不在安装目录:%1")
                                    .arg(QDir::toNativeSeparators(exe))
                              : QString());
        CloseHandle(parentIn);
        CloseHandle(parentOut);
        if (job)
            CloseHandle(job);
        return false;
    }
    job_ = job;
    process_ = pi.hProcess;
    in_ = parentIn;
    out_ = parentOut;
    pending_.clear();
    return true;
}

void LineChannel::stop(bool graceful) {
    if (in_) {
        CloseHandle(static_cast<HANDLE>(in_));
        in_ = nullptr;
    }
    if (process_) {
        if (!graceful || WaitForSingleObject(static_cast<HANDLE>(process_), 2000) != WAIT_OBJECT_0) {
            TerminateJobObject(static_cast<HANDLE>(job_), 1);
            WaitForSingleObject(static_cast<HANDLE>(process_), 5000);
        }
        CloseHandle(static_cast<HANDLE>(process_));
        process_ = nullptr;
    }
    if (out_) {
        CloseHandle(static_cast<HANDLE>(out_));
        out_ = nullptr;
    }
    if (job_) {
        CloseHandle(static_cast<HANDLE>(job_));
        job_ = nullptr;
    }
    pending_.clear();
}

bool LineChannel::writeLine(const QByteArray& line) {
    if (!in_)
        return false;
    QByteArray data = line;
    data.append('\n');
    qsizetype done = 0;
    while (done < data.size()) {
        DWORD put = 0;
        if (!WriteFile(static_cast<HANDLE>(in_), data.constData() + done, static_cast<DWORD>(data.size() - done),
                       &put, nullptr)
            || put == 0)
            return false;
        done += put;
    }
    return true;
}

LineChannel::Read LineChannel::readLine(QByteArray* line, int timeoutMs, const std::atomic<bool>& keepGoing) {
    if (!process_)
        return Read::Exited;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    const HANDLE out = static_cast<HANDLE>(out_);
    for (;;) {
        const qsizetype nl = pending_.indexOf('\n');
        if (nl >= 0) {
            *line = pending_.left(nl);
            pending_.remove(0, nl + 1);
            if (line->endsWith('\r'))
                line->chop(1);
            return Read::Line;
        }
        if (pending_.size() > kMaxLineBytes)
            return Read::Exited;

        DWORD avail = 0;
        if (!PeekNamedPipe(out, nullptr, 0, nullptr, &avail, nullptr))
            return Read::Exited;
        if (avail > 0) {
            char buf[8192];
            DWORD got = 0;
            if (!ReadFile(out, buf, std::min<DWORD>(avail, sizeof(buf)), &got, nullptr) || got == 0)
                return Read::Exited;
            pending_.append(buf, static_cast<qsizetype>(got));
            continue;
        }
        if (!keepGoing.load())
            return Read::Cancelled;
        if (std::chrono::steady_clock::now() >= deadline)
            return Read::TimedOut;
        if (WaitForSingleObject(static_cast<HANDLE>(process_), 15) == WAIT_OBJECT_0) {
            if (PeekNamedPipe(out, nullptr, 0, nullptr, &avail, nullptr) && avail > 0)
                continue;
            return Read::Exited;
        }
    }
}

}
