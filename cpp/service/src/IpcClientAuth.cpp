#include "bulwark/service/IpcClientAuth.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/monitoring/ProcessInspector.h"

#include <QDir>
#include <QFileInfo>
#include <QMutex>
#include <QMutexLocker>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace bulwark::service {

namespace {

Logger& log() { static Logger l(QStringLiteral("IpcAuth")); return l; }

QMutex& gate() { static QMutex m; return m; }

IpcClientAuth::Policy& policy() {
    static IpcClientAuth::Policy p;
    return p;
}

QString normPath(const QString& p) {
    QString s = p.trimmed();
    s.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return s.toLower();
}

QString normThumbprint(const QString& t) {
    QString s;
    s.reserve(t.size());
    for (const QChar c : t) {
        if (c == QLatin1Char(' ') || c == QLatin1Char(':') || c == QLatin1Char('-'))
            continue;
        s.append(c.toUpper());
    }
    return s;
}

quint32 clientPidOf(qintptr socketDescriptor) {
    if (socketDescriptor == -1 || socketDescriptor == 0)
        return 0;
    ULONG pid = 0;
    if (!::GetNamedPipeClientProcessId(reinterpret_cast<HANDLE>(socketDescriptor), &pid))
        return 0;
    return static_cast<quint32>(pid);
}

QString imagePathOf(quint32 pid) {
    if (pid == 0)
        return QString();
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (h == nullptr)
        return QString();
    wchar_t buf[MAX_PATH * 2] = {};
    DWORD sz = static_cast<DWORD>(sizeof(buf) / sizeof(buf[0]));
    QString out;
    if (::QueryFullProcessImageNameW(h, 0, buf, &sz))
        out = QString::fromWCharArray(buf, static_cast<int>(sz));
    ::CloseHandle(h);
    return out;
}

bool isElevatedAdministrator(quint32 pid, QString* reason) {
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                   static_cast<DWORD>(pid));
    if (process == nullptr) {
        if (reason) *reason = QStringLiteral("无法打开客户端进程令牌");
        return false;
    }
    HANDLE token = nullptr;
    const BOOL tokenOk = ::OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &token);
    ::CloseHandle(process);
    if (!tokenOk) {
        if (reason) *reason = QStringLiteral("无法读取客户端进程令牌");
        return false;
    }

    TOKEN_ELEVATION elevation{};
    DWORD got = 0;
    const bool elevated = ::GetTokenInformation(token, TokenElevation, &elevation,
                                                 sizeof(elevation), &got) != FALSE
        && elevation.TokenIsElevated != 0;

    BYTE sidBuffer[SECURITY_MAX_SID_SIZE] = {};
    DWORD sidSize = sizeof(sidBuffer);
    BOOL isAdmin = FALSE;
    HANDLE impersonation = nullptr;
    const bool haveAdminSid = ::CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr,
                                                    sidBuffer, &sidSize) != FALSE;
    const bool duplicated = ::DuplicateToken(token, SecurityIdentification, &impersonation) != FALSE;
    if (haveAdminSid && duplicated)
        ::CheckTokenMembership(impersonation, sidBuffer, &isAdmin);
    if (impersonation)
        ::CloseHandle(impersonation);
    ::CloseHandle(token);

    if (!elevated || !isAdmin) {
        if (reason) {
            *reason = QStringLiteral("客户端不是已提升的 Administrators 进程(UAC elevation=%1,admin=%2)")
                          .arg(elevated ? 1 : 0).arg(isAdmin ? 1 : 0);
        }
        return false;
    }
    return true;
}

}

void IpcClientAuth::configure(const Policy& p) {
    QMutexLocker lk(&gate());
    Policy norm;

    norm.installDir = normPath(p.installDir);
    if (!norm.installDir.isEmpty() && !norm.installDir.endsWith(QLatin1Char('\\')))
        norm.installDir += QLatin1Char('\\');

    for (const QString& n : p.allowedImageNames) {
        const QString t = n.trimmed().toLower();
        if (!t.isEmpty())
            norm.allowedImageNames << t;
    }
    if (norm.allowedImageNames.isEmpty())
        norm.allowedImageNames << QStringLiteral("bulwark_ui.exe");

    norm.requireElevatedAdministrator = p.requireElevatedAdministrator;
    norm.enforceSignature = p.enforceSignature;
    for (const QString& t : p.allowedThumbprints) {
        const QString v = normThumbprint(t);
        if (!v.isEmpty())
            norm.allowedThumbprints << v;
    }
    for (const QString& s : p.allowedPublishers) {
        const QString v = s.trimmed();
        if (!v.isEmpty())
            norm.allowedPublishers << v;
    }

    policy() = norm;

    if (norm.installDir.isEmpty()) {
        log().error(QStringLiteral(
            "控制管道认证:安装目录为空,将拒绝所有客户端连接。这是配置/接线错误,请检查 configure 调用。"));
    } else {
        log().info(QStringLiteral("控制管道认证已启用:%1").arg(policySummary()));
    }
}

QString IpcClientAuth::policySummary() {
    const Policy& p = policy();
    QString s = QStringLiteral("会话准入=仅交互会话(SessionId>0);强制层=映像须位于「%1」且文件名属于 {%2}")
                    .arg(p.installDir.isEmpty() ? QStringLiteral("(未设置)") : p.installDir,
                         p.allowedImageNames.join(QStringLiteral(", ")));
    s += p.requireElevatedAdministrator
        ? QStringLiteral(";操作者授权=仅已提升 Administrators")
        : QStringLiteral(";操作者授权=未要求提升");
    if (!p.enforceSignature) {
        s += QStringLiteral(";签名加固=关(当前构建的 UI 未做代码签名)");
    } else {
        s += QStringLiteral(";签名加固=开");
        if (!p.allowedThumbprints.isEmpty())
            s += QStringLiteral("(指纹白名单 %1 条)").arg(p.allowedThumbprints.size());
        else if (!p.allowedPublishers.isEmpty())
            s += QStringLiteral("(发布者白名单 %1 条)").arg(p.allowedPublishers.size());
        else
            s += QStringLiteral("(仅要求签名有效)");
    }
    return s;
}

IpcClientAuth::Result IpcClientAuth::authenticate(qintptr socketDescriptor) {
    Result r;

    Policy p;
    {
        QMutexLocker lk(&gate());
        p = policy();
    }

    r.pid = clientPidOf(socketDescriptor);
    if (r.pid == 0) {
        r.reason = QStringLiteral("无法确定连接方进程(GetNamedPipeClientProcessId 失败,错误 %1)")
                       .arg(::GetLastError());
        return r;
    }

    DWORD sessionId = 0;
    if (::ProcessIdToSessionId(static_cast<DWORD>(r.pid), &sessionId))
        r.sessionId = static_cast<int>(sessionId);
    if (r.sessionId <= 0) {
        r.reason = QStringLiteral("连接方位于非交互 Session 0 或无法确定 Windows 会话(PID %1,会话 %2)。"
                                  "桌面 UI 不得以 LocalSystem 身份连接控制管道")
                       .arg(r.pid).arg(r.sessionId);
        return r;
    }

    if (p.requireElevatedAdministrator) {
        QString why;
        if (!isElevatedAdministrator(r.pid, &why)) {
            r.reason = QStringLiteral("操作者授权失败(PID %1):%2").arg(r.pid).arg(why);
            return r;
        }
    }

    r.imagePath = imagePathOf(r.pid);
    if (r.imagePath.trimmed().isEmpty()) {
        r.reason = QStringLiteral("无法解析连接方 PID %1 的映像路径(进程已退出或权限不足)").arg(r.pid);
        return r;
    }

    if (p.installDir.isEmpty()) {
        r.reason = QStringLiteral("服务未配置安装目录,认证无法进行(拒绝)");
        return r;
    }
    const QString lower = normPath(r.imagePath);
    if (!lower.startsWith(p.installDir)) {
        r.reason = QStringLiteral("连接方不在本产品安装目录内(PID %1:%2)").arg(r.pid).arg(r.imagePath);
        return r;
    }
    const QString name = QFileInfo(lower).fileName();
    if (!p.allowedImageNames.contains(name)) {
        r.reason = QStringLiteral("连接方映像名不在允许清单内(PID %1:%2)").arg(r.pid).arg(name);
        return r;
    }

    if (p.enforceSignature) {
        using monitoring::ProcessInspector;
        if (!ProcessInspector::isSigned(r.imagePath)) {
            r.reason = QStringLiteral("已开启签名加固,但连接方无可信数字签名(PID %1:%2)")
                           .arg(r.pid).arg(r.imagePath);
            return r;
        }
        const bool haveAllowlist = !p.allowedThumbprints.isEmpty() || !p.allowedPublishers.isEmpty();
        if (haveAllowlist) {
            bool hit = false;
            if (!p.allowedThumbprints.isEmpty()) {
                const QString tp = normThumbprint(ProcessInspector::getCertInfo(r.imagePath).thumbprint);
                hit = !tp.isEmpty() && p.allowedThumbprints.contains(tp);
            }
            if (!hit && !p.allowedPublishers.isEmpty()) {
                const QString pub = ProcessInspector::tryGetPublisher(r.imagePath);
                if (!pub.isEmpty()) {
                    for (const QString& allowed : p.allowedPublishers) {
                        if (pub.trimmed().compare(allowed.trimmed(), Qt::CaseInsensitive) == 0) { hit = true; break; }
                    }
                }
            }
            if (!hit) {
                r.reason = QStringLiteral("连接方签名不在指纹/发布者白名单内(PID %1:%2)")
                               .arg(r.pid).arg(r.imagePath);
                return r;
            }
        }
    }

    r.ok = true;
    r.reason = QStringLiteral("PID %1 · 会话 %2 · %3")
                   .arg(r.pid)
                   .arg(r.sessionId)
                   .arg(QFileInfo(r.imagePath).fileName());
    return r;
}

}
