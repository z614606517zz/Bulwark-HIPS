#pragma once

#include <QFileInfo>
#include <QSet>
#include <QString>

#include "bulwark/engine/SystemPaths.h"
#include "bulwark/engine/TrustPolicy.h"
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::service::response_policy {

// 系统盘 \Windows\ 下的会话级关键进程。名字相同但不在那里的是冒充者。
inline bool isSessionCriticalImage(const QString& path)
{
    static const QSet<QString> kNames = {
        QStringLiteral("explorer.exe"),
        QStringLiteral("svchost.exe"),
        QStringLiteral("services.exe"),  QStringLiteral("wininit.exe"),
        QStringLiteral("winlogon.exe"),  QStringLiteral("userinit.exe"),
        QStringLiteral("csrss.exe"),     QStringLiteral("smss.exe"),
        QStringLiteral("lsass.exe"),     QStringLiteral("lsaiso.exe"),
        QStringLiteral("dwm.exe"),
    };
    if (!kNames.contains(QFileInfo(path).fileName().toLower()))
        return false;

    return bulwark::engine::SystemPaths::systemVolumeRelative(path.trimmed().toLower())
        .startsWith(QStringLiteral("\\windows\\"));
}

// 足迹(进程树写出的文件、指向主体的持久化)能否记到这个主体名下。内存扫描的承载方只是载荷所在的
// 进程,不是释放者;会话级关键进程的子孙与写入来自整个会话里的其他程序。这两种情况按主体收足迹,
// 会把用户自己启动的程序写的文件、系统服务注册当成恶意释放物清掉。
inline bool footprintAttributableToActor(const bulwark::SecurityEvent& e)
{
    return !e.isMemoryCarrierFinding() && !isSessionCriticalImage(e.actorPath);
}

// 剥权事件的发起方是系统组件或已安装的安全软件时,照引擎的放行结论记录,不改记为拦截:
// 任务管理器、csrss 打开本产品进程只是在看它,内核剥掉危险权限后打开照常成功。
// 脚本宿主与 LOLBin 不在其列,它们来打开本产品进程要留下拦截记录。
inline bool recordsRightsStripAsAllow(const bulwark::SecurityEvent& e)
{
    using bulwark::engine::TrustPolicy;
    return e.kernelRightsStripped
        && (TrustPolicy::isTrustedOsComponent(e).ok || TrustPolicy::isTrustedSecurityProduct(e).ok);
}

// 诱饵文件被 Windows 搜索或资源管理器打开:建索引、读属性、取缩略图都会带写属性权限打开文件,
// 驱动按写入上报。这两类访问只告警,不结束进程。
inline bool canaryTouchIsAlertOnly(const bulwark::SecurityEvent& e)
{
    const QString name = QFileInfo(e.actorPath).fileName().toLower();
    if (name == QLatin1String("explorer.exe")) {
        return isSessionCriticalImage(e.actorPath) && e.actorSigned && !e.signatureMismatch
            && !e.certRevoked && !e.signedAfterCertExpiry;
    }
    static const QSet<QString> kIndexer = {
        QStringLiteral("searchprotocolhost.exe"),
        QStringLiteral("searchfilterhost.exe"),
        QStringLiteral("searchindexer.exe"),
    };
    return kIndexer.contains(name) && bulwark::engine::TrustPolicy::isMicrosoftSystemImage(e);
}

}
