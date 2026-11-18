#include "bulwark/service/NativeAuditPolicy.h"
#include "bulwark/engine/NetworkEndpoint.h"
#include "bulwark/engine/SensitivePaths.h"
#include <QDir>
#include <QMutexLocker>
#include <QSet>
#include <QXmlStreamReader>
#include <algorithm>

namespace bulwark::service {
namespace {
QString normalized(QString value) {
    value.replace(QLatin1Char('\\'),QLatin1Char('/'));
    return QDir::cleanPath(value).toLower();
}
QString remoteKey(const bulwark::SecurityEvent& e) {
    return e.remoteAddress+QLatin1Char('|')+e.remoteUserSid+QLatin1Char('|')+e.remoteLogonId;
}
}
std::optional<bulwark::SecurityEvent> NativeAuditPolicy::parse(const QString& text) {
    using namespace bulwark;
    if (text.size()>65536) return {};
    QXmlStreamReader xml(text);
    xml.setEntityExpansionLimit(1024);
    QString provider,record,keywords,time;
    int id=0;
    QHash<QString,QString> fields;
    const QSet<QString> permitted = { "IpAddress","IpPort","SubjectUserSid","SubjectLogonId",
        "ShareName","ShareLocalPath","RelativeTargetName","AccessMask","VolumeName","Volume",
        "VolumeGuid","DriveLetter" };
    while (!xml.atEnd()) {
        xml.readNext();
        if (xml.isDTD() || xml.isEntityReference()) return {};
        if (!xml.isStartElement()) continue;
        const auto name=xml.name();
        if (name==QLatin1String("Provider")) provider=xml.attributes().value(QLatin1String("Name")).toString();
        else if (name==QLatin1String("EventID")) id=xml.readElementText().toInt();
        else if (name==QLatin1String("EventRecordID")) record=xml.readElementText().left(32);
        else if (name==QLatin1String("Keywords")) keywords=xml.readElementText();
        else if (name==QLatin1String("TimeCreated")) time=xml.attributes().value(QLatin1String("SystemTime")).toString();
        else if (name==QLatin1String("Data")) {
            const QString key=xml.attributes().value(QLatin1String("Name")).toString();
            if (permitted.contains(key)) fields.insert(key,xml.readElementText().left(2048));
        }
    }
    if (xml.hasError()) return {};
    SecurityEvent e;
    e.userModeObserved=true;
    e.auditRecordId=record;
    const auto stamp=QDateTime::fromString(time,Qt::ISODateWithMs);
    if (!stamp.isValid()) return {};
    e.timestampUtc=stamp.toUTC();
    if (provider==QLatin1String("Microsoft-Windows-Security-Auditing") && id==5145) {
        bool ok=false;
        const quint64 flags=keywords.toULongLong(&ok,0);
        if (!ok || !(flags&0x0020000000000000ULL) || (flags&0x0010000000000000ULL)) return {};
        const uint mask=fields.value(QStringLiteral("AccessMask")).toUInt(&ok,0);
        if (!ok) return {};
        auto endpoint=engine::NetworkEndpoint::parse(fields.value(QStringLiteral("IpAddress")));
        if (!endpoint || endpoint->address.isLoopback() || endpoint->address.isNull() || endpoint->address.isMulticast()) return {};
        QString root=fields.value(QStringLiteral("ShareLocalPath"));
        root.replace(QLatin1Char('/'),QLatin1Char('\\'));
        if (root.startsWith(QLatin1String("\\??\\"))) root=root.mid(4);
        if (root.size()<3 || !root.at(0).isLetter() || root.at(1)!=QLatin1Char(':') || root.at(2)!=QLatin1Char('\\')) return {};
        QString relative=fields.value(QStringLiteral("RelativeTargetName"));
        relative.replace(QLatin1Char('\\'),QLatin1Char('/'));
        if (relative.isEmpty() || relative.startsWith(QLatin1Char('/')) || relative.contains(QLatin1Char(':'))
            || relative.split(QLatin1Char('/')).contains(QStringLiteral(".."))) return {};
        const QString target=normalized(root+QLatin1Char('\\')+relative);
        const QString base=normalized(root);
        if (!target.startsWith(base.endsWith(QLatin1Char('/')) ? base : base+QLatin1Char('/'))) return {};
        if (!(mask&remoteMutationAccess) && !((mask&1U) && engine::isDeveloperCredential(target))) return {};
        const QString sid=fields.value(QStringLiteral("SubjectUserSid")),logon=fields.value(QStringLiteral("SubjectLogonId"));
        if (!sid.startsWith(QLatin1String("S-1-")) || logon.isEmpty()) return {};
        e.type=EventType::RemoteShareAccess;
        e.remoteAddress=endpoint->host(); e.remoteUserSid=sid; e.remoteLogonId=logon;
        e.remoteShare=fields.value(QStringLiteral("ShareName")).left(512);
        e.remoteOriginKind=QStringLiteral("access-check"); e.auditAccessMask=mask;
        e.actorPath=QStringLiteral("SMB client %1").arg(e.remoteAddress);
        e.target=QDir::toNativeSeparators(target);
        e.detail=QStringLiteral("Security 5145：远端用户通过共享访问检查，未证明实际读写已经发生；不将服务器 System 当作远端发起者");
        return e;
    }
    if (provider==QLatin1String("Microsoft-Windows-BitLocker-API")) {
        static const QHash<int,QString> actions = {
            {768,QStringLiteral("开始加密")},{769,QStringLiteral("计划重启后加密")},
            {770,QStringLiteral("开始解密")},{771,QStringLiteral("停止加密")},
            {772,QStringLiteral("恢复加密")},{773,QStringLiteral("暂停保护")},
            {775,QStringLiteral("新增密钥保护器")},{776,QStringLiteral("删除密钥保护器")}
        };
        if (!actions.contains(id)) return {};
        e.type=EventType::DiskProtectionChange;
        e.actorPath=QStringLiteral("BitLocker API (caller unknown)");
        e.target=fields.value(QStringLiteral("VolumeName"),fields.value(QStringLiteral("Volume"),
            fields.value(QStringLiteral("VolumeGuid"),fields.value(QStringLiteral("DriveLetter"),QStringLiteral("volume unknown"))))).left(512);
        e.auditOperation=actions.value(id);
        e.detail=QStringLiteral("BitLocker API 事件 %1：%2；属于变更后观测，不表示操作已被前置阻止，未推断调用方 PID")
            .arg(id).arg(e.auditOperation);
        return e;
    }
    return {};
}
void RemoteShareTracker::prune(qint64 now) {
    for (auto it=paths_.begin();it!=paths_.end();) {
        auto& list=it.value();
        list.erase(std::remove_if(list.begin(),list.end(),[now](const Access& a) {
            const qint64 elapsed=a.event.timestampUtc.toMSecsSinceEpoch();
            return elapsed>now || now-elapsed>5000;
        }),list.end());
        if (list.isEmpty()) it=paths_.erase(it); else ++it;
    }
    for (auto it=bursts_.begin();it!=bursts_.end();)
        if (now<it->last || now-it->last>60000) it=bursts_.erase(it); else ++it;
    if (paths_.size()>=4096) paths_.clear();
    if (bursts_.size()>=1024) bursts_.clear();
}
bool RemoteShareTracker::record(const bulwark::SecurityEvent& e) {
    using namespace bulwark;
    if (e.type!=EventType::RemoteShareAccess || e.remoteOriginKind!=QLatin1String("access-check")) return false;
    const qint64 now=e.timestampUtc.toMSecsSinceEpoch();
    QMutexLocker lock(&mutex_); prune(now);
    auto& accesses=paths_[normalized(e.target)];
    const QString key=remoteKey(e);
    accesses.erase(std::remove_if(accesses.begin(),accesses.end(),[&](const Access& a) { return remoteKey(a.event)==key; }),accesses.end());
    if (accesses.size()<16) accesses.push_back({e});
    if (!(e.auditAccessMask&remoteMutationAccess)) return true; // sensitive-read access check
    Burst& burst=bursts_[key]; burst.last=now;
    for (auto it=burst.files.begin();it!=burst.files.end();)
        if (now<it.value() || now-it.value()>30000) it=burst.files.erase(it); else ++it;
    if (burst.files.size()<512) burst.files.insert(normalized(e.target),now);
    if (burst.files.size()<40 || (burst.alerted>=0 && now-burst.alerted<60000)) return false;
    burst.alerted=now; return true;
}
void RemoteShareTracker::annotate(bulwark::SecurityEvent& e) {
    using namespace bulwark;
    if (e.actorPid>4 || e.kernelBlocked || (e.type!=EventType::FileWrite && e.type!=EventType::FileDelete)) return;
    e.remoteAddress.clear();e.remoteUserSid.clear();e.remoteLogonId.clear();e.remoteShare.clear();e.remoteOriginKind.clear();
    const qint64 now=e.timestampUtc.toMSecsSinceEpoch();
    QMutexLocker lock(&mutex_); prune(now);
    const auto list=paths_.value(normalized(e.target));
    if (list.isEmpty()) return;
    QHash<QString,SecurityEvent> candidates;
    for (const auto& a:list) if ((a.event.auditAccessMask&remoteMutationAccess)
        && a.event.timestampUtc.msecsTo(e.timestampUtc)>=0 && a.event.timestampUtc.msecsTo(e.timestampUtc)<=2000)
        candidates.insert(remoteKey(a.event),a.event);
    if (candidates.isEmpty()) return;
    if (candidates.size()!=1) {
        e.remoteOriginKind=QStringLiteral("ambiguous");
        e.addEvidence(QStringLiteral("SMB audit"),EvidenceKind::Info,QStringLiteral("同一文件存在多个近期远端访问者，无法确定本次写入来自谁"),0,false);
        return;
    }
    const auto candidate=candidates.constBegin().value();
    e.remoteAddress=candidate.remoteAddress; e.remoteUserSid=candidate.remoteUserSid;
    e.remoteLogonId=candidate.remoteLogonId; e.remoteShare=candidate.remoteShare;
    e.remoteOriginKind=QStringLiteral("recent-access-candidate");
    e.addEvidence(QStringLiteral("SMB audit"),EvidenceKind::Info,
        QStringLiteral("同路径近期唯一的共享访问检查来自 %1，用户 SID %2；仅为关联候选，未改变本地进程身份").arg(e.remoteAddress,e.remoteUserSid),0,false);
}
}
