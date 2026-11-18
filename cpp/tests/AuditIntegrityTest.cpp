#include "IntegrityFixtures.h"
#include "bulwark/engine/ZipIntegrity.h"
#include "bulwark/engine/FileContentClassifier.h"
#include "bulwark/engine/RansomwareBehaviorMonitor.h"
#include "bulwark/service/FileContentProbe.h"
#include "bulwark/service/NativeAuditPolicy.h"
#include "bulwark/service/WmiRepositoryPolicy.h"
#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <QTemporaryDir>
#include <QTimeZone>
#include <cstdio>
using namespace bulwark;
using namespace bulwark::engine;
using namespace bulwark::service;
namespace {
int total=0,failed=0;
void check(bool ok,const char* what){++total;if(!ok){++failed;std::printf("FAIL %s\n",what);}}
QString smb(const QString& address=QStringLiteral("192.168.1.20"),const QString& file=QStringLiteral("doc.txt"),const QString& mask=QStringLiteral("0x2")){
    return QStringLiteral("<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>5145</EventID><EventRecordID>18446744073709551615</EventRecordID><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-11-18T00:00:00.000Z'/><Execution ProcessID='4'/></System><EventData>")
        +QStringLiteral("<Data Name='IpAddress'>%1</Data><Data Name='SubjectUserSid'>S-1-5-21-123</Data><Data Name='SubjectLogonId'>0x1234</Data><Data Name='ShareName'>\\\\*\\Documents</Data><Data Name='ShareLocalPath'>\\??\\C:\\Share</Data><Data Name='RelativeTargetName'>%2</Data><Data Name='AccessMask'>%3</Data></EventData></Event>").arg(address,file,mask);
}
void zipTests(){
    for(const auto& fixture:integrityFixtures){
        const QByteArray bytes=QByteArray::fromBase64(fixture.base64);
        check(static_cast<int>(ZipIntegrity::verify(bytes))==fixture.expected,fixture.name);
    }
    check(ZipIntegrity::verify(QByteArray(16*1024*1024+1,'x'))==FileIntegrity::Unsupported,"archive size budget is enforced before parsing");
    const QByteArray valid=QByteArray::fromBase64(integrityFixtures[0].base64);
    for(int i=0;i<300;++i){
        QByteArray damaged=valid;
        damaged[(i*37)%damaged.size()]^=static_cast<char>(1+(i%255));
        const auto verdict=ZipIntegrity::verify(damaged);
        check(verdict!=FileIntegrity::Unchecked,"mutated metadata stays in bounded parser result domain");
    }
    QTemporaryDir directory;
    check(directory.isValid(),"local probe temporary directory created");
    for(const auto& fixture:integrityFixtures){
        const QString path=directory.path()+QLatin1Char('/')+QString::fromLatin1(fixture.name)+QStringLiteral(".docx");
        QFile file(path);check(file.open(QIODevice::WriteOnly),"fixture file opened");
        file.write(QByteArray::fromBase64(fixture.base64));file.close();
        const auto sample=FileContentProbe::readHead(path);
        check(sample.kind==FileContentSample::Kind::Present && static_cast<int>(sample.integrity)==fixture.expected,"real file probe connects full ZIP verification");
        if(sample.integrity==FileIntegrity::Invalid)
            check(FileContentClassifier::classify(QStringLiteral("report.docx"),sample)==ContentVerdict::Damaged,"corrupt ZIP is damaged, not automatically malware");
    }
    RansomwareBehaviorMonitor monitor;
    monitor.setFileStateProbe([](const QString&){RansomwareBehaviorMonitor::FileState s;s.kind=RansomwareBehaviorMonitor::FileState::Kind::Present;s.createdUtc=QDateTime::fromMSecsSinceEpoch(0,QTimeZone::UTC);return s;});
    monitor.setContentProbe([](const QString&){FileContentSample s;s.kind=FileContentSample::Kind::Present;s.size=100;s.head=QByteArray("PK\x03\x04",4);s.integrity=FileIntegrity::Invalid;return s;});
    RansomwareBehaviorMonitor::Result result;
    for(int i=0;i<4;++i){SecurityEvent e;e.type=EventType::FileWrite;e.actorPid=100;e.actorPath=QStringLiteral("C:\\Lab\\writer.exe");e.actorCreationFileTime=1;e.target=QStringLiteral("C:\\Data\\doc%1.docx").arg(i);e.timestampUtc=QDateTime::fromMSecsSinceEpoch(10000000+i*10000,QTimeZone::UTC);result=monitor.observe(e);}
    check(result.containmentRequired&&!result.hardSignal,"multiple existing corrupt documents require reversible containment without hard conviction");
}
void auditTests(){
    auto e=NativeAuditPolicy::parse(smb());
    check(e&&e->type==EventType::RemoteShareAccess&&e->actorPid==0,"SMB access subject is remote, not System PID");
    check(e&&e->remoteAddress==QStringLiteral("192.168.1.20")&&e->remoteOriginKind==QStringLiteral("access-check"),"SMB access-check provenance retained");
    if(!e)return;
    auto ipv6=NativeAuditPolicy::parse(smb(QStringLiteral("2001:db8::20")));
    check(ipv6&&ipv6->remoteAddress==QStringLiteral("2001:db8::20"),"IPv6 SMB client address parsed");
    auto fail=smb();fail.replace(QStringLiteral("0x8020000000000000"),QStringLiteral("0x8010000000000000"));
    check(!NativeAuditPolicy::parse(fail),"failed access checks are not successful writes");
    check(!NativeAuditPolicy::parse(smb(QStringLiteral("127.0.0.1"))),"loopback is not a remote SMB client");
    check(!NativeAuditPolicy::parse(smb(QStringLiteral("192.168.1.20"),QStringLiteral("../outside.docx"))),"share-relative traversal rejected");
    check(!NativeAuditPolicy::parse(smb(QStringLiteral("192.168.1.20"),QStringLiteral("C:/outside.docx"))),"absolute relative filename rejected");
    check(!NativeAuditPolicy::parse(smb(QStringLiteral("192.168.1.20"),QStringLiteral("doc.txt"),QStringLiteral("0x1"))),"ordinary read-only checks do not count toward write bursts");
    check(NativeAuditPolicy::parse(smb(QStringLiteral("192.168.1.20"),QStringLiteral("doc.txt"),QStringLiteral("0x40000"))).has_value(),"remote permission changes are observed");
    check(NativeAuditPolicy::parse(smb(QStringLiteral("192.168.1.20"),QStringLiteral("folder"),QStringLiteral("0x40"))).has_value(),"remote delete-child requests are observed");
    check(!NativeAuditPolicy::parse(smb(QStringLiteral("192.168.1.20"),QStringLiteral("doc.txt"),QStringLiteral("0x80"))),"attribute-only queries do not become mutation alerts");
    check(NativeAuditPolicy::parse(smb(QStringLiteral("192.168.1.20"),QStringLiteral("u/.ssh/id_rsa"),QStringLiteral("0x1"))).has_value(),"sensitive remote read check is retained without secret content");
    check(!NativeAuditPolicy::parse(smb(QStringLiteral("192.168.1.20"),QStringLiteral("u/.ssh/id_rsa.pub"),QStringLiteral("0x1"))),"public key read is not a remote credential alert");
    auto wrong=smb();wrong.replace(QStringLiteral("Microsoft-Windows-Security-Auditing"),QStringLiteral("FakeProvider"));
    check(!NativeAuditPolicy::parse(wrong),"provider identity is required");
    check(!NativeAuditPolicy::parse(QStringLiteral("<!DOCTYPE x [<!ENTITY a 'boom'>]>")+smb()),"DTD and entity expansion rejected");
    check(!NativeAuditPolicy::parse(QString(65537,QLatin1Char('x'))),"oversized audit payload rejected");
    auto round=SecurityEvent::fromJson(e->toJson());
    check(round.remoteUserSid==e->remoteUserSid&&round.remoteLogonId==e->remoteLogonId&&round.auditRecordId==e->auditRecordId&&round.type==e->type,"remote audit contract round-trips with full record ID precision");
    RemoteShareTracker tracker;int alerts=0;
    for(int i=0;i<50;++i){auto access=*e;access.target=QStringLiteral("C:\\Share\\doc%1.txt").arg(i);access.timestampUtc=e->timestampUtc.addMSecs(i);alerts+=tracker.record(access)?1:0;}
    check(alerts==1,"distinct write-intent burst alerts once per session cooldown");
    SecurityEvent io;io.type=EventType::FileWrite;io.actorPid=4;io.target=QStringLiteral("C:\\Share\\doc0.txt");io.timestampUtc=e->timestampUtc.addMSecs(100);
    tracker.annotate(io);
    check(io.actorPid==4&&io.remoteOriginKind==QStringLiteral("recent-access-candidate"),"candidate association never replaces local process identity");
    auto other=*e;other.remoteAddress=QStringLiteral("192.168.1.21");tracker.record(other);
    auto ambiguous=io;ambiguous.target=e->target;ambiguous.remoteOriginKind.clear();tracker.record(*e);tracker.annotate(ambiguous);
    check(ambiguous.remoteOriginKind==QStringLiteral("ambiguous")&&ambiguous.remoteAddress.isEmpty(),"multiple remote users are reported as ambiguous without retaining an older candidate");
    auto later=io;later.remoteOriginKind.clear();later.remoteAddress.clear();later.timestampUtc=e->timestampUtc.addSecs(10);tracker.annotate(later);
    check(later.remoteOriginKind.isEmpty(),"stale access checks do not attribute later I/O");
    const QString disk=QStringLiteral("<Event><System><Provider Name='Microsoft-Windows-BitLocker-API'/><EventID>776</EventID><TimeCreated SystemTime='2026-11-18T00:00:00Z'/><Execution ProcessID='999'/></System><EventData><Data Name='VolumeName'>C:</Data><Data Name='RecoveryPassword'>DO-NOT-RECORD-THIS</Data></EventData></Event>");
    auto change=NativeAuditPolicy::parse(disk);
    check(change&&change->type==EventType::DiskProtectionChange&&change->actorPid==0&&change->target==QStringLiteral("C:"),"BitLocker API change is independent of command-line and provider PID");
    check(change&&!QJsonDocument(change->toJson()).toJson().contains("DO-NOT-RECORD-THIS"),"recovery material is excluded from event serialization");
    auto backup=disk;backup.replace(QStringLiteral("776"),QStringLiteral("784"));
    check(!NativeAuditPolicy::parse(backup),"routine recovery backup event is not classified as protector mutation");
}
void wmiTests(){
    WmiRepositoryPolicy policy;
    QHash<QString,WmiObjectFingerprint> objects;
    objects.insert(QStringLiteral("__EventFilter.Name=old"),{QStringLiteral("__EventFilter"),QStringLiteral("hash0")});
    auto initial=policy.update(objects,true);
    check(initial.baseline&&initial.events.isEmpty(),"initial WMI inventory does not impersonate a new subscription");
    check(!policy.update({},false).accepted,"incomplete WMI enumeration is rejected");
    check(policy.update(objects,true).events.isEmpty(),"failed enumeration does not wipe previous WMI baseline");
    objects.insert(QStringLiteral("CommandLineEventConsumer.Name=new"),{QStringLiteral("CommandLineEventConsumer"),QStringLiteral("hash1")});
    auto changed=policy.update(objects,true);
    check(changed.events.size()==1&&changed.events.first().actorPid==0,"WMI object created through any API produces a caller-unknown change");
    objects[QStringLiteral("CommandLineEventConsumer.Name=new")].digest=QStringLiteral("hash2");
    check(policy.update(objects,true).events.size()==1,"consumer payload fingerprint changes are detected");
    objects.remove(QStringLiteral("__EventFilter.Name=old"));
    check(policy.update(objects,true).events.isEmpty(),"legitimate subscription cleanup is not reported as new persistence");
    WmiRepositoryPolicy burst;burst.update({},true);QHash<QString,WmiObjectFingerprint> many;
    for(int i=0;i<130;++i)many.insert(QString::number(i),{QStringLiteral("__EventConsumer"),QStringLiteral("hash")});
    int delivered=0;for(int i=0;i<4;++i)delivered+=burst.update(many,true).events.size();
    check(delivered==130,"WMI batches larger than 64 retain their undelivered changes for later polls");
}
}
int main(int argc,char** argv){QCoreApplication app(argc,argv);zipTests();auditTests();wmiTests();std::printf("audit_integrity_unit: %d/%d passed\n",total-failed,total);return failed?1:0;}
