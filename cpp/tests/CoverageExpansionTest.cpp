#include "bulwark/engine/CrossEventMonitor.h"
#include "bulwark/engine/FileContentClassifier.h"
#include "bulwark/engine/NetworkEndpoint.h"
#include "bulwark/engine/SensitivePaths.h"
#include "bulwark/engine/RuleEngine.h"
#include "bulwark/engine/DefaultRules.h"
#include "bulwark/service/IpBlockPolicy.h"
#include "bulwark/service/SensitiveDataGuardPolicy.h"
#include <QCoreApplication>
#include <QTimeZone>
#include <cstdio>
using namespace bulwark;
using namespace bulwark::engine;
namespace {
int total=0, failed=0;
void check(bool ok, const char* what) { ++total; if (!ok) { ++failed; std::printf("FAIL %s\n", what); } }
SecurityEvent event(EventType type, int pid=100, qint64 ms=100000) {
    SecurityEvent e;
    e.type=type; e.actorPid=pid; e.actorCreationFileTime=1000+static_cast<quint64>(pid);
    e.actorPath=QStringLiteral("C:\\Lab\\worker.exe"); e.actorUserSid=QStringLiteral("S-1-5-21-1");
    e.timestampUtc=QDateTime::fromMSecsSinceEpoch(ms, QTimeZone::UTC);
    return e;
}
void testEndpoints() {
    auto v6=NetworkEndpoint::parse(QStringLiteral("[2001:db8::1]:443"));
    check(v6 && v6->port==443 && v6->text()==QStringLiteral("[2001:db8::1]:443"), "IPv6 port parsing and display");
    auto bare=NetworkEndpoint::parse(QStringLiteral("2001:db8::443"));
    check(bare && bare->port==0, "bare IPv6 is never split into address plus guessed port");
    auto mapped=NetworkEndpoint::parse(QStringLiteral("[::ffff:8.8.8.8]:53"));
    check(mapped && mapped->text()==QStringLiteral("8.8.8.8:53"), "mapped IPv4 has native policy identity");
    for (const char* text : { "1.2.3.4:evil", "[::1]:65536", "[::1]:", "[::1]evil", "1.2.3.4:443:80", "fe80::1%12" })
        check(!NetworkEndpoint::parse(QString::fromLatin1(text)), "invalid endpoint rejected without broadening to all ports");
    using bulwark::service::isUnsafeToBlanketBlockIp;
    for (const char* text : { "::1", "fe80::1", "fc00::1", "ff02::1", "::ffff:127.0.0.1", "2001:4860:4860::8888", "2606:4700:4700::1111" })
        check(isUnsafeToBlanketBlockIp(QString::fromLatin1(text)), "IPv6 infrastructure is protected from blanket blocking");
    check(!isUnsafeToBlanketBlockIp(QStringLiteral("2607:abcd:1234::5")), "public IPv6 endpoint can be blocked");
    DefenseRule rule;
    rule.type=EventType::NetworkConnect; rule.action=VerdictAction::Block;
    rule.targetPattern=QStringLiteral("[2001:0db8:0:0:0:0:0:1]:443");
    auto connect=event(EventType::NetworkConnect); connect.target=QStringLiteral("[2001:db8::1]:443");
    check(rule.matches(connect), "IPv6 rules match equivalent compressed and expanded addresses");
    connect.target=QStringLiteral("[2001:db8::1]:80");
    check(!rule.matches(connect), "IPv6 numeric matching retains the exact port restriction");
    RuleEngine engine; engine.enableBaseline=false; engine.loadRules({rule});
    connect.target=QStringLiteral("[2001:db8::1]:443");
    check(engine.evaluate(connect).action==VerdictAction::Block, "IPv6 endpoint rule reaches the actual verdict engine");
}
void testSecrets() {
    check(isDeveloperCredential(QStringLiteral("C:/Users/a/.ssh/id_ed25519")), "SSH private key classified");
    check(!isDeveloperCredential(QStringLiteral("C:/Users/a/.ssh/id_ed25519.pub")), "public key excluded");
    check(isDeveloperCredential(QStringLiteral("C:/Users/a/.aws/credentials")), "cloud credential classified");
    check(!isDeveloperCredential(QStringLiteral("C:/Users/a/.aws/credentials-example")), "filename boundary respected");
    const auto entries=bulwark::service::sensitive_data_guard::composeEntries(true, {});
    check(entries.contains(QStringLiteral("\\.pypirc$")), "developer credentials enter kernel policy");
    RuleEngine engine;
    engine.enableBaseline=false;
    engine.loadRules(DefaultRules::build());
    auto read=event(EventType::FileRead);
    read.target=QStringLiteral("C:\\Users\\a\\.ssh\\id_ed25519");
    check(engine.evaluate(read).action==VerdictAction::Ask && read.matchedRuleDisablesSignedAutoAllow,
          "actual rule engine preserves confirmation for private-key reads");
    auto publicRead=event(EventType::FileRead);
    publicRead.target=read.target+QStringLiteral(".pub");
    check(engine.evaluate(publicRead).action==VerdictAction::Allow, "public-key reads do not match private-key rules");
}
void testDamage() {
    CrossEventMonitor monitor;
    CrossEventMonitor::Result result;
    for (int i=0;i<6;++i) {
        auto e=event(EventType::FileWrite,100+i,100000+i*120000);
        e.parentPid=900; e.parentCreationFileTime=9000; e.parentPath=QStringLiteral("C:\\Lab\\controller.exe");
        result=monitor.damage(e,{QStringLiteral("C:\\Data\\victim%1.txt").arg(i)});
    }
    check(result.containment && result.score==55, "slow destruction across cooperating children is contained");
    auto innocent=event(EventType::FileWrite,190,900000);
    innocent.parentPid=900; innocent.parentCreationFileTime=9000; innocent.parentPath=QStringLiteral("C:\\Lab\\controller.exe");
    check(!monitor.damage(innocent,{}).containment, "unrelated non-destructive event does not inherit a sibling's conviction");
    CrossEventMonitor shell;
    for(int i=0;i<6;++i) {
        auto e=event(EventType::FileWrite,400+i,100000+i*120000); e.actorUserSid.clear();
        e.parentPid=900; e.parentCreationFileTime=9000; e.parentPath=QStringLiteral("C:\\Windows\\explorer.exe");
        result=shell.damage(e,{QStringLiteral("C:\\Data\\victim%1.txt").arg(i)});
    }
    check(!result.containment, "unrelated applications launched by Explorer are not a process family");
    CrossEventMonitor restarts;
    for(int i=0;i<6;++i) result=restarts.damage(event(EventType::FileWrite,200+i,100000+i*120000),{QStringLiteral("C:\\Data\\victim%1.txt").arg(i)});
    check(result.containment, "same user and executable remain correlated across process restarts");
    CrossEventMonitor clean;
    for(int i=0;i<10;++i) {
        auto e=event(EventType::FileWrite,300+i,100000+i*120000); e.actorUserSid.clear();
        result=clean.damage(e,{QStringLiteral("C:\\Data\\victim%1.txt").arg(i)});
    }
    check(!result.containment, "unrelated unknown users are not joined by executable path");
    CrossEventMonitor duplicates;
    for(int i=0;i<50;++i) result=duplicates.damage(event(EventType::FileWrite),{QStringLiteral("C:\\Data\\one.txt")});
    check(!result.containment, "repeated edits of one file do not exhaust a distinct-file budget");
    CrossEventMonitor expired;
    for(int i=0;i<6;++i) result=expired.damage(event(EventType::FileWrite,100,100000+i*31*60000),{QStringLiteral("C:\\Data\\victim%1.txt").arg(i)});
    check(!result.containment, "expired damage is not accumulated forever");
    auto blocked=event(EventType::FileWrite); blocked.kernelBlocked=true;
    for(int i=0;i<10;++i) result=clean.damage(blocked,{QString::number(i)});
    check(!result.containment, "prevented operations are never counted as actual damage");
}
void testExfiltration() {
    CrossEventMonitor monitor;
    auto read=event(EventType::FileRead); read.target=QStringLiteral("C:\\Users\\a\\.aws\\credentials");
    check(!monitor.observe(read).containment, "read alone is not exfiltration");
    auto archive=event(EventType::ProcessCreate,101,101000);
    archive.parentPid=100; archive.parentCreationFileTime=1100; archive.parentPath=read.actorPath;
    archive.commandLine=QStringLiteral("7z.exe a archive.zip files");
    check(!monitor.observe(archive).containment, "archive alone does not trigger containment");
    auto connect=event(EventType::NetworkConnect,102,102000);
    connect.parentPid=100; connect.parentCreationFileTime=1100; connect.parentPath=read.actorPath;
    connect.target=QStringLiteral("[2607:abcd:1234::5]:443");
    check(monitor.observe(connect).containment, "read, archive and network chain spans parent and child instances");
    auto local=connect; local.target=QStringLiteral("192.168.1.2:445");
    check(!monitor.observe(local).containment, "LAN backup is not classified as public exfiltration");
    CrossEventMonitor noArchive; noArchive.observe(read);
    check(!noArchive.observe(connect).containment, "reading then connecting without an archive remains allowed");
    auto reused=connect; reused.parentCreationFileTime=9999;
    check(!monitor.observe(reused).containment, "reused parent PID cannot inherit an exfiltration chain");
    CrossEventMonitor denied; read.kernelBlocked=true; denied.observe(read); denied.observe(archive);
    check(!denied.observe(connect).containment, "denied secret read never becomes proof of acquired data");
    auto json=SecurityEvent::fromJson(connect.toJson());
    check(json.actorCreationFileTime==connect.actorCreationFileTime && json.parentCreationFileTime==connect.parentCreationFileTime
        && json.actorUserSid==connect.actorUserSid, "stable process and user identities survive IPC");
}
void testPartialContent() {
    FileContentSample sample; sample.kind=FileContentSample::Kind::Present; sample.size=65536;
    sample.head=QByteArray(4096,'a'); sample.middle=QByteArray(4096,'b'); sample.tail=QByteArray(4096,'c');
    check(FileContentClassifier::classify(QStringLiteral("report.txt"),sample)==ContentVerdict::Recognized, "legitimate multi-range text remains recognized");
    for(int i=0;i<4096;++i) sample.middle[i]=static_cast<char>(i%256);
    check(FileContentClassifier::classify(QStringLiteral("report.txt"),sample)==ContentVerdict::Scrambled, "encrypted middle with preserved text head is detected");
    sample.middle.clear(); sample.head=QByteArray("PK\x03\x04",4)+QByteArray(26,'\0')+QByteArray(4066,'a');
    sample.head[26]=1; sample.tail=QByteArray(4096,'a');
    check(FileContentClassifier::classify(QStringLiteral("report.docx"),sample)!=ContentVerdict::Recognized, "ZIP without valid end structure is not declared intact");
}
}
int main(int argc,char** argv) {
    QCoreApplication app(argc,argv);
    testEndpoints(); testSecrets(); testDamage(); testExfiltration(); testPartialContent();
    std::printf("coverage_expansion_unit: %d/%d passed\n",total-failed,total);
    return failed?1:0;
}
