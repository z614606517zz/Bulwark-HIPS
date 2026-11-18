#include "bulwark/engine/DefaultRules.h"
#include "bulwark/engine/FileContentClassifier.h"
#include "bulwark/engine/RuleEngine.h"
#include "bulwark/engine/SystemPaths.h"
#include "bulwark/engine/TrustPolicy.h"
#include "bulwark/models/DefenseRule.h"
#include <QDateTime>
#include <cstdio>

using namespace bulwark;
using namespace bulwark::engine;

namespace {
int checks = 0;
int failures = 0;
void check(bool ok, const char* label) {
    ++checks;
    if (!ok) { ++failures; std::fprintf(stderr, "FAIL: %s\n", label); }
}

SecurityEvent makeEvent(EventType type, const QString& actor, const QString& command = {}) {
    SecurityEvent e;
    e.type = type;
    e.actorPid = 5100;
    e.actorCreationFileTime = 111;
    e.actorPath = actor;
    e.commandLine = command;
    return e;
}

void sign(SecurityEvent& e, const QString& publisher = QStringLiteral("Microsoft Corporation")) {
    e.actorSigned = true;
    e.actorPublisher = publisher;
}

Verdict evaluate(SecurityEvent& e, const QVector<DefenseRule>& extra = {}) {
    RuleEngine engine;
    engine.enableBaseline = false;
    QVector<DefenseRule> rules = DefaultRules::build();
    rules += extra;
    engine.loadRules(rules);
    return engine.evaluate(e);
}

void testTrustCannotOverrideDenies() {
    SecurityEvent e = makeEvent(EventType::NetworkConnect,
        QStringLiteral("C:\\Program Files\\Tencent\\QQ\\QQ.exe"));
    sign(e, QStringLiteral("Tencent Technology (Shenzhen) Company Limited"));
    e.target = QStringLiteral("203.0.113.8:443");
    DefenseRule deny;
    deny.type = e.type;
    deny.actorPath = e.actorPath;
    deny.targetPattern = e.target;
    deny.action = VerdictAction::Block;
    deny.hardOverride = true;
    deny.note = QStringLiteral("test: explicit endpoint deny");
    check(evaluate(e, {deny}).action == VerdictAction::Block,
          "vendor network trust cannot override an explicit endpoint deny");

    SecurityEvent security = makeEvent(EventType::ProcessCreate,
        QStringLiteral("C:\\Program Files\\Audit\\avp.exe"));
    sign(security, QStringLiteral("Unrelated Publisher"));
    check(!TrustPolicy::isTrustedSecurityProduct(security).ok,
          "security-product identity rejects unrelated certificate publishers");
    security.actorPublisher = QStringLiteral("AO Kaspersky Lab");
    check(TrustPolicy::isTrustedSecurityProduct(security).ok,
          "genuine installed security-product identity remains recognized");
    security.actorHash = QString(64, QLatin1Char('A'));
    DefenseRule hashDeny;
    hashDeny.actorHashes.insert(security.actorHash);
    hashDeny.action = VerdictAction::Block;
    hashDeny.note = QStringLiteral("test: explicit malicious hash");
    check(evaluate(security, {hashDeny}).action == VerdictAction::Block,
          "even a matching security publisher cannot override malicious hashes");

    for (EventType type : { EventType::FileWrite, EventType::FileDelete, EventType::ImageLoad }) {
        SecurityEvent writer = makeEvent(type, QStringLiteral("C:\\Lab\\untrusted.exe"));
        writer.target = QStringLiteral("C:\\Data\\trusted.dll");
        DefenseRule trust = DefenseRule::createTrust(writer.target, QStringLiteral("test target trust"));
        DefenseRule block;
        block.type = type;
        block.targetPattern = writer.target;
        block.action = VerdictAction::Block;
        block.hardOverride = true;
        block.note = QStringLiteral("test: deny unrelated actor");
        check(evaluate(writer, {trust, block}).action == VerdictAction::Block,
              "trusting a target does not authorize an unrelated writer/deleter/loader");
    }
}

void testAdministrativeReadAndWriteDirections() {
    const QString ps = QStringLiteral("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    const QString reg = QStringLiteral("C:\\Windows\\System32\\reg.exe");
    const QString at = QStringLiteral("C:\\Windows\\System32\\at.exe");
    const struct Example { QString actor; QString command; VerdictAction expected; } examples[] = {
        {ps, QStringLiteral("powershell.exe -NoProfile -Command Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer"), VerdictAction::Allow},
        {ps, QStringLiteral("powershell.exe -NoProfile -Command Get-WmiObject -Namespace root/subscription -Class ActiveScriptEventConsumer"), VerdictAction::Allow},
        {reg, QStringLiteral("reg.exe query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /v Debugger"), VerdictAction::Allow},
        {at, QStringLiteral("C:\\Windows\\System32\\at.exe /?"), VerdictAction::Allow},
        {at, QStringLiteral("at.exe 12:30 cmd /c whoami"), VerdictAction::Block},
        {ps, QStringLiteral("powershell.exe -Command New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer"), VerdictAction::Block},
        {reg, QStringLiteral("reg.exe add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /v Debugger /d cmd.exe"), VerdictAction::Block},
    };
    for (const Example& sample : examples) {
        SecurityEvent e = makeEvent(EventType::ProcessCreate, sample.actor, sample.command);
        sign(e);
        check(evaluate(e).action == sample.expected,
              "administrative queries stay quiet while actual dangerous mutations remain blocked");
    }
}

void testSignedDestructionAndProcessIdentity() {
    for (const bool signedActor : {false, true}) {
        RuleEngine engine;
        engine.enableBaseline = false;
        engine.trustSignedActors = false;
        engine.loadRules(DefaultRules::build());
        int contained = 0;
        for (int i = 0; i < 40; ++i) {
            SecurityEvent e = makeEvent(EventType::FileDelete, QStringLiteral("C:\\Lab\\writer.exe"));
            e.target = QStringLiteral("C:\\Data\\docs\\file_%1.txt").arg(i);
            if (signedActor) sign(e, QStringLiteral("Audit Publisher"));
            const Verdict v = engine.evaluate(e);
            if (v.action != VerdictAction::Allow && e.ransomwareContainmentRequired) ++contained;
        }
        check(contained >= 16, "signed and unsigned destructive actors remain contained after the threshold");
    }
    RuleEngine engine;
    engine.enableBaseline = false;
    for (int i = 0; i < 3; ++i) {
        SecurityEvent e = makeEvent(EventType::FileWrite, QStringLiteral("C:\\Lab\\writer.exe"));
        e.target = QStringLiteral("C:\\Data\\victim_%1.locked").arg(i);
        engine.evaluate(e);
    }
    SecurityEvent replacement = makeEvent(EventType::FileWrite, QStringLiteral("C:\\Lab\\writer.exe"));
    replacement.actorCreationFileTime = 222;
    replacement.target = QStringLiteral("C:\\Data\\ordinary.txt");
    check(engine.evaluate(replacement).action == VerdictAction::Allow,
          "PID reuse with a new creation time never inherits a prior conviction");

    RansomwareBehaviorMonitor network;
    bool sharedContained = false;
    for (int i = 0; i < 25; ++i) {
        SecurityEvent e = makeEvent(EventType::FileDelete, QStringLiteral("C:\\Lab\\writer.exe"));
        e.target = QStringLiteral("\\\\server\\share\\doc_%1.txt").arg(i);
        sharedContained = network.observe(e).containmentRequired || sharedContained;
    }
    check(sharedContained, "UNC user-document paths participate in destruction accounting");
}

void testNewCoverageAndContainerChecks() {
    SecurityEvent driver = makeEvent(EventType::ImageLoad, QStringLiteral("kernel"));
    driver.actorPid = 0;
    driver.target = QStringLiteral("C:\\Program Files\\Audit\\RTCore64.sys");
    driver.targetSigned = true;
    check(evaluate(driver).action == VerdictAction::Ask,
          "known vulnerable signed drivers are not silently allowed in Program Files");
    SecurityEvent subscription = makeEvent(EventType::WmiSubscription,
        QStringLiteral("C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"));
    sign(subscription);
    check(evaluate(subscription).action == VerdictAction::Ask
              && subscription.matchedRuleDisablesSignedAutoAllow,
          "WMI API subscription telemetry retains confirmation for signed clients");
    check(SecurityEvent::fromJson(subscription.toJson()).type == EventType::WmiSubscription,
          "WMI event type round-trips through the event contract");
    DefenseRule wmiRule;
    wmiRule.type = EventType::WmiSubscription;
    check(DefenseRule::fromJson(wmiRule.toJson()).type == EventType::WmiSubscription,
          "WMI rule type round-trips through the rule contract");

    const QString manager = QStringLiteral("C:\\Windows\\System32\\manage-bde.exe");
    for (const QString& command : {QStringLiteral("manage-bde.exe -on C:"),
                                   QStringLiteral("manage-bde.exe -protectors -delete C:")}) {
        SecurityEvent e = makeEvent(EventType::ProcessCreate, manager, command);
        sign(e);
        check(evaluate(e).action == VerdictAction::Ask && e.matchedRuleDisablesSignedAutoAllow,
              "native encryption and recovery-key changes require confirmation");
    }
    SecurityEvent status = makeEvent(EventType::ProcessCreate, manager,
                                    QStringLiteral("manage-bde.exe -status C:"));
    sign(status);
    check(evaluate(status).action == VerdictAction::Allow, "BitLocker status queries are not mutations");

    FileContentSample invalid;
    invalid.kind = FileContentSample::Kind::Present;
    invalid.size = 65536;
    invalid.head = QByteArray("PK\x03\x04", 4) + QByteArray(4092, '\x93');
    check(FileContentClassifier::classify(QStringLiteral("report.docx"), invalid)
              != ContentVerdict::Recognized,
          "impossible ZIP header lengths cannot clear destruction evidence");
}
} // namespace

int main() {
    SystemPaths::setSystemDriveForTest(QStringLiteral("c:"));
    testTrustCannotOverrideDenies();
    testAdministrativeReadAndWriteDirections();
    testSignedDestructionAndProcessIdentity();
    testNewCoverageAndContainerChecks();
    std::printf("rule_hardening_unit: %d/%d passed\n", checks - failures, checks);
    return failures == 0 ? 0 : 1;
}
