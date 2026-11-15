#include "WindowGuardPolicy.h"
#include "bulwark/service/FilelessPolicy.h"
#include "bulwark/service/RemoteThreadDeduplicator.h"
#include "bulwark/service/EventSourceRoutingPolicy.h"
#include "bulwark/service/DurableExecBlockPolicy.h"
#include "bulwark/service/WorkerDurableExecBlockSeam.h"
#include "bulwark/service/SensitiveDataGuardPolicy.h"
#include "bulwark/models/DefenseRule.h"
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/engine/TrustPolicy.h"

#include <QString>
#include <QJsonObject>

#include <cstdio>
#include <functional>
#include <optional>

namespace {

int gChecks = 0;
int gFailed = 0;

void check(bool condition, const char* name)
{
    ++gChecks;
    if (condition)
        return;
    ++gFailed;
    std::fprintf(stderr, "FAIL: %s\n", name);
}

void testWindowPolicy()
{
    using bulwark::ui::window_policy::isCloseAuthorizationFresh;
    using bulwark::ui::window_policy::shouldAllowCloseMessage;
    using bulwark::ui::window_policy::shouldClearHiddenIntent;
    using bulwark::ui::window_policy::shouldRestoreHiddenWindow;

    check(shouldRestoreHiddenWindow(false, false, false),
          "unexpected native hide is restored even when Qt also reports hidden");
    check(!shouldRestoreHiddenWindow(true, false, false),
          "close-to-tray hide remains hidden");
    check(!shouldRestoreHiddenWindow(false, true, false),
          "minimized window is not forced open");
    check(!shouldRestoreHiddenWindow(false, false, true),
          "visible window needs no repair");
    check(shouldClearHiddenIntent(true, false, true),
          "native re-show clears stale close-to-tray intent");
    check(!shouldClearHiddenIntent(true, true, true),
          "minimized window retains hidden intent");

    check(!shouldAllowCloseMessage(false, false),
          "direct external WM_CLOSE is denied without a SC_CLOSE authorization");
    check(shouldAllowCloseMessage(false, true),
          "WM_CLOSE following validated SC_CLOSE authorization is allowed once");
    check(shouldAllowCloseMessage(true, false),
          "explicit application quit token is allowed");
    check(isCloseAuthorizationFresh(true, 20, 500),
          "close-event authorization stays valid for immediate delivery");
    check(!isCloseAuthorizationFresh(false, 0, 500),
          "missing close-event authorization is denied");
    check(!isCloseAuthorizationFresh(true, 501, 500),
          "stale close-event authorization is denied");
}

void testFilelessTargetPolicy()
{
    using bulwark::service::fileless_policy::isHighRiskMemoryScanHost;
    using bulwark::service::fileless_policy::shouldTargetNewProcess;

    const QStringList hosts = {
        QStringLiteral("powershell.exe"), QStringLiteral("PowerShell_ISE.EXE"),
        QStringLiteral("pwsh.exe"),       QStringLiteral("wscript.exe"),
        QStringLiteral("cscript.exe"),    QStringLiteral("mshta.exe"),
        QStringLiteral("rundll32.exe"),   QStringLiteral("regsvr32.exe"),
    };
    for (const QString& host : hosts) {
        check(isHighRiskMemoryScanHost(QStringLiteral("C:\\Windows\\System32\\") + host),
              "script host is targeted regardless of case");
    }

    check(shouldTargetNewProcess(
              QStringLiteral("C:\\Users\\Alice\\AppData\\Local\\Temp\\carrier.exe")),
          "user temp launch is targeted");
    check(shouldTargetNewProcess(QStringLiteral("D:/Users/Alice/Downloads/carrier.exe")),
          "downloads launch is targeted with slash normalization");
    check(shouldTargetNewProcess(QStringLiteral("C:\\Users\\Public\\drop\\carrier.exe")),
          "public user launch is targeted");
    check(!shouldTargetNewProcess(QStringLiteral("C:\\Program Files\\Temp Tools\\helper.exe")),
          "program files path containing Temp is not targeted");
    check(!shouldTargetNewProcess(QStringLiteral("C:\\Windows\\System32\\notpowershell.exe")),
          "host matching is exact by basename");

    using bulwark::service::fileless_policy::scanIsCoolingDown;
    check(!scanIsCoolingDown(true, 2000, 1500,
                             -1, 60000, 5000),
          "normal launch pre-scan never suppresses urgent injection scan");
    check(scanIsCoolingDown(true, 3000, -1,
                            1000, 60000, 5000),
          "urgent injection scans retain a short independent cooldown");
    check(!scanIsCoolingDown(true, 7000, -1,
                             1000, 60000, 5000),
          "urgent cooldown expires at its boundary");
    check(scanIsCoolingDown(false, 2000, 1500,
                            -1, 60000, 5000),
          "normal scans retain the regular cooldown");
}

void testEventRoutingPolicy()
{
    using bulwark::service::event_routing_policy::suppressBaseWhenKernelConnected;
    check(suppressBaseWhenKernelConnected(bulwark::EventType::ProcessCreate),
          "kernel-connected process create duplicate is suppressed");
    check(!suppressBaseWhenKernelConnected(bulwark::EventType::ProcessTerminate),
          "process terminate has no kernel producer, so the ETW audit source stays live");
    check(!suppressBaseWhenKernelConnected(bulwark::EventType::ImageLoad),
          "ETW image-load coverage remains active with driver connected");
    check(!suppressBaseWhenKernelConnected(bulwark::EventType::RemoteThread),
          "ETW remote-thread coverage remains active with driver connected");
}

void testRemoteThreadDeduplication()
{
    using bulwark::service::RemoteThreadDeduplicator;
    using bulwark::service::RemoteThreadSource;

    RemoteThreadDeduplicator dedup;
    const QString key = QStringLiteral("1200|2400");
    check(!dedup.shouldSuppress(key, RemoteThreadSource::Base, 1000),
          "first ETW event is retained");
    check(dedup.shouldSuppress(key, RemoteThreadSource::Driver, 1100),
          "matching driver copy is suppressed");

    check(!dedup.shouldSuppress(key, RemoteThreadSource::Driver, 2000),
          "first driver event is retained");
    check(dedup.shouldSuppress(key, RemoteThreadSource::Base, 2100),
          "matching ETW copy is suppressed");

    check(!dedup.shouldSuppress(key, RemoteThreadSource::Base, 3000),
          "first same-source event is retained");
    check(!dedup.shouldSuppress(key, RemoteThreadSource::Base, 3050),
          "repeated same-source event is retained");
    check(dedup.shouldSuppress(key, RemoteThreadSource::Driver, 3100),
          "first opposite-source event pairs one-to-one");
    check(dedup.shouldSuppress(key, RemoteThreadSource::Driver, 3150),
          "second opposite-source event pairs one-to-one");

    check(!dedup.shouldSuppress(QStringLiteral("1200|2500"), RemoteThreadSource::Driver, 3200),
          "different target is not a duplicate");
    check(!dedup.shouldSuppress(key, RemoteThreadSource::Driver, 7001),
          "expired event is not a duplicate");
}

void testDevToolOverrideSerialization()
{
    bulwark::DefenseRule plain;
    check(!plain.toJson().contains(QStringLiteral("disableDevToolAutoAllow")),
          "typed dev-tool override is omitted when false");
    plain.disableDevToolAutoAllow = true;
    check(bulwark::DefenseRule::fromJson(plain.toJson()).disableDevToolAutoAllow,
          "typed dev-tool override serializes and round-trips");
}

void testDurableExecBlockPolicy()
{
    using bulwark::EventType;
    using bulwark::SecurityEvent;
    using bulwark::service::DurableExecBlockDecision;
    using bulwark::service::DurableExecBlockOrigin;
    using bulwark::service::DurableExecBlockPolicy;
    using ProcessInstance =
        bulwark::service::monitoring::ProcessInspector::ProcessInstance;

    SecurityEvent event;
    event.type = EventType::ProcessCreate;
    event.actorPid = 4242;
    event.actorCreationFileTime = 123456789ULL;
    event.actorPath = QStringLiteral("C:/Users/Alice/Temp/sample.exe");
    ProcessInstance current{4242, 123456789ULL,
                            QStringLiteral("c:\\users\\alice\\temp\\sample.exe")};

    for (DurableExecBlockOrigin origin : { DurableExecBlockOrigin::Enforcement,
                                           DurableExecBlockOrigin::LaunchingParent,
                                           DurableExecBlockOrigin::MaliciousSweep }) {
        const auto allowed = DurableExecBlockPolicy::evaluate(true, event, current, origin);
        check(allowed.decision == DurableExecBlockDecision::Allowed
                  && allowed.authorization.has_value()
                  && allowed.authorization->origin() == origin,
              "each durable writer origin receives only policy-minted authorization");
    }
    check(DurableExecBlockPolicy::evaluate(false, event, current).decision
              == DurableExecBlockDecision::NotRequested,
          "durable block rejects an absent request");
    SecurityEvent wrong = event;
    wrong.type = EventType::FileWrite;
    check(DurableExecBlockPolicy::evaluate(true, wrong, current).decision
              == DurableExecBlockDecision::WrongEventType,
          "durable block rejects a non-ProcessCreate event");
    SecurityEvent lowPid = event;
    lowPid.actorPid = 4;
    check(DurableExecBlockPolicy::evaluate(true, lowPid, current).decision
              == DurableExecBlockDecision::InvalidPid,
          "durable block rejects PID four and below");
    check(DurableExecBlockPolicy::evaluate(true, event, std::nullopt).decision
              == DurableExecBlockDecision::PidAbsent,
          "durable block rejects absent or unreadable current identity");
    SecurityEvent noObservedTime = event;
    noObservedTime.actorCreationFileTime.reset();
    check(DurableExecBlockPolicy::evaluate(true, noObservedTime, current).decision
              == DurableExecBlockDecision::ObservedIdentityUnavailable,
          "durable block rejects unavailable observed identity");
    ProcessInstance unusable{4242, 0, QString()};
    check(DurableExecBlockPolicy::evaluate(true, event, unusable).decision
              == DurableExecBlockDecision::CurrentIdentityUnavailable,
          "durable block rejects unusable current identity");
    ProcessInstance wrongPid = current;
    wrongPid.pid = 4343;
    check(DurableExecBlockPolicy::evaluate(true, event, wrongPid).decision
              == DurableExecBlockDecision::PidMismatch,
          "durable block rejects current PID mismatch");
    ProcessInstance reused = current;
    reused.creationFileTime++;
    check(DurableExecBlockPolicy::evaluate(true, event, reused).decision
              == DurableExecBlockDecision::CreationTimeMismatch,
          "durable block rejects same PID and image with different creation time");
    ProcessInstance wrongImage = current;
    wrongImage.imagePath = QStringLiteral("C:\\Users\\Alice\\Temp\\other.exe");
    check(DurableExecBlockPolicy::evaluate(true, event, wrongImage).decision
              == DurableExecBlockDecision::ImageMismatch,
          "durable block rejects image mismatch");

    using Execution = bulwark::service::DurableExecBlockExecution;
    using PersistFn = DurableExecBlockPolicy::PersistFn;
    using ContainFn = DurableExecBlockPolicy::ContainFn;
    using RunWorkerSource = std::function<Execution(
        const std::optional<ProcessInstance>&, const PersistFn&, const ContainFn&)>;

    const auto exerciseWorkerSource = [&](const RunWorkerSource& run,
                                          DurableExecBlockOrigin expectedOrigin,
                                          bulwark::service::DurableExecBlockEffectOrder order,
                                          int containmentPid) {
        const auto invoke = [&](const std::optional<ProcessInstance>& instance,
                                int& blockExecWrites,
                                int& denyAceWrites,
                                int& containmentCalls,
                                QString& authorizedPath,
                                QStringList& sequence) {
            return run(
                instance,
                [&](const bulwark::service::DurableExecBlockAuthorization& authorization) {
                    sequence << QStringLiteral("persist");
                    ++blockExecWrites;
                    ++denyAceWrites;
                    authorizedPath = authorization.imagePath();
                    return authorization.origin() == expectedOrigin;
                },
                [&](int pid) {
                    sequence << QStringLiteral("contain");
                    ++containmentCalls;
                    return pid == containmentPid;
                });
        };

        int blockExecWrites = 0;
        int denyAceWrites = 0;
        int containmentCalls = 0;
        QString authorizedPath;
        QStringList sequence;
        const auto allowed = invoke(current, blockExecWrites, denyAceWrites,
                                    containmentCalls, authorizedPath, sequence);
        check(allowed.evaluation.decision == DurableExecBlockDecision::Allowed
                  && allowed.persistenceSucceeded && allowed.containmentSucceeded,
              "actual Worker source seam authorizes persistence and retains containment");
        check(blockExecWrites == 1 && denyAceWrites == 1 && containmentCalls == 1,
              "actual Worker source seam performs each authorized effect exactly once");
        check(authorizedPath == QStringLiteral("c:\\users\\alice\\temp\\sample.exe"),
              "actual Worker source seam writes the normalized authorized image");
        const QStringList expectedOrder = order
                == bulwark::service::DurableExecBlockEffectOrder::PersistThenContain
            ? QStringList{QStringLiteral("persist"), QStringLiteral("contain")}
            : QStringList{QStringLiteral("contain"), QStringLiteral("persist")};
        check(sequence == expectedOrder,
              "actual Worker source seam preserves its production side-effect order");

        blockExecWrites = 0;
        denyAceWrites = 0;
        containmentCalls = 0;
        authorizedPath.clear();
        sequence.clear();
        const auto unavailable = invoke(std::nullopt, blockExecWrites, denyAceWrites,
                                        containmentCalls, authorizedPath, sequence);
        check(unavailable.evaluation.decision == DurableExecBlockDecision::PidAbsent
                  && !unavailable.persistenceAttempted,
              "actual Worker source seam rejects an unprovable process identity");
        check(blockExecWrites == 0 && denyAceWrites == 0 && containmentCalls == 1
                  && unavailable.containmentSucceeded,
              "unprovable identity writes no durable state and still contains");

        blockExecWrites = 0;
        denyAceWrites = 0;
        containmentCalls = 0;
        authorizedPath.clear();
        sequence.clear();
        ProcessInstance reusedInstance = current;
        ++reusedInstance.creationFileTime;
        const auto reusedDenied = invoke(reusedInstance, blockExecWrites, denyAceWrites,
                                         containmentCalls, authorizedPath, sequence);
        check(reusedDenied.evaluation.decision == DurableExecBlockDecision::CreationTimeMismatch
                  && !reusedDenied.persistenceAttempted,
              "actual Worker source seam rejects PID reuse with a different FILETIME");
        check(blockExecWrites == 0 && denyAceWrites == 0 && containmentCalls == 1
                  && reusedDenied.containmentSucceeded,
              "PID reuse writes no durable state and still contains");
    };

    exerciseWorkerSource(
        [&](const std::optional<ProcessInstance>& instance,
            const PersistFn& persist, const ContainFn& contain) {
            return bulwark::service::WorkerDurableExecBlockSeam::fromEnforceBlock(
                event, instance, 5252,
                persist, contain);
        },
        DurableExecBlockOrigin::Enforcement,
        bulwark::service::DurableExecBlockEffectOrder::PersistThenContain,
        5252);
    exerciseWorkerSource(
        [&](const std::optional<ProcessInstance>& instance,
            const PersistFn& persist, const ContainFn& contain) {
            return bulwark::service::WorkerDurableExecBlockSeam::fromLaunchingParent(
                event, instance, persist, contain);
        },
        DurableExecBlockOrigin::LaunchingParent,
        bulwark::service::DurableExecBlockEffectOrder::ContainThenPersist,
        event.actorPid);
    exerciseWorkerSource(
        [&](const std::optional<ProcessInstance>& instance,
            const PersistFn& persist, const ContainFn& contain) {
            return bulwark::service::WorkerDurableExecBlockSeam::fromSweptMalicious(
                event, instance, persist, contain);
        },
        DurableExecBlockOrigin::MaliciousSweep,
        bulwark::service::DurableExecBlockEffectOrder::ContainThenPersist,
        event.actorPid);

    const QStringList authoritative = {
        QStringLiteral("\\blocked\\trusted.exe"),
        QStringLiteral("\\blocked\\keep.exe"),
        QStringLiteral("\\blocked\\keep.exe"),
    };
    const auto replay = DurableExecBlockPolicy::planAuthoritativeReplay(
        authoritative, {QStringLiteral("\\blocked\\trusted.exe")});
    check(replay.drop == QStringList{QStringLiteral("\\blocked\\trusted.exe")},
          "trust reconciliation drops only an authoritative entry that blocks trust");
    check(replay.keep == QStringList({QStringLiteral("\\blocked\\keep.exe"),
                                      QStringLiteral("\\blocked\\keep.exe")}),
          "trust reconciliation preserves authoritative order and multiplicity");
    bool replayIsAuthoritative = true;
    for (const QString& entry : replay.keep)
        replayIsAuthoritative = replayIsAuthoritative && authoritative.contains(entry);
    check(replayIsAuthoritative
              && !replay.keep.contains(QStringLiteral("\\event-derived\\new.exe")),
          "trust reconciliation cannot manufacture an event-derived replay entry");
}

void testAuditCorrelationSerialization()
{
    bulwark::SecurityEvent event;
    event.correlationId = QStringLiteral("11111111-2222-3333-4444-555555555555");
    const QJsonObject encoded = event.toJson();
    check(encoded.value(QStringLiteral("correlationId")).toString() == event.correlationId,
          "non-empty correlation identifier serializes for RunId-scoped evidence");
    const bulwark::SecurityEvent decoded = bulwark::SecurityEvent::fromJson(encoded);
    check(decoded.correlationId == event.correlationId,
          "correlation identifier round-trips through SecurityEvent JSON");

    event.correlationId.clear();
    check(!event.toJson().contains(QStringLiteral("correlationId")),
          "ordinary production events omit an empty correlation identifier");
}

void testRuleSubjectSpecificity()
{
    using bulwark::DefenseRule;
    using bulwark::EventType;
    using bulwark::VerdictAction;

    {
        DefenseRule r;
        r.actorHashes.insert(QStringLiteral(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        check(r.identifiesSubject(), "hash-only rule identifies its subject");
    }
    {
        DefenseRule r;
        r.actorPath = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\dropper.exe");
        check(r.identifiesSubject(), "exact actorPath identifies its subject");
    }
    {
        DefenseRule r;
        r.actorPattern = QStringLiteral("C:\\ProgramData\\x\\payload.exe");
        check(r.identifiesSubject(), "wildcard-free actorPattern identifies its subject");
    }

    {
        DefenseRule r;
        r.type = EventType::ProcessCreate;
        r.commandLinePattern = QStringLiteral("*-executionpolicy*bypass*");
        r.action = VerdictAction::Ask;
        check(!r.identifiesSubject(),
              "command-line-only rule does NOT identify its subject");
    }
    {
        DefenseRule r;
        r.actorPattern = QStringLiteral("*\\evil.exe");
        check(!r.identifiesSubject(),
              "wildcarded actorPattern does NOT identify its subject");
    }
    {
        DefenseRule usage;
        usage.type = EventType::ProcessCreate;
        usage.actorPattern = QStringLiteral("*\\powershell.exe");
        usage.commandLinePattern = QStringLiteral("*-executionpolicy*bypass*");
        usage.parentPattern = QStringLiteral("*\\explorer.exe");
        usage.targetPattern = QStringLiteral("*");

        DefenseRule byHash;
        byHash.type = EventType::ProcessCreate;
        byHash.actorHashes.insert(QStringLiteral(
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));

        check(usage.specificityScore() >= byHash.specificityScore(),
              "a usage rule can score as specific as a hash rule (why specificityScore "
              "must not gate escalation)");
        check(!usage.identifiesSubject() && byHash.identifiesSubject(),
              "identifiesSubject separates usage rules from subject-pinning rules");
    }
}

void testWholeProcessTrustRejection()
{
    using bulwark::engine::TrustPolicy;
    const auto rejects = [](const char* p, bool dir) {
        return TrustPolicy::rejectsWholeProcessTrust(QString::fromUtf8(p), dir).ok;
    };
    check(rejects("C:\\WINDOWS\\System32\\cmd.exe", false), "whole-process trust of cmd.exe is rejected");
    check(rejects("c:/windows/system32/WindowsPowerShell/v1.0/powershell.exe", false),
          "whole-process trust of powershell.exe is rejected regardless of case and separators");
    check(rejects("C:\\Windows\\System32\\rundll32.exe", false), "whole-process trust of rundll32.exe is rejected");
    check(rejects("C:\\Windows\\System32\\certutil.exe", false), "whole-process trust of certutil.exe is rejected");
    check(rejects("C:\\Windows\\System32\\mshta.exe", false), "whole-process trust of mshta.exe is rejected");
    check(!rejects("C:\\Program Files\\Vendor\\app.exe", false), "ordinary program trust is still accepted");
    check(!rejects("C:\\Tools\\notcmd.exe", false), "name match is exact, not substring");
    check(rejects("C:\\", true), "trusting a drive root is rejected");
    check(rejects("C:\\Windows\\System32", true), "trusting the Windows directory tree is rejected");
    check(rejects("C:\\Windows\\System32\\*", true), "stored wildcard form of the Windows tree is rejected");
    check(!rejects("D:\\Games\\MyGame", true), "ordinary folder trust is still accepted");
    check(!rejects("C:\\WindowsApps\\x", true), "folder anchoring does not match a mere name prefix");
}

void testRemovableTargetExemption()
{
    bulwark::DefenseRule r;
    r.type = bulwark::EventType::FileWrite;
    r.targetPattern = QStringLiteral("\\\\.\\physicaldrive*");
    r.action = bulwark::VerdictAction::Block;
    r.exemptRemovableTarget = true;

    bulwark::SecurityEvent e;
    e.type = bulwark::EventType::FileWrite;
    e.actorPath = QStringLiteral("C:\\Tools\\imager.exe");
    e.target = QStringLiteral("\\\\.\\PhysicalDrive1");
    check(r.matches(e), "raw write to a fixed disk still matches a removable-exempt rule");
    e.targetOnRemovableMedia = true;
    check(!r.matches(e), "raw write to a USB / SD disk is exempt");

    const bulwark::DefenseRule back = bulwark::DefenseRule::fromJson(r.toJson());
    check(back.exemptRemovableTarget, "exemptRemovableTarget survives a JSON round trip");
    r.exemptRemovableTarget = false;
    check(r.matches(e), "rules without the exemption still match removable targets");
}

void testSensitiveDataReaders()
{
    const QStringList entries = bulwark::service::sensitive_data_guard::composeEntries(true, {});
    const auto allows = [&entries](const char* data, const char* reader) {
        for (const QString& e : entries)
            if (e.startsWith(QString::fromUtf8(data), Qt::CaseInsensitive)
                && e.contains(QString::fromUtf8(reader), Qt::CaseInsensitive))
                return true;
        return false;
    };
    check(allows("\\Mozilla\\Firefox\\Profiles\\", "\\Mozilla Firefox\\"), "Firefox reads its own profiles");
    check(allows("\\Mozilla\\Firefox\\Profiles\\", "\\Firefox Developer Edition\\"),
          "Firefox Developer Edition shares Firefox\\Profiles and may read it");
    check(allows("\\Mozilla\\Firefox\\Profiles\\", "\\Firefox Nightly\\"),
          "Firefox Nightly shares Firefox\\Profiles and may read it");
    check(allows("\\Thunderbird\\Profiles\\", "\\Betterbird\\"),
          "Betterbird shares Thunderbird\\Profiles and may read it");
}

}

int main()
{
    testWindowPolicy();
    testWholeProcessTrustRejection();
    testRuleSubjectSpecificity();
    testFilelessTargetPolicy();
    testEventRoutingPolicy();
    testRemoteThreadDeduplication();
    testDevToolOverrideSerialization();
    testDurableExecBlockPolicy();
    testAuditCorrelationSerialization();
    testRemovableTargetExemption();
    testSensitiveDataReaders();
    std::printf("%d checks, %d failed\n", gChecks, gFailed);
    return gFailed == 0 ? 0 : 1;
}
