#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/DefenseRule.h"
#include "bulwark/models/Enums.h"

#include <QString>
#include <cstdio>

using bulwark::SecurityEvent;
using bulwark::DefenseRule;
using bulwark::EventType;
using bulwark::VerdictAction;

static int g_failures = 0;

static void expect(bool cond, const char* what) {
    if (!cond) {
        ++g_failures;
        std::fprintf(stderr, "[FAIL] %s\n", what);
    }
}

static SecurityEvent carrierFinding(const QString& image, int pid) {
    SecurityEvent e;
    e.type = EventType::RemoteThread;
    e.actorPid = pid;
    e.actorPath = image;
    e.target = QStringLiteral("PID %1 %2 · 进程内存中存在可写且可执行的私有内存(RWX)")
                   .arg(pid).arg(QStringLiteral("powershell.exe"));
    e.userModeObserved = true;
    e.memoryInjection = true;
    return e;
}

static SecurityEvent attributedInjection(const QString& injector, const QString& victim) {
    SecurityEvent e;
    e.type = EventType::RemoteThread;
    e.actorPid = 4321;
    e.actorPath = injector;
    e.target = victim;
    e.userModeObserved = false;
    e.memoryInjection = false;
    return e;
}

static DefenseRule actorAttributionRule(const QString& actorPattern) {
    DefenseRule r;
    r.type = EventType::RemoteThread;
    r.actorPattern = actorPattern;
    r.action = VerdictAction::Block;
    r.hardOverride = true;
    r.note = QStringLiteral("[内置] 脚本宿主发起跨进程远程线程注入(T1055)");
    return r;
}

static DefenseRule carrierRule(const QString& targetPattern) {
    DefenseRule r;
    r.type = EventType::RemoteThread;
    r.targetPattern = targetPattern;
    r.action = VerdictAction::Ask;
    r.note = QStringLiteral("[内置] 承载进程内存中存在可写可执行私有内存(写入方未知,T1055)");
    return r;
}

int main() {
    const QString ps = QStringLiteral("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");

    expect(carrierFinding(ps, 18324).isMemoryCarrierFinding(),
           "FilelessGuard 形态必须被识别为承载方发现");
    expect(!attributedInjection(ps, QStringLiteral("C:\\Windows\\System32\\lsass.exe"))
                .isMemoryCarrierFinding(),
           "已归因的真实注入不得被识别为承载方发现");
    {
        SecurityEvent e = carrierFinding(ps, 18324);
        e.memoryInjection = false;
        expect(!e.isMemoryCarrierFinding(), "缺 memoryInjection 不应判为承载方");
    }
    {
        SecurityEvent e = carrierFinding(ps, 18324);
        e.userModeObserved = false;
        expect(!e.isMemoryCarrierFinding(), "缺 userModeObserved 不应判为承载方(内核归因的真实注入)");
    }
    {
        SecurityEvent e = carrierFinding(ps, 18324);
        e.target = QStringLiteral("C:\\Windows\\System32\\lsass.exe");
        expect(!e.isMemoryCarrierFinding(), "target 是映像路径时不应判为承载方");
    }

    {
        const DefenseRule r = actorAttributionRule(QStringLiteral("*\\powershell.exe"));
        const SecurityEvent carrier = carrierFinding(ps, 18324);
        expect(!r.matches(carrier),
               "承载方发现【绝不能】命中按发起方归因的注入规则 —— 这正是三次事故的根因");
        const SecurityEvent real = attributedInjection(ps, QStringLiteral("C:\\Windows\\System32\\lsass.exe"));
        expect(r.matches(real),
               "真实的跨进程注入必须【仍然】命中该规则(修复不得牺牲检出)");
    }

    {
        const DefenseRule r = carrierRule(QStringLiteral("*可写且可执行的私有内存*"));
        const SecurityEvent carrier = carrierFinding(ps, 18324);
        expect(r.matches(carrier),
               "承载方规则必须仍然命中承载方发现 —— 否则无文件检测整块失效");
    }

    {
        DefenseRule r;
        r.type = EventType::ProcessCreate;
        r.actorPattern = QStringLiteral("*\\powershell.exe");
        r.action = VerdictAction::Block;
        SecurityEvent e = carrierFinding(ps, 18324);
        e.type = EventType::ProcessCreate;
        expect(r.matches(e), "非 RemoteThread 规则的匹配行为不得被本次改动影响");
    }
    {
        DefenseRule r;
        r.actorPattern = QStringLiteral("*\\powershell.exe");
        r.action = VerdictAction::Block;
        expect(r.matches(carrierFinding(ps, 18324)),
               "未限定事件类型的规则不受本次改动影响(闸只针对显式 RemoteThread 规则)");
    }

    if (g_failures == 0) {
        std::printf("memory_carrier_attribution_unit: all checks passed\n");
        return 0;
    }
    std::fprintf(stderr, "memory_carrier_attribution_unit: %d check(s) FAILED\n", g_failures);
    return 1;
}
