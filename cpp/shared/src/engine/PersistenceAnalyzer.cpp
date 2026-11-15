#include "bulwark/engine/PersistenceAnalyzer.h"
#include "bulwark/engine/AttackAnnotator.h"
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/engine/ThreatDetector.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"

#include <algorithm>

namespace bulwark::engine {

using detail::u;

namespace {

QString categoryLabel(bulwark::PersistenceCategory c) {
    using C = bulwark::PersistenceCategory;
    switch (c) {
        case C::RegistryRun:     return u("注册表 Run 键");
        case C::RegistryRunOnce: return u("注册表 RunOnce 键");
        case C::StartupFolder:   return u("启动文件夹");
        case C::ScheduledTask:   return u("计划任务");
        case C::Service:         return u("Windows 服务");
        case C::WmiSubscription: return u("WMI 事件订阅");
        case C::IfeoDebugger:    return u("映像劫持");
        case C::Winlogon:        return u("Winlogon");
        case C::AppInitDll:      return u("AppInit_DLLs");
        default:                 return u("其它");
    }
}

// 合法软件的自启动项几乎都指向安装目录;指向这些目录的多半是投递后的驻留。
bool pointsIntoStagingDir(const QString& path) {
    QString p = path.toLower();
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    for (const char* d : { "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\", "\\$recycle.bin\\",
                           "\\perflogs\\" })
        if (p.contains(QLatin1String(d)))
            return true;
    return false;
}

}

QString PersistenceAnalyzer::techniqueFor(bulwark::PersistenceCategory c) {
    using C = bulwark::PersistenceCategory;
    switch (c) {
        case C::RegistryRun:
        case C::RegistryRunOnce:
        case C::StartupFolder:   return QStringLiteral("T1547.001");
        case C::ScheduledTask:   return QStringLiteral("T1053.005");
        case C::Service:         return QStringLiteral("T1543.003");
        case C::WmiSubscription: return QStringLiteral("T1546.003");
        case C::IfeoDebugger:    return QStringLiteral("T1546.012");
        case C::Winlogon:        return QStringLiteral("T1547.004");
        case C::AppInitDll:      return QStringLiteral("T1546.010");
        default:                 return QString();
    }
}

void PersistenceAnalyzer::analyze(bulwark::PersistenceEntry& entry) {
    using C = bulwark::PersistenceCategory;

    // 自启动项到点就会被拉起:按「这条命令被启动」来评,签名、伪装、命令行判据都能复用。
    bulwark::SecurityEvent synthetic;
    synthetic.type = bulwark::EventType::ProcessCreate;
    synthetic.actorPath = entry.imagePath.isEmpty() ? entry.command : entry.imagePath;
    synthetic.commandLine = entry.command;
    synthetic.actorSigned = entry.isSigned.value_or(false);
    synthetic.actorPublisher = entry.publisher;
    synthetic.target = entry.location;
    ThreatDetector::analyze(synthetic);

    int score = synthetic.riskScore;
    QStringList reasons = synthetic.riskReasons;

    const QString tech = techniqueFor(entry.category);
    if (!tech.isEmpty()) {
        const QString where = u("%1自启动持久化(%2)").arg(categoryLabel(entry.category), tech);
        reasons.append(where);
        synthetic.addEvidence(QStringLiteral("PersistenceAnalyzer"), bulwark::EvidenceKind::Info, where, 0, false);
    }

    switch (entry.category) {
        case C::IfeoDebugger:
            score += 25;
            reasons.append(u("映像劫持调试器:目标程序一启动就先运行它,几乎没有正当用途"));
            break;
        case C::WmiSubscription:
            score += 20;
            reasons.append(u("WMI 事件订阅:无文件驻留,在任务计划和启动项里都看不到"));
            break;
        case C::AppInitDll:
            score += 20;
            reasons.append(u("AppInit_DLLs:注入每一个加载 user32 的进程"));
            break;
        default:
            break;
    }
    if (pointsIntoStagingDir(synthetic.actorPath) || pointsIntoStagingDir(entry.command)) {
        score += 20;
        reasons.append(u("自启动项指向临时 / 公共目录(投递后的驻留形态)"));
    }

    entry.riskScore = std::min(100, score);
    entry.riskReasons = reasons;

    AttackAnnotator::annotate(synthetic);
    entry.techniques = synthetic.techniques;
}

}
