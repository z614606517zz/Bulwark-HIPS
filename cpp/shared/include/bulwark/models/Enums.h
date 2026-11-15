#pragma once
#include <QString>

namespace bulwark {

enum class EventType {
    ProcessCreate = 0,
    ProcessTerminate,
    RemoteThread,
    ImageLoad,
    FileWrite,
    FileDelete,
    RegistryWrite,
    NetworkConnect,
    SelfProtect,
    DnsQuery,
    ScriptScan,
};

// 注册表操作方向。内核 BlwEventRegistrySetValue/DeleteValue/DeleteKey 三者在用户态
// 统一成 EventType::RegistryWrite,方向靠这个字段保留:删值/删键常常是加固动作,
// 只有「设值」才可能是持久化/削弱防护,规则据此区分而不是一律触发。
enum class RegistryOperation {
    Unknown = 0,   // 事件源未提供(ETW / 用户态行为源),不参与方向过滤
    SetValue,
    DeleteValue,
    DeleteKey,
    // 整棵恢复 / 替换键(RegRestoreKey / RegReplaceKey):一次写下任意值,只认「设值」的规则也要命中它。
    RestoreKey,
};

inline QString registryOperationToString(RegistryOperation op) {
    switch (op) {
        case RegistryOperation::SetValue:     return QStringLiteral("SetValue");
        case RegistryOperation::DeleteValue:  return QStringLiteral("DeleteValue");
        case RegistryOperation::DeleteKey:    return QStringLiteral("DeleteKey");
        case RegistryOperation::RestoreKey:   return QStringLiteral("RestoreKey");
        case RegistryOperation::Unknown:
        default:                              return QStringLiteral("Unknown");
    }
}

inline RegistryOperation registryOperationFromString(const QString& s) {
    if (s == QLatin1String("SetValue"))    return RegistryOperation::SetValue;
    if (s == QLatin1String("DeleteValue")) return RegistryOperation::DeleteValue;
    if (s == QLatin1String("DeleteKey"))   return RegistryOperation::DeleteKey;
    if (s == QLatin1String("RestoreKey"))  return RegistryOperation::RestoreKey;
    return RegistryOperation::Unknown;
}

enum class VerdictAction {
    Allow = 0,
    Block,
    Ask,
};

enum class VerdictSource {
    Rule = 0,
    Heuristic,
    TrustedSigner,
    UserPrompt,
    Timeout,
    DefaultPolicy,
    Ai,  // 只用于显示旧记录(旧版「AI 全权裁决」);新代码不得产生
    SharedIntel,
};

enum class EvidenceKind {
    Info = 0,
    SoftSignal,
    HardIndicator,
    Corroboration,
    Trust,
    Rule,
    Decision,
};

enum class RememberScope {
    Permanent = 0,
    Session,
    OneHour,
    OneDay,
};

enum class ProcessOriginKind {
    Unknown = 0,
    Interactive,
    Service,
    ScheduledTask,
    WmiProvider,
    LogonAutostart,
    SystemBoot,
};

enum class EnforcementOutcome {
    NotApplicable = 0,
    KernelBlocked,
    Terminated,
    ModuleBlacklisted,
    Failed,
    AlertedOnly,
    ExecDenied,
    ActorAlreadyGone,
    WriteUndone,
    PayloadQuarantined,
    // 10 已退役。历史事件记录里可能仍存着这个数值,不得复用。
};

inline QString evidenceKindToString(EvidenceKind k) {
    switch (k) {
        case EvidenceKind::Info:          return QStringLiteral("Info");
        case EvidenceKind::SoftSignal:    return QStringLiteral("SoftSignal");
        case EvidenceKind::HardIndicator: return QStringLiteral("HardIndicator");
        case EvidenceKind::Corroboration: return QStringLiteral("Corroboration");
        case EvidenceKind::Trust:         return QStringLiteral("Trust");
        case EvidenceKind::Rule:          return QStringLiteral("Rule");
        case EvidenceKind::Decision:      return QStringLiteral("Decision");
    }
    return QStringLiteral("Info");
}

inline EvidenceKind evidenceKindFromString(const QString& s) {
    if (s == QLatin1String("SoftSignal"))    return EvidenceKind::SoftSignal;
    if (s == QLatin1String("HardIndicator")) return EvidenceKind::HardIndicator;
    if (s == QLatin1String("Corroboration")) return EvidenceKind::Corroboration;
    if (s == QLatin1String("Trust"))         return EvidenceKind::Trust;
    if (s == QLatin1String("Rule"))          return EvidenceKind::Rule;
    if (s == QLatin1String("Decision"))      return EvidenceKind::Decision;
    return EvidenceKind::Info;
}

inline QString eventTypeToString(EventType t) {
    switch (t) {
        case EventType::ProcessCreate:    return QStringLiteral("ProcessCreate");
        case EventType::ProcessTerminate: return QStringLiteral("ProcessTerminate");
        case EventType::RemoteThread:     return QStringLiteral("RemoteThread");
        case EventType::ImageLoad:        return QStringLiteral("ImageLoad");
        case EventType::FileWrite:        return QStringLiteral("FileWrite");
        case EventType::FileDelete:       return QStringLiteral("FileDelete");
        case EventType::RegistryWrite:    return QStringLiteral("RegistryWrite");
        case EventType::NetworkConnect:   return QStringLiteral("NetworkConnect");
        case EventType::SelfProtect:      return QStringLiteral("SelfProtect");
        case EventType::DnsQuery:         return QStringLiteral("DnsQuery");
        case EventType::ScriptScan:       return QStringLiteral("ScriptScan");
    }
    return QStringLiteral("ProcessCreate");
}

inline QString verdictActionToString(VerdictAction a) {
    switch (a) {
        case VerdictAction::Allow: return QStringLiteral("Allow");
        case VerdictAction::Block: return QStringLiteral("Block");
        case VerdictAction::Ask:   return QStringLiteral("Ask");
    }
    return QStringLiteral("Allow");
}

inline QString verdictSourceToString(VerdictSource s) {
    switch (s) {
        case VerdictSource::Rule:          return QStringLiteral("Rule");
        case VerdictSource::Heuristic:     return QStringLiteral("Heuristic");
        case VerdictSource::TrustedSigner: return QStringLiteral("TrustedSigner");
        case VerdictSource::UserPrompt:    return QStringLiteral("UserPrompt");
        case VerdictSource::Timeout:       return QStringLiteral("Timeout");
        case VerdictSource::DefaultPolicy: return QStringLiteral("DefaultPolicy");
        case VerdictSource::Ai:            return QStringLiteral("Ai");
        case VerdictSource::SharedIntel:   return QStringLiteral("SharedIntel");
    }
    return QStringLiteral("Rule");
}

inline QString processOriginKindToString(ProcessOriginKind k) {
    switch (k) {
        case ProcessOriginKind::Unknown:        return QStringLiteral("Unknown");
        case ProcessOriginKind::Interactive:    return QStringLiteral("Interactive");
        case ProcessOriginKind::Service:        return QStringLiteral("Service");
        case ProcessOriginKind::ScheduledTask:  return QStringLiteral("ScheduledTask");
        case ProcessOriginKind::WmiProvider:    return QStringLiteral("WmiProvider");
        case ProcessOriginKind::LogonAutostart: return QStringLiteral("LogonAutostart");
        case ProcessOriginKind::SystemBoot:     return QStringLiteral("SystemBoot");
    }
    return QStringLiteral("Unknown");
}

inline QString enforcementOutcomeToString(EnforcementOutcome o) {
    switch (o) {
        case EnforcementOutcome::NotApplicable:     return QStringLiteral("NotApplicable");
        case EnforcementOutcome::KernelBlocked:     return QStringLiteral("KernelBlocked");
        case EnforcementOutcome::Terminated:        return QStringLiteral("Terminated");
        case EnforcementOutcome::ModuleBlacklisted: return QStringLiteral("ModuleBlacklisted");
        case EnforcementOutcome::Failed:            return QStringLiteral("Failed");
        case EnforcementOutcome::AlertedOnly:       return QStringLiteral("AlertedOnly");
        case EnforcementOutcome::ExecDenied:        return QStringLiteral("ExecDenied");
        case EnforcementOutcome::ActorAlreadyGone:  return QStringLiteral("ActorAlreadyGone");
        case EnforcementOutcome::WriteUndone:       return QStringLiteral("WriteUndone");
        case EnforcementOutcome::PayloadQuarantined: return QStringLiteral("PayloadQuarantined");
    }
    return QStringLiteral("NotApplicable");
}

}
