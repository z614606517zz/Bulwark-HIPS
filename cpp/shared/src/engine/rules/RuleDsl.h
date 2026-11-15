#pragma once
#include <QString>
#include <QStringList>
#include <QVector>
#include <initializer_list>
#include "bulwark/models/DefenseRule.h"

namespace bulwark::engine::rules {

using bulwark::DefenseRule;
using bulwark::EventType;
using bulwark::RegistryOperation;
using bulwark::VerdictAction;

inline constexpr VerdictAction Allow = VerdictAction::Allow;
inline constexpr VerdictAction Ask   = VerdictAction::Ask;
inline constexpr VerdictAction Block = VerdictAction::Block;

inline QString u(const char* s) { return QString::fromUtf8(s); }

class RuleRef {
public:
    explicit RuleRef(DefenseRule& r) : r_(&r) {}

    RuleRef& actor(const char* pattern)  { r_->actorPattern = QString::fromUtf8(pattern); return *this; }
    RuleRef& target(const char* pattern) { r_->targetPattern = QString::fromUtf8(pattern); return *this; }
    RuleRef& cmd(const char* pattern)    { r_->commandLinePattern = QString::fromUtf8(pattern); return *this; }
    RuleRef& parent(const char* pattern) { r_->parentPattern = QString::fromUtf8(pattern); return *this; }

    RuleRef& actor(const QString& pattern)  { r_->actorPattern = pattern; return *this; }
    RuleRef& target(const QString& pattern) { r_->targetPattern = pattern; return *this; }
    RuleRef& cmd(const QString& pattern)    { r_->commandLinePattern = pattern; return *this; }
    RuleRef& parent(const QString& pattern) { r_->parentPattern = pattern; return *this; }

    RuleRef& unsignedOnly()              { r_->requireUnsigned = true; return *this; }
    RuleRef& signedOnly()                { r_->requireSigned = true; return *this; }
    RuleRef& targetUnsignedOnly()        { r_->requireTargetUnsigned = true; return *this; }
    RuleRef& targetSignedOnly()          { r_->requireTargetSigned = true; return *this; }
    RuleRef& hostSignedOnly()            { r_->requireHostSigned = true; return *this; }
    RuleRef& targetBesideActor()         { r_->requireTargetBesideActor = true; return *this; }
    RuleRef& exemptRemovableTarget()     { r_->exemptRemovableTarget = true; return *this; }
    RuleRef& regOp(RegistryOperation op) { r_->requireRegOp = op; return *this; }
    RuleRef& onlySetValue()              { return regOp(RegistryOperation::SetValue); }
    RuleRef& onlyDeleteValue()           { return regOp(RegistryOperation::DeleteValue); }
    RuleRef& onlyDeleteKey()             { return regOp(RegistryOperation::DeleteKey); }
    RuleRef& regDword(quint32 v)         { r_->requireRegDword = v; return *this; }
    RuleRef& exemptOs()                  { r_->exemptTrustedOsComponent = true; return *this; }
    RuleRef& hard()                      { r_->hardOverride = true; return *this; }
    RuleRef& disableDevToolAutoAllow()   { r_->disableDevToolAutoAllow = true; return *this; }
    // 主体多为微软签名的系统程序时必须加:否则 Worker 按「签名健康」把询问静默放行。
    RuleRef& disableSignedAutoAllow()    { r_->disableSignedAutoAllow = true; return *this; }

private:
    DefenseRule* r_;
};

class Segment {
public:
    Segment(QVector<DefenseRule>& out, const char* category);

    // 之后加入的规则一律不享受开发工具自动放行:提权、凭据、远控、驱动这类行为
    // 由 python / node / git 做出来一样危险,而开发工具的身份只是文件名和路径。
    Segment& noDevToolAutoAllow() { noDevToolAutoAllow_ = true; return *this; }

    RuleRef add(EventType type, VerdictAction action, const QString& note);

    RuleRef proc(VerdictAction a, const QString& n)   { return add(EventType::ProcessCreate, a, n); }
    RuleRef reg(VerdictAction a, const QString& n)    { return add(EventType::RegistryWrite, a, n); }
    RuleRef file(VerdictAction a, const QString& n)   { return add(EventType::FileWrite, a, n); }
    RuleRef del(VerdictAction a, const QString& n)    { return add(EventType::FileDelete, a, n); }
    RuleRef image(VerdictAction a, const QString& n)  { return add(EventType::ImageLoad, a, n); }
    RuleRef thread(VerdictAction a, const QString& n) { return add(EventType::RemoteThread, a, n); }
    RuleRef kill(VerdictAction a, const QString& n)   { return add(EventType::ProcessTerminate, a, n); }
    RuleRef net(VerdictAction a, const QString& n)    { return add(EventType::NetworkConnect, a, n); }
    RuleRef dns(VerdictAction a, const QString& n)    { return add(EventType::DnsQuery, a, n); }

    RuleRef proc(VerdictAction a, const char* n)   { return proc(a, u(n)); }
    RuleRef reg(VerdictAction a, const char* n)    { return reg(a, u(n)); }
    RuleRef file(VerdictAction a, const char* n)   { return file(a, u(n)); }
    RuleRef del(VerdictAction a, const char* n)    { return del(a, u(n)); }
    RuleRef image(VerdictAction a, const char* n)  { return image(a, u(n)); }
    RuleRef thread(VerdictAction a, const char* n) { return thread(a, u(n)); }
    RuleRef kill(VerdictAction a, const char* n)   { return kill(a, u(n)); }
    RuleRef net(VerdictAction a, const char* n)    { return net(a, u(n)); }
    RuleRef dns(VerdictAction a, const char* n)    { return dns(a, u(n)); }

private:
    QVector<DefenseRule>& out_;
    QString prefix_;
    bool noDevToolAutoAllow_ = false;
};

// "powershell.exe" -> "*\powershell.exe"
QString exe(const char* imageName);
QStringList exes(std::initializer_list<const char*> imageNames);
// "*\powershell.exe" -> "powershell.exe"
QString imageNameOf(const QString& pattern);

// 能执行任意脚本 / 命令的宿主:命令行就是它的行为。
const QStringList& scriptHosts();
// 被滥用来代理执行、下载或注入的系统自带程序(都带微软签名)。
const QStringList& proxyExecutionBinaries();
const QStringList& officeApps();
const QStringList& documentReaders();
const QStringList& browsers();
// 通用解释器:开发者天天用,不进 scriptHosts 的执行类规则;但它们写自启动、
// UAC 绕过、安全配置这类键时与 PowerShell 无异,已并入 scriptedWriters。
const QStringList& interpreterHosts();
// 「写进注册表 / 文件」时足以说明是脚本或命令在动手的写入者。
const QStringList& scriptedWriters();

// 合法软件几乎从不在这里运行可执行体。
const QStringList& rareExecutionDirs();
// 投递常用、但也有大量正常软件的目录:只配合其它条件使用。
const QStringList& commonDropDirs();

const QStringList& securityProductImages();
const QStringList& securityServiceNames();

void addExecutionRules(QVector<DefenseRule>& out);
void addPersistenceRules(QVector<DefenseRule>& out);
void addPrivilegeEscalationRules(QVector<DefenseRule>& out);
void addDefenseEvasionRules(QVector<DefenseRule>& out);
void addCredentialAccessRules(QVector<DefenseRule>& out);
void addLateralMovementRules(QVector<DefenseRule>& out);
void addCommandAndControlRules(QVector<DefenseRule>& out);
void addImpactRules(QVector<DefenseRule>& out);
void addInjectionAndDriverRules(QVector<DefenseRule>& out);
void addSystemIntegrityRules(QVector<DefenseRule>& out);

}
