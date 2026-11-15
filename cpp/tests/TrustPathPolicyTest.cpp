#include "bulwark/engine/SystemPaths.h"
#include "bulwark/engine/TrustPolicy.h"
#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/DefenseRule.h"
#include "bulwark/models/SecurityEvent.h"

#include <QString>

#include <cstdio>
#include <optional>

namespace {

int g_fail = 0;
int g_total = 0;

void check(bool ok, const char* what) {
    ++g_total;
    if (!ok) ++g_fail;
    std::printf("  %s %s\n", ok ? "PASS" : "FAIL", what);
}

using bulwark::engine::SystemPaths;
using bulwark::engine::TrustPolicy;

void testSystemVolumeRelative() {
    std::printf("[1] SystemPaths::systemVolumeRelative\n");
    SystemPaths::setSystemDriveForTest(QStringLiteral("C:"));
    check(SystemPaths::systemDrive() == QLatin1String("c:"), "系统盘归一为小写 c:");

    check(SystemPaths::systemVolumeRelative(QStringLiteral("C:\\Windows\\System32\\a.exe"))
              == QLatin1String("\\Windows\\System32\\a.exe"),
          "系统盘路径 -> 卷内部分,保留大小写");
    check(SystemPaths::systemVolumeRelative(QStringLiteral("c:/program files/x/a.exe"))
              == QLatin1String("\\program files\\x\\a.exe"),
          "小写盘符 + 正斜杠 -> 归一为反斜杠");
    check(SystemPaths::systemVolumeRelative(QStringLiteral("\\\\?\\C:\\Windows\\a.exe"))
              == QLatin1String("\\Windows\\a.exe"),
          "\\\\?\\ 前缀 -> 剥掉后判定");
    check(SystemPaths::systemVolumeRelative(QStringLiteral("\\??\\C:\\Windows\\a.exe"))
              == QLatin1String("\\Windows\\a.exe"),
          "\\??\\ 前缀 -> 剥掉后判定");
    check(SystemPaths::systemVolumeRelative(QStringLiteral("E:\\Windows\\System32\\a.exe")).isEmpty(),
          "U 盘 / ISO 上的 E:\\Windows\\System32 -> 空");
    check(SystemPaths::systemVolumeRelative(QStringLiteral("\\\\server\\share\\a.exe")).isEmpty(),
          "UNC 路径 -> 空");
    check(SystemPaths::systemVolumeRelative(QStringLiteral("C:relative.exe")).isEmpty(),
          "盘符相对路径 -> 空");
    check(SystemPaths::systemVolumeRelative(QString()).isEmpty(), "空串 -> 空");
}

bulwark::SecurityEvent signedEvent(const QString& path, const QString& publisher) {
    bulwark::SecurityEvent e;
    e.type = bulwark::EventType::ProcessCreate;
    e.actorPath = path;
    e.actorSigned = true;
    e.actorPublisher = publisher;
    return e;
}

void testTrustDirsRequireSystemVolume() {
    std::printf("[2] 「标准安装目录 / 系统目录」信任只认系统盘\n");

    check(TrustPolicy::isBenignSigner(
              signedEvent(QStringLiteral("C:\\Program Files\\Acme\\a.exe"), QStringLiteral("Acme Widgets Ltd"))).ok,
          "系统盘 Program Files 下的签名程序 -> 良性签名");
    check(!TrustPolicy::isBenignSigner(
              signedEvent(QStringLiteral("E:\\Program Files\\Acme\\a.exe"), QStringLiteral("Acme Widgets Ltd"))).ok,
          "非系统盘的同名目录 -> 不算标准安装目录");

    check(TrustPolicy::isStronglyTrusted(
              signedEvent(QStringLiteral("C:\\Windows\\System32\\svchost.exe"), QStringLiteral("Microsoft Windows"))).ok,
          "微软签名 + 系统盘 System32 -> 强可信");
    check(!TrustPolicy::isStronglyTrusted(
              signedEvent(QStringLiteral("E:\\Windows\\System32\\svchost.exe"), QStringLiteral("Microsoft Windows"))).ok,
          "微软签名 + 非系统盘 System32 -> 不强可信");

    check(TrustPolicy::isTrustedSecurityProduct(
              signedEvent(QStringLiteral("C:\\Program Files\\Windows Defender\\MsMpEng.exe"),
                          QStringLiteral("Microsoft Corporation"))).ok,
          "系统盘上的安全软件 -> 共存放行");
    check(!TrustPolicy::isTrustedSecurityProduct(
              signedEvent(QStringLiteral("E:\\Program Files\\Windows Defender\\MsMpEng.exe"),
                          QStringLiteral("Microsoft Corporation"))).ok,
          "非系统盘上的同名安全软件 -> 不放行");
}

bulwark::DefenseRule allowRule(const QString& actor, std::optional<bulwark::EventType> type,
                               const QString& target) {
    bulwark::ipc::AddRulePayload p;
    p.actorPath = actor;
    p.type = type;
    p.targetPattern = target;
    p.action = bulwark::VerdictAction::Allow;
    return p.toRule();
}

void testAllowRuleGate() {
    std::printf("[3] TrustPolicy::rejectsAllowRule(经控制管道写入的放行规则)\n");
    using bulwark::EventType;
    const auto rejected = [](const bulwark::DefenseRule& r) { return TrustPolicy::rejectsAllowRule(r).ok; };

    check(rejected(allowRule(QStringLiteral("*"), std::nullopt, QString())),
          "任意程序的全部行为 -> 拒绝");
    check(rejected(allowRule(QStringLiteral("*"), EventType::ProcessCreate, QString())),
          "任意程序的整类行为 -> 拒绝");
    check(rejected(allowRule(QStringLiteral("powershell.exe"), std::nullopt, QString())),
          "裸名脚本宿主整体放行 -> 拒绝");
    check(rejected(allowRule(QStringLiteral("C:\\Windows\\System32\\cmd.exe"), EventType::ProcessCreate, QString())),
          "完整路径的 cmd.exe 整类放行 -> 拒绝");
    check(rejected(allowRule(QStringLiteral("C:\\*"), std::nullopt, QString())),
          "整个盘符 -> 拒绝");
    check(rejected(allowRule(QStringLiteral("*\\Windows\\System32\\*"), std::nullopt, QString())),
          "通配写法的 Windows 目录 -> 拒绝");
    check(rejected(allowRule(QStringLiteral("?:\\Windows\\*"), EventType::FileWrite, QString())),
          "?: 写法的 Windows 目录 -> 拒绝");
    check(rejected(allowRule(QStringLiteral("*\\power*.exe"), std::nullopt, QString())),
          "文件名带通配且不限目标 -> 拒绝");

    check(!rejected(allowRule(QStringLiteral("C:\\Tools\\backup.exe"), std::nullopt, QString())),
          "具体程序的整体放行 -> 允许");
    check(!rejected(allowRule(QStringLiteral("C:\\Tools\\*"), EventType::FileWrite, QString())),
          "普通目录的整类放行 -> 允许");
    check(!rejected(allowRule(QStringLiteral("backup.exe"), EventType::FileWrite, QString())),
          "普通程序的裸名放行 -> 允许(界面另有提示)");
    check(!rejected(allowRule(QStringLiteral("powershell.exe"), EventType::FileWrite,
                              QStringLiteral("C:\\Data\\report.csv"))),
          "脚本宿主但限定了具体目标 -> 允许");
    check(!rejected(allowRule(QStringLiteral("*"), EventType::FileWrite, QStringLiteral("C:\\Data\\*.tmp"))),
          "任意程序但限定了目标 -> 允许");

    bulwark::ipc::AddRulePayload block;
    block.actorPath = QStringLiteral("*");
    block.action = bulwark::VerdictAction::Block;
    check(!rejected(block.toRule()), "拦截规则不受这道闸门约束");

    bulwark::DefenseRule pinned = allowRule(QStringLiteral("*"), std::nullopt, QString());
    pinned.actorHashes.insert(QStringLiteral("AA"));
    check(!rejected(pinned), "按哈希锁定主体 -> 允许");
}

}

int main() {
    std::printf("=== trust path policy unit ===\n");
    testSystemVolumeRelative();
    testTrustDirsRequireSystemVolume();
    testAllowRuleGate();
    SystemPaths::setSystemDriveForTest(QString());
    std::printf("%d/%d passed\n", g_total - g_fail, g_total);
    return g_fail == 0 ? 0 : 1;
}
