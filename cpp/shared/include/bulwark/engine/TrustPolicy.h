#pragma once
#include <QString>
#include <QStringList>
#include "bulwark/models/SecurityEvent.h"

namespace bulwark {
struct DefenseRule;
}

namespace bulwark::engine {

struct TrustDecision {
    bool ok = false;
    QString reason;
};

struct TrustPolicy {
    static TrustDecision isTrustedSecurityProduct(const bulwark::SecurityEvent& e);
    static TrustDecision isTrustedVendorApp(const bulwark::SecurityEvent& e);
    static TrustDecision isStronglyTrusted(const bulwark::SecurityEvent& e);
    static TrustDecision isHealthySigned(const bulwark::SecurityEvent& e);
    static TrustDecision isBenignSigner(const bulwark::SecurityEvent& e);
    static TrustDecision isTrustedOsComponent(const bulwark::SecurityEvent& e);
    static TrustDecision isTrusted(const bulwark::SecurityEvent& e);

    static TrustDecision rejectsWholeProcessTrust(const QString& path, bool isDirectory);

    // 替请求方创建进程、并把父进程设成请求方的系统代办(UAC 提权、runas、WER,服务 / WMI / 计划任务宿主)。
    // 进程创建事件里真实创建者与父进程不同,只有创建者是它们时才不算伪造父进程。
    static bool isProcessCreationBroker(const QString& creatorPath);

    // 签名健康、发行方是微软且位于系统目录的映像。只看身份不看行为,用来决定要不要做文件内容扫描;
    // 不能当放行依据(放行还要看命令行与进程链,见 isStronglyTrusted)。
    static bool isMicrosoftSystemImage(const bulwark::SecurityEvent& e);

    // 放行规则写入的服务端闸门。目标为空(放行该主体的整类行为)时,主体必须能通过
    // rejectsWholeProcessTrust,且不能只有通配符;限定了具体目标的例外不受限制。
    static TrustDecision rejectsAllowRule(const bulwark::DefenseRule& r);

    static TrustDecision isAbusedSigner(const bulwark::SecurityEvent& e);

    static void setAbusedSigners(const QStringList& thumbprints, const QStringList& publishers);
};

}
