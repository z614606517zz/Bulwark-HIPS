#pragma once
#include <QString>
#include <QDateTime>
#include <QList>
#include <optional>

namespace bulwark::service::monitoring {

class ProcessInspector {
public:
    struct CertInfo {
        QString   thumbprint;
        QDateTime notAfterUtc;
        QDateTime notBeforeUtc;
        QDateTime signingTimeUtc;
        bool      signedAfterCertExpiry = false;
        bool      revoked = false;
    };

    static QString tryGetUserSid(int pid);
    static bool    isSigned(const QString& path);
    static QString tryGetPublisher(const QString& path);
    static QString tryGetSignerThumbprint(const QString& path);
    static QString tryComputeSha256(const QString& path);
    static bool    hasEmbeddedSignature(const QString& path);
    static bool    isSignatureMismatch(const QString& path);
    static CertInfo getCertInfo(const QString& path);

    struct ForensicFacts {
        bool     trustedSignature = false;
        bool     embeddedSignature = false;
        bool     signatureDigestMismatch = false;
        QString  publisher;
        QString  sha256;
        CertInfo cert;
        bool     isRealFile = false;
        qint64   fileSize = 0;
    };
    static ForensicFacts collectForensics(const QString& path, bool includeCert);

    struct ProcessInstance {
        int pid = 0;
        quint64 creationFileTime = 0;
        QString imagePath;
        bool isUsable() const { return pid > 4 && creationFileTime != 0 && !imagePath.isEmpty(); }
    };
    static std::optional<ProcessInstance> tryGetProcessInstance(int pid);
    static bool isCurrentProcessInstance(const ProcessInstance& expected);
    static QString tryGetProcessImagePath(int pid);
    static QString tryGetCommandLine(int pid);
    static int     tryGetParentPid(int pid);
    static QList<int> enumeratePids();

    static bool ensureDebugPrivilege();
    static bool isCriticalProcess(int pid);
    static bool tryTerminateProcess(int pid);
    static bool waitForExit(int pid, int msTimeout = 0);
    // 返回 TerminateProcess 成功的个数。ended 非空时追加本次结束掉的实例(动手前取的
    // PID + 创建时间 + 映像):TerminateProcess 成功的,以及轮到它时已经自行退出的。
    static int  terminateProcessTree(int rootPid, QList<ProcessInstance>* ended = nullptr);
    static bool trySuspend(int pid);
    static bool tryResume(int pid);

    inline static bool onlineRevocationCheck = false;
    inline static int  onlineRevocationBudgetMs = 800;
};

}
