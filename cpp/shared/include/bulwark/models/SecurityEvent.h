#pragma once
#include <QString>
#include <QStringList>
#include <QDateTime>
#include <QUuid>
#include <QVector>
#include <QJsonObject>
#include <optional>
#include "bulwark/models/Enums.h"
#include "bulwark/models/Evidence.h"
#include "bulwark/models/ChainEventInfo.h"
#include "bulwark/models/ThreatSnippet.h"
#include "bulwark/Clock.h"

namespace bulwark {

namespace targetTag {

inline QString volumeBootSector()        { return QStringLiteral("[卷引导区写入]"); }
inline QString volumeBootSectorPattern() { return QStringLiteral("*[卷引导区写入]*"); }

}

struct SecurityEvent {
    QUuid id = QUuid::createUuid();
    QDateTime timestampUtc = nowUtc();
    EventType type = EventType::ProcessCreate;

    int actorPid = 0;
    std::optional<quint64> actorCreationFileTime;
    QString actorPath;
    QString actorHash;
    bool actorSigned = false;
    bool signatureMismatch = false;
    bool signatureTampered = false;
    qint64 actorFileSize = 0;
    QString actorPublisher;
    QString actorCertThumbprint;
    std::optional<QDateTime> certNotAfterUtc;
    std::optional<QDateTime> signingTimeUtc;
    bool certRevoked = false;
    bool signedAfterCertExpiry = false;
    bool isFirstSeen = false;

    int originatorPid = 0;                // RPC 真凶 PID(0=无)
    QString originatorPath;
    int parentPid = 0;
    QString parentPath;
    // 进程创建事件里真正调用 CreateProcess 的进程(只在与 parentPid 不同时填)。父进程可以用
    // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 随意指定;富化阶段核实后,伪造时把 parent* 换成真实创建者,
    // 被冒用的父进程移到 spoofedParent*。
    int creatorPid = 0;
    int spoofedParentPid = 0;
    QString spoofedParentPath;
    // 进程仍在运行,映像文件却已不在原路径(进程幽灵化 / 启动即自删)。
    bool actorImageMissing = false;
    // 驱动在进程创建那一刻看到的映像文件状态(Protocol.h 的 BLW_IMAGE_*,只有进程创建事件才有)。
    enum ImageFlag { ImageDeletePending = 0x1, ImageTransacted = 0x2, ImageWritable = 0x4 };
    int actorImageFlags = 0;

    ProcessOriginKind originKind = ProcessOriginKind::Unknown;
    QString originService;
    QString originServiceDisplay;
    QString originTask;
    QString originDetail;
    QString commandLine;

    // 命令行还原结果(RuleEngine 在规则匹配前用 CommandDeobfuscator 填):实际会被执行的那一串与 Base64 解出的正文,
    // 供 DefenseRule::matchesCommandLine 多比对一遍。三项都是每次评估重算的过程量,不进 toJson。
    // normalizedCommandLine 为空有两种含义:没做还原,或还原结果与原文逐字一致。
    QString normalizedCommandLine;
    QStringList decodedCommandBlocks;
    QStringList commandDeobfuscationLayers;
    // 还原是否已写进证据链。还原本身不算证据:7-Zip 的 -o"C:\path"、Inno 的 /c ""setup.tmp"" 这类正常写法也会触发还原。
    // 只有某条特征或规则只在还原后的文本上才命中时,才由 reportCommandDeobfuscation 记一次。
    bool commandDeobfuscationReported = false;
    // 原文的规整形态(至多两份:连续空白压成一个空格的,以及再去掉包着单个 token 的引号的),
    // 同样是每次评估重算的过程量,不进 toJson。与还原无关:正常命令行也会有,不能当作"被混淆过"的依据。
    // 为空表示规整后与原文或 normalizedCommandLine 一致。
    QStringList canonicalCommandLines;

    QString target;
    QString detail;
    QString correlationId;

    // RegistryWrite 的操作方向。内核的 Set/DeleteValue/DeleteKey 三态被折叠成
    // EventType::RegistryWrite 后,靠这个字段保住方向,供规则区分加固写入与削弱写入。
    RegistryOperation registryOp = RegistryOperation::Unknown;

    // RegistryWrite 的 REG_DWORD 值(仅设值且类型为 REG_DWORD 时有效)。
    // 由内核经 BLW_EVENT_MESSAGE 的 RemoteIpV4/RemotePort 传上来(注册表事件不占网络字段),
    // 用于区分「设 0 加固」与「设 1 削弱」。hasRegistryDword=false 表示值不可得。
    bool hasRegistryDword = false;
    quint32 registryDwordValue = 0;

    bool targetSigned = false;
    bool targetSignatureMismatch = false;
    // FileWrite 的目标是原始磁盘 / 卷设备,且该设备是 U 盘、SD 卡、USB 硬盘等外接存储(服务端查询)。
    bool targetOnRemovableMedia = false;

    int riskScore = 0;
    QStringList riskReasons;
    QVector<Evidence> evidenceChain;
    QStringList techniques;

    bool hasThreatIndicator = false;
    QString matchedRuleNote;
    bool userModeObserved = false;
    bool kernelBlocked = false;
    // 内核只剥掉了句柄上的危险权限,打开本身照常成功(自我保护 / 内存防护的剥权事件)。
    // 与 kernelBlocked 同时为真;每次由事件源现填,不进 toJson。
    bool kernelRightsStripped = false;
    bool ransomwareContainmentRequired = false;
    bool scriptContainmentRequired = false;
    bool requiresTransientContainment() const {
        return ransomwareContainmentRequired || scriptContainmentRequired;
    }

    QString processInstanceKey() const;
    bool matchedRuleIdentifiesSubject = false;
    bool matchedRuleDisablesSignedAutoAllow = false;
    bool matchedRuleUsageOnly = false;
    bool userTrusted = false;
    bool productSignedAncestor = false;
    bool memoryInjection = false;
    bool fileCreatedNew = false;
    QString fileDescription;
    // PE 版本资源里的 OriginalFilename(小写,去掉 .mui);只为系统 / 安装目录以外的进程读取。
    QString originalFileName;

    bool isInstaller = false;

    QString tamperedModulePath;

    QString sideloadedUnsignedModulePath;
    QString sideloadedUnsignedModuleWhy;

    QString selfCopyTargetPath;
    QString selfCopyWhy;
    bool selfCopyContentConfirmed = false;

    QString scriptFilePath;
    int scriptFileScore = 0;
    bool scriptFileHardIndicator = false;
    QStringList scriptFileHits;
    QStringList scriptFileReasons;

    QVector<ThreatSnippet> threatSnippets;

    bool addSnippet(const ThreatSnippet& s);

    QVector<ChainEventInfo> chainContext;

    void addEvidence(const QString& source, EvidenceKind kind,
                     const QString& description, int scoreDelta = 0,
                     bool alsoReason = true,
                     EvidenceSubject subject = EvidenceSubject::Actor);

    bool isMemoryCarrierFinding() const;

    bool hasActorHardIndicator() const;

    int actorHardEvidenceSourceCount() const;

    // 全事件的独立硬证据组数，供静默模式与 AI 补偿处置使用。subject 不限；需要给发起方
    // 定罪时必须使用上面的 actor-only 版本。
    int hardEvidenceGroupCount() const;

    QString originLabel() const;

    QJsonObject toJson() const;
    static SecurityEvent fromJson(const QJsonObject& o);
};

}
