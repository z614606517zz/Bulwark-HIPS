#pragma once
#include <QDateTime>
#include <QHash>
#include <QMutex>
#include <QString>
#include <QStringList>
#include <functional>
#include "bulwark/engine/FileContentClassifier.h"
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

class RansomwareBehaviorMonitor {
public:
    struct FileState {
        enum class Kind { Unavailable, Missing, Present };
        Kind kind = Kind::Unavailable;
        QDateTime createdUtc;
    };
    using FileStateProbe = std::function<FileState(const QString& path)>;
    // 读文件开头一小段,用来分辨「改写之后还是好文件」和「已经成了乱码」。
    using ContentProbe = std::function<FileContentSample(const QString& path)>;

    struct Result {
        int score = 0;
        QStringList reasons;
        bool hardSignal = false;
        bool containmentRequired = false;
    };

    void setFileStateProbe(FileStateProbe probe);
    void setContentProbe(ContentProbe probe);
    // inspectContent 为 false 或没装内容探针时,只按改写 / 删除的数量判断,不读文件。
    Result observe(const SecurityEvent& e, bool inspectContent = true);

private:
    enum class Prior { New, Existing, Unverifiable };
    enum class Look { Done, Wait, Busy };

    // 还没下结论的文件。事件在操作发生之前就发出,解压工具覆盖时又是先删后建:过一会儿再看内容。
    struct Pending {
        qint64 eventMs = 0;      // 它最后一次动这个文件的时间
        qint64 dueMs = 0;        // 下一次回头看的时间
        int looks = 0;
        bool marked = false;     // 文件名带已知勒索扩展名
        bool existing = false;   // 动的是早就存在的文件
        bool deleted = false;    // 收到过删除
    };

    struct Ledger {
        QHash<QString, qint64> destroyed;      // 已有文件被删、被移走,或改写后内容无从判断
        QHash<QString, qint64> scrambled;      // 已有文件的内容成了乱码(键是原文件路径)
        QHash<QString, qint64> cipherCopies;   // 旁边新出现了乱码副本、原件还在(键是原文件路径)
        QHash<QString, qint64> markedFiles;
    };

    struct Activity {
        Ledger ledger;
        // 上一阵留下、过了一整个窗口才看清的文件单独记账,不和眼下这一分钟混在一起数。
        Ledger late;
        QHash<QString, qint64> noteDirs;
        QHash<QString, Pending> pending;
        qint64 nextLookMs = 0;   // 待定表里最早的到期时间;没到就不用扫表
        qint64 lastMs = 0;
        bool containmentReported = false;
        bool notesReported = false;
        bool markedReported = false;
        // 一次拦截只拒掉一次写入,进程还会接着加密别的文件;判定之后的每次改写都继续报。
        bool convicted = false;
        // PID 会被复用:主体映像变了就是另一个进程,状态从头算。
        QString actorPath;
    };

    static void pruneLedger(Ledger& ledger, qint64 nowMs);
    static void noteDestroyed(Ledger& ledger, const QString& path, qint64 stampMs);
    static void countByOldRule(Ledger& ledger, const QString& path, const Pending& p, qint64 stampMs);
    static void recordScrambled(Ledger& ledger, const QString& path, const ContentClaim& claim, const Pending& p,
                                qint64 stampMs);

    Prior priorState(const SecurityEvent& e, const QString& path, const QDateTime& when);
    void admitWrite(Activity& a, const SecurityEvent& e, const QString& path, const QString& name,
                    const QDateTime& when, qint64 nowMs, bool content);
    void admitDelete(Activity& a, const QString& path, qint64 nowMs, bool content);
    Look look(Ledger& ledger, const QString& path, Pending& p, qint64 nowMs, qint64 stampMs, bool forced);
    void settle(Activity& a, qint64 nowMs);
    void trimPending(Activity& a, qint64 nowMs);
    void score(Activity& a, const Ledger& ledger, Result& r);
    void evict(qint64 nowMs);

    FileStateProbe probe_;
    ContentProbe content_;
    QHash<int, Activity> activity_;
    QMutex gate_;
};

}
