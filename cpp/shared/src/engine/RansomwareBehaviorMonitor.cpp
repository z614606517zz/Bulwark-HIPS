#include "bulwark/engine/RansomwareBehaviorMonitor.h"
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/Clock.h"
#include <QElapsedTimer>
#include <QMutexLocker>
#include <QSet>
#include <QVector>
#include <algorithm>
#include <limits>
#include <utility>

namespace bulwark::engine {

using detail::u;
using detail::fileNameLower;

namespace {

constexpr qint64 kWindowMs = 60 * 1000;
constexpr qint64 kIdleMs = 5 * 60 * 1000;
constexpr int kFreshFileSecs = 10 * 60;
constexpr int kContainmentThreshold = 25;
constexpr int kNoteDirThreshold = 3;
constexpr int kMarkedThreshold = 3;
constexpr int kMarkedDestroyedThreshold = 5;
constexpr int kMaxProcesses = 512;

// 内容确认成了乱码的文件,几个就够下结论;全集中在同一目录的同一种文件上时要更多
// (某个应用用私有格式重写自己的一批数据文件,不该几个就报)。
constexpr int kScrambledThreshold = 4;
constexpr int kScrambledSameKindThreshold = 8;

// 事件在写入 / 删除 / 改名发生之前就发出,收到时文件可能还是旧样子;解压工具覆盖已有文件又是
// 先删后建。所以不当场下结论,隔一会儿回头看:过了 kLandMs 操作已经落地,这时内容完好就放过;
// 「原文件不见了」「内容说明不了什么」要等它停手 kSettleMs 之后才认。
constexpr qint64 kLandMs = 50;
constexpr qint64 kSettleMs = 1500;
constexpr qint64 kLookAgesMs[] = { kLandMs, 200, 600, kSettleMs };
constexpr int kMaxLooks = 5;
// 回头看要读盘,不能拖慢事件处理:每个事件最多看这么多个文件、总共这么久,剩下的留给下一个事件。
constexpr int kLooksPerEvent = 6;
constexpr int kLateLooksPerEvent = 24;
constexpr qint64 kLookBudgetMs = 60;
constexpr int kMaxPending = 1024;

// 应用数据、系统、开发与缓存目录天然高频写入大量已有文件,不在勒索监视范围。
bool isMonitoredTarget(const QString& lower) {
    if (lower.size() < 3 || lower.at(1) != QLatin1Char(':'))
        return false;
    static const char* excluded[] = {
        "\\appdata\\", "\\windows\\", "\\program files", "\\programdata\\", "\\$recycle.bin\\",
        "\\system volume information\\", "\\temp\\", "\\tmp\\", "\\node_modules\\", "\\.git\\", "\\.svn\\",
        "\\.vs\\", "\\.vscode\\", "\\.idea\\", "\\obj\\", "\\bin\\", "\\build\\", "\\out\\", "\\dist\\",
        "\\target\\", "\\__pycache__\\", "\\.gradle\\", "\\.m2\\", "\\.nuget\\", "\\packages\\", "\\vendor\\",
        "\\cache\\", "\\.cache\\", "\\steamapps\\", "\\logs\\", "\\onedrive\\.", "\\.venv\\", "\\venv\\",
        "\\deps\\", "\\incremental\\", "\\.fingerprint\\",
    };
    for (const char* x : excluded)
        if (lower.contains(QLatin1String(x)))
            return false;
    // 编译器中间产物:增量构建成批覆写上一轮的产物,而构建目录可以起任意名字(cargo --target-dir)。
    static const char* buildArtifacts[] = {
        ".obj", ".o", ".lib", ".exp", ".pdb", ".ilk", ".idb", ".iobj", ".ipdb",
        ".pch", ".ipch", ".rlib", ".rmeta", ".tlog",
    };
    for (const char* x : buildArtifacts)
        if (lower.endsWith(QLatin1String(x)))
            return false;
    return true;
}

bool isRansomNote(const QString& name) {
    static const char* exts[] = { ".txt", ".html", ".htm", ".hta", ".rtf" };
    bool docExt = false;
    for (const char* x : exts)
        docExt = docExt || name.endsWith(QLatin1String(x));
    if (!docExt)
        return false;
    if (name == QLatin1String("_readme.txt") || name.contains(QLatin1String("ransom")))
        return true;
    if (name.contains(QLatin1String("decrypt")))
        return true;
    const bool files = name.contains(QLatin1String("files")) || name.contains(QLatin1String("data"));
    return files && (name.contains(QLatin1String("recover")) || name.contains(QLatin1String("restore")));
}

bool hasRansomwareExtension(const QString& name) {
    static const char* exts[] = {
        ".locked", ".encrypted", ".crypt", ".crypted", ".cryptolocker", ".lockbit", ".conti", ".ryk",
        ".wncry", ".wnry", ".wcry", ".cerber", ".locky", ".zepto", ".odin", ".djvu", ".makop", ".phobos",
        ".dharma", ".stop", ".medusa", ".akira", ".blackcat", ".royal", ".rhysida", ".babuk", ".hive",
        ".lockfile", ".enc1", ".kraken",
    };
    for (const char* x : exts)
        if (name.endsWith(QLatin1String(x)))
            return true;
    return false;
}

QString dirOf(const QString& path) {
    const qsizetype slash = path.lastIndexOf(QLatin1Char('\\'));
    return slash > 0 ? path.left(slash) : path;
}

void prune(QHash<QString, qint64>& h, qint64 nowMs) {
    for (auto it = h.begin(); it != h.end();) {
        if (nowMs - it.value() > kWindowMs) it = h.erase(it);
        else ++it;
    }
}

// 动过之后按 50ms、200ms、600ms、1.5s 的间隔回头看,此后每 1.5s 一次。
qint64 nextLookAt(qint64 eventMs, qint64 nowMs) {
    const qint64 age = nowMs - eventMs;
    for (const qint64 at : kLookAgesMs)
        if (age < at)
            return eventMs + at;
    return nowMs + kSettleMs;
}

enum class MarkedContent { Hit, Benign, Empty };

// 已知勒索扩展名里有几个撞了正常格式(.djvu 是电子书,.hive 是注册表配置单元),另一些
// (.locked / .stop)常被程序拿来当锁文件、标记文件。内容确实是那种格式、或只是文本的不算;
// 其余的二进制内容(包括套着这个扩展名的图片、文档)照旧计入。
MarkedContent judgeMarked(const QString& name, const FileContentSample& sample) {
    if (FileContentClassifier::classify(ContentClaim{}, sample) == ContentVerdict::Unsettled)
        return MarkedContent::Empty;
    const QByteArray& head = sample.head;
    if (name.endsWith(QLatin1String(".djvu")) && head.startsWith("AT&TFORM"))
        return MarkedContent::Benign;
    if (name.endsWith(QLatin1String(".hive")) && head.startsWith("regf"))
        return MarkedContent::Benign;
    if (FileContentClassifier::looksLikeText(head))
        return MarkedContent::Benign;
    return MarkedContent::Hit;
}

// 同一个说明文件名出现在多少个目录里。勒索程序往每个目录放的是同名的说明;
// 一套文档里各不相同的 *decrypt*.html 不是这个形状。键是「文件名|目录」。
int widestNoteSpread(const QHash<QString, qint64>& notes) {
    QHash<QString, int> perName;
    int widest = 0;
    for (auto it = notes.cbegin(); it != notes.cend(); ++it) {
        const QString& key = it.key();
        widest = qMax(widest, ++perName[key.left(key.indexOf(QLatin1Char('|')))]);
    }
    return widest;
}

bool spansKinds(const QHash<QString, qint64>& victims) {
    QSet<QString> dirs;
    QSet<QString> types;
    for (auto it = victims.cbegin(); it != victims.cend(); ++it) {
        dirs.insert(dirOf(it.key()));
        types.insert(FileContentClassifier::claimOf(fileNameLower(it.key())).type);
    }
    return dirs.size() >= 2 || types.size() >= 2;
}

QString sampleNames(const QHash<QString, qint64>& victims) {
    QStringList names;
    for (auto it = victims.cbegin(); it != victims.cend(); ++it)
        names << fileNameLower(it.key());
    names.sort();
    if (names.size() <= 3)
        return names.join(u("、"));
    return names.mid(0, 3).join(u("、")) + u(" 等");
}

}

void RansomwareBehaviorMonitor::setFileStateProbe(FileStateProbe probe) {
    QMutexLocker locker(&gate_);
    probe_ = std::move(probe);
}

void RansomwareBehaviorMonitor::setContentProbe(ContentProbe probe) {
    QMutexLocker locker(&gate_);
    content_ = std::move(probe);
}

RansomwareBehaviorMonitor::Prior RansomwareBehaviorMonitor::priorState(const SecurityEvent& e, const QString& path,
                                                                       const QDateTime& when) {
    if (e.fileCreatedNew)
        return Prior::New;
    if (!probe_)
        return Prior::Existing;
    const FileState st = probe_(path);
    switch (st.kind) {
    case FileState::Kind::Unavailable:
        return Prior::Unverifiable;
    case FileState::Kind::Missing:
        // 已被改名或删掉,或是改名的目标还没落地;同一路径随后的删除仍会计入。
        return Prior::New;
    case FileState::Kind::Present:
        // 覆写、截断都保留原创建时间;创建时间很新只可能是真新建(解压、导出、构建产物)。
        return (st.createdUtc.isValid() && st.createdUtc >= when.addSecs(-kFreshFileSecs)) ? Prior::New
                                                                                         : Prior::Existing;
    }
    return Prior::Unverifiable;
}

void RansomwareBehaviorMonitor::pruneLedger(Ledger& ledger, qint64 nowMs) {
    prune(ledger.destroyed, nowMs);
    prune(ledger.scrambled, nowMs);
    prune(ledger.cipherCopies, nowMs);
    prune(ledger.markedFiles, nowMs);
}

void RansomwareBehaviorMonitor::noteDestroyed(Ledger& ledger, const QString& path, qint64 stampMs) {
    if (ledger.scrambled.contains(path))
        return;
    // 原件没了,而旁边先前出现过它的乱码副本:这个文件是被加密了。
    if (ledger.cipherCopies.remove(path)) {
        ledger.destroyed.remove(path);
        ledger.scrambled.insert(path, stampMs);
        return;
    }
    ledger.destroyed.insert(path, stampMs);
}

// 内容看不了或说明不了什么时退回原来的算法:带勒索扩展名的计入,动了已有文件的计入。
void RansomwareBehaviorMonitor::countByOldRule(Ledger& ledger, const QString& path, const Pending& p,
                                               qint64 stampMs) {
    if (p.marked)
        ledger.markedFiles.insert(path, stampMs);
    else if (p.existing || p.deleted)
        noteDestroyed(ledger, path, stampMs);
}

void RansomwareBehaviorMonitor::recordScrambled(Ledger& ledger, const QString& path, const ContentClaim& claim,
                                                const Pending& p, qint64 stampMs) {
    if (!claim.inner) {
        // 名字没变、内容成了乱码:受害的就是它自己。
        ledger.destroyed.remove(path);
        ledger.cipherCopies.remove(path);
        ledger.scrambled.insert(path, stampMs);
        return;
    }
    // report.docx.abc 是乱码:受害的是 report.docx。
    const QString victim = dirOf(path) + QLatin1Char('\\') + claim.original;
    ledger.destroyed.remove(path);
    if (p.existing || p.deleted || ledger.scrambled.contains(victim) || ledger.destroyed.remove(victim)) {
        // 原件改名带过来的(创建时间是旧的),或者原件已经没了。
        ledger.destroyed.remove(victim);
        ledger.cipherCopies.remove(victim);
        ledger.scrambled.insert(victim, stampMs);
        return;
    }
    // 新写出来的乱码副本,原件还在:等原件被删或被移走再算。
    ledger.cipherCopies.insert(victim, stampMs);
}

// 回头看一眼文件现在的样子。Done:有结论了,可以从待定表里拿掉;Wait:还要再等;Busy:这会儿读不到。
// forced:不能再等了(待定表满了,或已经过了一整个窗口),只要读得到就必须下结论。
RansomwareBehaviorMonitor::Look RansomwareBehaviorMonitor::look(Ledger& ledger, const QString& path, Pending& p,
                                                                qint64 nowMs, qint64 stampMs, bool forced) {
    const FileContentSample sample = content_(path);
    if (sample.kind == FileContentSample::Kind::Busy)
        return Look::Busy;
    ++p.looks;
    const qint64 age = nowMs - p.eventMs;
    const bool landed = forced || age >= kLandMs;
    const bool settled = forced || age >= kSettleMs;
    const bool lastLook = forced || (settled && p.looks >= kMaxLooks);

    if (sample.kind == FileContentSample::Kind::Unavailable) {
        // 这个位置读不了内容(网络盘、云端占位文件)。
        countByOldRule(ledger, path, p, stampMs);
        return Look::Done;
    }
    if (sample.kind == FileContentSample::Kind::Missing) {
        if (p.deleted) {
            // 删掉后没有再出现:先记上。解压覆盖是先删后建,稍后若以认得出的内容重新出现,复查时销账。
            noteDestroyed(ledger, path, stampMs);
            return settled ? Look::Done : Look::Wait;
        }
        if (!settled)
            return Look::Wait;   // 改名的目标可能还没落地
        // 原有的文件动过之后不见了(被改名或移走):按原来的算法计入。新建的文件自己消失不算。
        if (p.existing && !p.marked)
            noteDestroyed(ledger, path, stampMs);
        return Look::Done;
    }

    const QString name = fileNameLower(path);
    if (p.marked) {
        switch (judgeMarked(name, sample)) {
        case MarkedContent::Hit:
            ledger.markedFiles.insert(path, stampMs);
            return Look::Done;
        case MarkedContent::Benign:
            return settled ? Look::Done : Look::Wait;
        case MarkedContent::Empty:
            return lastLook ? Look::Done : Look::Wait;
        }
        return Look::Done;
    }

    const ContentClaim claim = FileContentClassifier::claimOf(name);
    switch (FileContentClassifier::classify(claim, sample)) {
    case ContentVerdict::Scrambled:
        recordScrambled(ledger, path, claim, p, stampMs);
        return Look::Done;
    case ContentVerdict::Recognized:
        if (!landed)
            return Look::Wait;   // 写入可能还没落盘,看到的是旧内容
        // 内容完好。先前按「删了」记的账(先删后建)销掉。
        ledger.destroyed.remove(path);
        return Look::Done;
    case ContentVerdict::Unknown:
        if (!settled)
            return Look::Wait;
        countByOldRule(ledger, path, p, stampMs);
        return Look::Done;
    case ContentVerdict::Unsettled:
        // 空文件、全零:多等几轮,始终如此才按原来的算法计入。
        if (!lastLook)
            return Look::Wait;
        countByOldRule(ledger, path, p, stampMs);
        return Look::Done;
    }
    return Look::Done;
}

void RansomwareBehaviorMonitor::admitWrite(Activity& a, const SecurityEvent& e, const QString& path,
                                           const QString& name, const QDateTime& when, qint64 nowMs,
                                           bool content) {
    Ledger& ledger = a.ledger;
    if (isRansomNote(name)) {
        a.noteDirs.insert(name + QLatin1Char('|') + dirOf(path), nowMs);
        return;
    }
    const bool marked = hasRansomwareExtension(name);
    if (!content) {
        if (marked)
            ledger.markedFiles.insert(path, nowMs);
        else if (priorState(e, path, when) != Prior::New)
            ledger.destroyed.insert(path, nowMs);
        return;
    }
    if (ledger.scrambled.contains(path)) {
        ledger.scrambled.insert(path, nowMs);
        return;
    }

    auto it = a.pending.find(path);
    if (it == a.pending.end()) {
        Pending p;
        p.marked = marked;
        // 先前按「删了」记过账的路径又有写入:原来是有这个文件的,看过内容再定。
        p.existing = ledger.destroyed.contains(path);
        if (!marked && !p.existing) {
            const Prior prior = priorState(e, path, when);
            if (prior == Prior::Unverifiable) {
                // 查不了的位置(网络盘等)也读不了内容,按原来的算法计入。
                ledger.destroyed.insert(path, nowMs);
                return;
            }
            p.existing = prior == Prior::Existing;
            // 普通的新文件不用看。只有「原文件名 + 外加后缀」的新文件值得看一眼是不是乱码副本。
            if (!p.existing && !FileContentClassifier::claimOf(name).inner)
                return;
        }
        it = a.pending.insert(path, p);
    } else {
        it->marked = it->marked || marked;
        // 删掉之后又写:原来是有这个文件的。
        it->existing = it->existing || it->deleted;
        it->looks = 0;
    }
    it->eventMs = nowMs;
    // 当场看一眼:已经是乱码的立刻计入,其余的过一会儿再定。
    if (look(ledger, path, *it, nowMs, nowMs, false) == Look::Done) {
        a.pending.erase(it);
        return;
    }
    it->dueMs = nowMs + kLandMs;
    a.nextLookMs = qMin(a.nextLookMs, it->dueMs);
    trimPending(a, nowMs);
}

void RansomwareBehaviorMonitor::admitDelete(Activity& a, const QString& path, qint64 nowMs, bool content) {
    Ledger& ledger = a.ledger;
    if (!content) {
        ledger.destroyed.insert(path, nowMs);
        return;
    }
    if (ledger.scrambled.contains(path)) {
        ledger.scrambled.insert(path, nowMs);
        return;
    }
    // 旁边已经有它的乱码副本,现在原件被删:这个文件是被加密了,不用再等。
    if (ledger.cipherCopies.remove(path)) {
        a.pending.remove(path);
        ledger.destroyed.remove(path);
        ledger.scrambled.insert(path, nowMs);
        return;
    }
    // 删除事件发出时文件还在,当场看没有意义;稍后看它是真没了,还是又以完好的内容出现。
    Pending& p = a.pending[path];
    p.deleted = true;
    p.eventMs = nowMs;
    p.dueMs = nowMs + kLandMs;
    p.looks = 0;
    a.nextLookMs = qMin(a.nextLookMs, p.dueMs);
    trimPending(a, nowMs);
}

// 把到期的待定文件回头看一遍。过了一整个窗口还没结论的(那阵动作太短,没来得及看就停了)记进 late,
// 单独结账。
void RansomwareBehaviorMonitor::settle(Activity& a, qint64 nowMs) {
    if (a.pending.isEmpty() || nowMs < a.nextLookMs)
        return;
    // (到期时间, 路径):先到期的先看;排过序,结果不随哈希表的遍历顺序变。
    QVector<std::pair<qint64, QString>> due;
    for (auto it = a.pending.cbegin(); it != a.pending.cend(); ++it)
        if (it->dueMs <= nowMs)
            due.append(std::make_pair(it->dueMs, it.key()));
    std::sort(due.begin(), due.end());

    QElapsedTimer spent;
    spent.start();
    int looked = 0;
    int lateLooked = 0;
    for (const auto& entry : std::as_const(due)) {
        if (looked + lateLooked > 0 && spent.elapsed() >= kLookBudgetMs)
            break;
        const QString& path = entry.second;
        const auto it = a.pending.find(path);
        if (it == a.pending.end())
            continue;
        const qint64 age = nowMs - it->eventMs;
        const bool late = age > kWindowMs;
        Look result = Look::Wait;
        if (late) {
            if (lateLooked >= kLateLooksPerEvent)
                continue;
            ++lateLooked;
            result = look(a.late, path, *it, nowMs, nowMs, true);
            if (result == Look::Busy && age > 2 * kWindowMs) {
                // 两个窗口过去了还是读不到:不再等,按原来的算法入账。
                countByOldRule(a.late, path, *it, nowMs);
                result = Look::Done;
            }
        } else {
            if (looked >= kLooksPerEvent)
                continue;
            ++looked;
            result = look(a.ledger, path, *it, nowMs, it->eventMs, false);
        }
        if (result == Look::Done)
            a.pending.erase(it);
        else
            it->dueMs = nextLookAt(it->eventMs, nowMs);
    }

    qint64 next = std::numeric_limits<qint64>::max();
    for (auto it = a.pending.cbegin(); it != a.pending.cend(); ++it)
        next = qMin(next, it->dueMs);
    a.nextLookMs = next;
}

// 待定的太多时,最早的那个不再等,现在就看一眼定下来;读不到就按原来的算法入账。
void RansomwareBehaviorMonitor::trimPending(Activity& a, qint64 nowMs) {
    while (a.pending.size() > kMaxPending) {
        auto oldest = a.pending.begin();
        for (auto it = a.pending.begin(); it != a.pending.end(); ++it) {
            if (it->eventMs < oldest->eventMs || (it->eventMs == oldest->eventMs && it.key() < oldest.key()))
                oldest = it;
        }
        const bool late = nowMs - oldest->eventMs > kWindowMs;
        Ledger& ledger = late ? a.late : a.ledger;
        const qint64 stampMs = late ? nowMs : oldest->eventMs;
        if (look(ledger, oldest.key(), *oldest, nowMs, stampMs, true) == Look::Busy)
            countByOldRule(ledger, oldest.key(), *oldest, stampMs);
        a.pending.erase(oldest);
    }
}

void RansomwareBehaviorMonitor::score(Activity& a, const Ledger& ledger, Result& r) {
    const qsizetype scrambled = ledger.scrambled.size();
    const qsizetype damaged = ledger.destroyed.size() + scrambled;
    if (ledger.markedFiles.size() >= kMarkedThreshold && !a.markedReported) {
        a.markedReported = true;
        r.score += 60;
        r.hardSignal = true;
        r.containmentRequired = r.containmentRequired || damaged >= kMarkedDestroyedThreshold;
        r.reasons << u("1 分钟内产出 %1 个已知勒索扩展名文件(T1486)").arg(ledger.markedFiles.size());
    }
    if (a.containmentReported)
        return;
    if (scrambled >= kScrambledThreshold
        && (scrambled >= kScrambledSameKindThreshold || spansKinds(ledger.scrambled))) {
        a.containmentReported = true;
        r.score += 50;
        r.containmentRequired = true;
        r.reasons << u("1 分钟内有 %1 个已有文件被改写成无法识别的内容(原格式已损毁,疑似被加密,T1486):%2")
                         .arg(scrambled)
                         .arg(sampleNames(ledger.scrambled));
    } else if (damaged >= kContainmentThreshold) {
        a.containmentReported = true;
        r.score += 50;
        r.containmentRequired = true;
        r.reasons << u("1 分钟内改写 / 删除 %1 个已有用户文件(疑似批量加密,T1486)").arg(damaged);
    }
}

RansomwareBehaviorMonitor::Result RansomwareBehaviorMonitor::observe(const SecurityEvent& e, bool inspectContent) {
    Result r;
    if (e.actorPid <= 0)
        return r;
    if (e.type != EventType::FileWrite && e.type != EventType::FileDelete)
        return r;
    QString target = e.target.toLower();
    target.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (!isMonitoredTarget(target))
        return r;

    const QDateTime when = e.timestampUtc.isValid() ? e.timestampUtc : nowUtc();
    const qint64 nowMs = when.toMSecsSinceEpoch();
    const QString name = fileNameLower(target);

    QMutexLocker locker(&gate_);
    evict(nowMs);
    Activity& a = activity_[e.actorPid];
    const QString actor = e.actorPath.toLower();
    if (a.actorPath != actor) {
        a = Activity{};
        a.actorPath = actor;
    }
    a.lastMs = nowMs;

    if (a.convicted) {
        r.score = 60;
        r.hardSignal = true;
        r.reasons << u("已判定为勒索行为的进程继续改写 / 删除用户文件(T1486)");
        return r;
    }

    pruneLedger(a.ledger, nowMs);
    pruneLedger(a.late, nowMs);
    prune(a.noteDirs, nowMs);

    const bool content = inspectContent && content_;
    if (!content && !a.pending.isEmpty()) {
        // 这个进程改按数量判断了:待定的不再读内容,直接入账。
        for (auto it = a.pending.cbegin(); it != a.pending.cend(); ++it) {
            const bool late = nowMs - it->eventMs > kWindowMs;
            countByOldRule(late ? a.late : a.ledger, it.key(), *it, late ? nowMs : it->eventMs);
        }
        a.pending.clear();
        a.nextLookMs = 0;
    }

    // 被内核拦下的改写 / 删除没有发生,不计入。
    if (!e.kernelBlocked) {
        if (e.type == EventType::FileDelete)
            admitDelete(a, target, nowMs, content);
        else
            admitWrite(a, e, target, name, when, nowMs, content);
    }
    if (content)
        settle(a, nowMs);

    if (!a.notesReported && a.noteDirs.size() >= kNoteDirThreshold) {
        const int spread = widestNoteSpread(a.noteDirs);
        if (spread >= kNoteDirThreshold) {
            a.notesReported = true;
            r.score += 60;
            r.hardSignal = true;
            r.reasons << u("1 分钟内在 %1 个目录写入勒索说明文件(T1486)").arg(spread);
        }
    }
    score(a, a.late, r);
    score(a, a.ledger, r);
    a.convicted = r.hardSignal;
    return r;
}

void RansomwareBehaviorMonitor::evict(qint64 nowMs) {
    if (activity_.size() <= kMaxProcesses)
        return;
    for (auto it = activity_.begin(); it != activity_.end();) {
        if (nowMs - it->lastMs > kIdleMs) it = activity_.erase(it);
        else ++it;
    }
    if (activity_.size() > kMaxProcesses)
        activity_.clear();
}

}
