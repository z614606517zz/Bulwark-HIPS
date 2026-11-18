#include "bulwark/engine/FileContentClassifier.h"
#include "bulwark/engine/RansomwareBehaviorMonitor.h"
#include "bulwark/engine/RuleEngine.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"

#include <QByteArray>
#include <QDateTime>
#include <QHash>
#include <QString>
#include <QStringList>
#include <QTimeZone>

#include <cstdio>

namespace {

using bulwark::engine::ContentClaim;
using bulwark::engine::ContentVerdict;
using bulwark::engine::FileContentClassifier;
using bulwark::engine::FileContentSample;
using bulwark::engine::RansomwareBehaviorMonitor;
using Result = RansomwareBehaviorMonitor::Result;

int gChecks = 0;
int gFailed = 0;

void check(bool condition, const char* name)
{
    ++gChecks;
    if (condition)
        return;
    ++gFailed;
    std::fprintf(stderr, "FAIL: %s\n", name);
}

bulwark::SecurityEvent fileEvent(int pid, const QString& target)
{
    bulwark::SecurityEvent event;
    event.type = bulwark::EventType::FileWrite;
    event.actorPid = pid;
    event.actorPath = QStringLiteral("C:\\Lab\\unsigned-writer.exe");
    event.actorSigned = false;
    event.target = target;
    return event;
}

void testCanaryBlocksImmediately()
{
    bulwark::engine::RuleEngine engine;
    engine.trustSignedActors = false;
    engine.addCanaryFile(QStringLiteral("C:\\Users\\u\\Documents\\Canary.docx"));

    bulwark::SecurityEvent write = fileEvent(4701, QStringLiteral("c:/users/u/documents/canary.docx"));
    const bulwark::Verdict vw = engine.evaluate(write);
    check(vw.action == bulwark::VerdictAction::Block && write.hasThreatIndicator
              && write.riskScore == 100,
          "canary write blocks with a hard indicator (path compare ignores case and separators)");

    bulwark::SecurityEvent removal = fileEvent(4702, QStringLiteral("C:\\Users\\u\\Documents\\Canary.docx"));
    removal.type = bulwark::EventType::FileDelete;
    check(engine.evaluate(removal).action == bulwark::VerdictAction::Block,
          "canary deletion blocks");

    bulwark::SecurityEvent other = fileEvent(4703, QStringLiteral("C:\\Users\\u\\Documents\\report.docx"));
    check(engine.evaluate(other).action == bulwark::VerdictAction::Allow && !other.hasThreatIndicator,
          "ordinary user file write is not a canary hit");

    bulwark::SecurityEvent noPid = fileEvent(0, QStringLiteral("C:\\Users\\u\\Documents\\Canary.docx"));
    check(engine.evaluate(noPid).action == bulwark::VerdictAction::Allow,
          "event without a writer pid is not treated as a canary hit");
}

// 文件内容

QByteArray filler(int size, quint32 seed)
{
    QByteArray b(size, Qt::Uninitialized);
    quint32 x = seed * 2654435761u + 0x9E3779B9u;
    for (int i = 0; i < size; ++i) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        b[i] = static_cast<char>(x >> 11);
    }
    return b;
}

QByteArray withHeader(const QByteArray& magic, quint32 seed, int size = 4096)
{
    QByteArray b = filler(size, seed);
    b.replace(0, magic.size(), magic);
    return b;
}

QByteArray jpeg(quint32 seed) { return withHeader(QByteArray::fromHex("ffd8ffe000104a4649460001"), seed); }
QByteArray docx(quint32 seed) {
    QByteArray b = withHeader(QByteArray("PK\x03\x04", 4), seed);
    // Minimal bounded ZIP local header; a magic plus random header fields is not
    // a valid fixture for an intact OOXML container.
    for (int i = 4; i < 30; ++i) b[i] = '\0';
    b[4] = 20;
    b[8] = 8;
    b[26] = 1;
    b[30] = 'x';
    return b;
}
QByteArray pdf(quint32 seed) { return withHeader(QByteArray("%PDF-1.7\n"), seed); }
QByteArray djvu(quint32 seed) { return withHeader(QByteArray("AT&TFORM"), seed); }
QByteArray text() { return QByteArray("meeting notes, line one\r\nline two\r\n").repeated(60); }

// 加密后的样子:整段高熵,开头既不是任何已知文件头,也不像容器头(没有连续的零和成串的可见字符)。
QByteArray scrambled(quint32 seed, int size = 4096)
{
    QByteArray b = filler(size, seed + 1000);
    for (int i = 0; i < 32 && i < size; ++i)
        b[i] = static_cast<char>(0x80 + (i * 37 + static_cast<int>(seed % 7)) % 0x70);
    return b;
}

FileContentSample present(const QByteArray& head)
{
    FileContentSample s;
    s.kind = FileContentSample::Kind::Present;
    s.size = head.size();
    s.head = head;
    return s;
}

void testContentClassifier()
{
    const ContentClaim plain = FileContentClassifier::claimOf(QStringLiteral("report.docx"));
    check(plain.type == QLatin1String("docx") && !plain.inner && !plain.textAllowed,
          "report.docx claims to be a docx");
    const ContentClaim wrapped = FileContentClassifier::claimOf(QStringLiteral("report.docx.k7x"));
    check(wrapped.type == QLatin1String("docx") && wrapped.inner
              && wrapped.original == QLatin1String("report.docx"),
          "report.docx.k7x is report.docx with a suffix added");
    check(FileContentClassifier::claimOf(QStringLiteral("x.pdf.crdownload")).type.isEmpty(),
          "a download in progress claims nothing");
    check(FileContentClassifier::claimOf(QStringLiteral("backup.zip.001")).type.isEmpty(),
          "a split-archive volume claims nothing");
    check(FileContentClassifier::claimOf(QStringLiteral("report.docx.gpg")).type.isEmpty(),
          "output of a file-encryption tool claims nothing");
    check(FileContentClassifier::claimOf(QStringLiteral("readme")).type.isEmpty(),
          "a name without an extension claims nothing");
    check(FileContentClassifier::claimOf(QStringLiteral("blob.dat")).type.isEmpty(),
          "an unknown extension claims nothing");
    const ContentClaim notes = FileContentClassifier::claimOf(QStringLiteral("notes.txt"));
    check(notes.type == QLatin1String("txt") && notes.textAllowed && !notes.inner, "notes.txt may hold text");
    const ContentClaim tgz = FileContentClassifier::claimOf(QStringLiteral("archive.tar.gz"));
    check(tgz.type == QLatin1String("gz") && !tgz.inner, "archive.tar.gz is judged by its own extension");

    using V = ContentVerdict;
    const QString jpgName = QStringLiteral("photo.jpg");
    check(FileContentClassifier::classify(jpgName, present(jpeg(1))) == V::Recognized, "a real jpeg is recognized");
    check(FileContentClassifier::classify(jpgName, present(scrambled(1))) == V::Scrambled,
          "random bytes under .jpg are scrambled");
    check(FileContentClassifier::classify(jpgName, present(docx(1))) == V::Recognized,
          "any known format counts as intact, whatever the extension");
    check(FileContentClassifier::classify(QStringLiteral("blob.dat"), present(scrambled(2))) == V::Unknown,
          "random bytes under an unknown extension prove nothing");
    check(FileContentClassifier::classify(QStringLiteral("notes.txt"), present(text())) == V::Recognized,
          "text in a text file is recognized");
    check(FileContentClassifier::classify(QStringLiteral("notes.txt"), present(scrambled(3))) == V::Scrambled,
          "random bytes in a text file are scrambled");
    check(FileContentClassifier::classify(jpgName, present(text())) == V::Unknown,
          "text under .jpg is odd but not scrambled");
    check(FileContentClassifier::classify(jpgName, present(QByteArray())) == V::Unsettled,
          "an empty file is not settled yet");
    check(FileContentClassifier::classify(jpgName, present(QByteArray(4096, '\0'))) == V::Unsettled,
          "a zero-filled file is not settled yet");
    check(FileContentClassifier::classify(jpgName, present(scrambled(4, 300))) == V::Unknown,
          "a few hundred bytes are too little to call scrambled");
    check(FileContentClassifier::classify(jpgName, present(scrambled(5, 700))) == V::Scrambled,
          "700 random bytes are enough");

    QByteArray zeroLed = scrambled(6);
    for (int i = 0; i < 8; ++i)
        zeroLed[i] = '\0';
    check(FileContentClassifier::classify(jpgName, present(zeroLed)) == V::Unknown,
          "a header with zero fields looks like some container, not ciphertext");
    QByteArray salted = scrambled(7);
    salted.replace(0, 8, QByteArray("Salted__"));
    check(FileContentClassifier::classify(jpgName, present(salted)) == V::Unknown,
          "a readable tag at the start looks like some container, not ciphertext");
    const QByteArray lowEntropy = QByteArray::fromHex("9b01a2f3").repeated(600);
    check(FileContentClassifier::classify(jpgName, present(lowEntropy)) == V::Unknown,
          "low-entropy binary is not scrambled");

    QByteArray latePdf = filler(2000, 9);
    for (int i = 0; i < 16; ++i)
        latePdf[i] = static_cast<char>(0x90 + i);
    latePdf.replace(16, 8, QByteArray("%PDF-1.4"));
    check(FileContentClassifier::classify(QStringLiteral("scan.pdf"), present(latePdf)) == V::Recognized,
          "a PDF header after a little leading junk is still a PDF");
    check(FileContentClassifier::hasKnownSignature(QByteArray::fromHex("d0cf11e0a1b11ae1") + filler(600, 10)),
          "OLE2 (legacy / password-protected Office) is a known format");
    check(FileContentClassifier::hasKnownSignature(QByteArray::fromHex("000000186674797069736f6d") + filler(600, 11)),
          "mp4 (ftyp box) is a known format");
    check(FileContentClassifier::hasKnownSignature(QByteArray("MZ") + filler(600, 12)), "PE is a known format");
    check(!FileContentClassifier::hasKnownSignature(scrambled(13)), "random bytes carry no known signature");

    FileContentSample gone;
    gone.kind = FileContentSample::Kind::Missing;
    FileContentSample busy;
    busy.kind = FileContentSample::Kind::Busy;
    check(FileContentClassifier::classify(jpgName, gone) == V::Unknown
              && FileContentClassifier::classify(jpgName, busy) == V::Unknown
              && FileContentClassifier::classify(jpgName, FileContentSample{}) == V::Unknown,
          "no content, no verdict");

    check(FileContentClassifier::entropyBits(QByteArray(1000, 'a')) < 0.001, "one repeated byte has no entropy");
    QByteArray all;
    for (int round = 0; round < 4; ++round)
        for (int v = 0; v < 256; ++v)
            all.append(static_cast<char>(v));
    check(FileContentClassifier::entropyBits(all) > 7.99, "all byte values equally often is 8 bits");
    check(FileContentClassifier::entropyBits(scrambled(14)) > 7.8, "the scrambled fixture really is high-entropy");
}

// 假磁盘 + 监控

constexpr qint64 kT0 = 1700000000000;   // 测试里的 0 时刻
constexpr qint64 kOld = -3600000;       // 一小时前就有的文件

QDateTime at(qint64 ms) { return QDateTime::fromMSecsSinceEpoch(kT0 + ms, QTimeZone::UTC); }

// 路径(小写、反斜杠)→ 这一刻盘上的文件。
struct FakeDisk {
    struct File {
        QByteArray head;
        qint64 createdMs = 0;
    };
    QHash<QString, File> files;
    bool busy = false;         // 读不到:被占用、读盘超时
    bool unreadable = false;   // 这个位置读不了:网络盘
    int reads = 0;

    void put(const QString& path, const QByteArray& head, qint64 createdMs) { files.insert(path, File{ head, createdMs }); }
    void take(const QString& path) { files.remove(path); }

    FileContentSample sample(const QString& path)
    {
        ++reads;
        FileContentSample s;
        if (unreadable)
            return s;
        if (busy) {
            s.kind = FileContentSample::Kind::Busy;
            return s;
        }
        const auto it = files.constFind(path);
        if (it == files.constEnd()) {
            s.kind = FileContentSample::Kind::Missing;
            return s;
        }
        return present(it->head);
    }

    RansomwareBehaviorMonitor::FileState state(const QString& path) const
    {
        RansomwareBehaviorMonitor::FileState st;
        const auto it = files.constFind(path);
        if (it == files.constEnd()) {
            st.kind = RansomwareBehaviorMonitor::FileState::Kind::Missing;
            return st;
        }
        st.kind = RansomwareBehaviorMonitor::FileState::Kind::Present;
        st.createdUtc = at(it->createdMs);
        return st;
    }
};

bulwark::SecurityEvent writeAt(int pid, const QString& target, qint64 ms)
{
    bulwark::SecurityEvent e = fileEvent(pid, target);
    e.timestampUtc = at(ms);
    return e;
}

bulwark::SecurityEvent deleteAt(int pid, const QString& target, qint64 ms)
{
    bulwark::SecurityEvent e = writeAt(pid, target, ms);
    e.type = bulwark::EventType::FileDelete;
    return e;
}

QString tickPath(qint64 ms) { return QStringLiteral("d:\\lab\\tick\\new-%1.tmp").arg(ms); }

struct Lab {
    FakeDisk disk;
    RansomwareBehaviorMonitor monitor;

    explicit Lab(bool inspectContent = true)
    {
        monitor.setFileStateProbe([this](const QString& p) { return disk.state(p); });
        if (inspectContent)
            monitor.setContentProbe([this](const QString& p) { return disk.sample(p); });
    }
    Lab(const Lab&) = delete;
    Lab& operator=(const Lab&) = delete;

    Result write(int pid, const QString& path, qint64 ms) { return monitor.observe(writeAt(pid, path, ms)); }
    Result remove(int pid, const QString& path, qint64 ms) { return monitor.observe(deleteAt(pid, path, ms)); }
    // 写一个全新的文件:本身不计入,只是让监控按时间回头看。
    Result tick(int pid, qint64 ms) { return write(pid, tickPath(ms), ms); }
    // 连着 count 个滴答(每毫秒一个),返回其间第一次报出的结果。
    Result ticks(int pid, qint64 fromMs, int count)
    {
        for (int i = 0; i < count; ++i) {
            const Result r = tick(pid, fromMs + i);
            if (r.score > 0)
                return r;
        }
        return {};
    }
};

QStringList numbered(const QString& pattern, int count)
{
    QStringList out;
    for (int i = 0; i < count; ++i)
        out << pattern.arg(i, 4, 10, QLatin1Char('0'));
    return out;
}

bool mentions(const Result& r, const char* utf8) { return r.reasons.join(QLatin1Char('|')).contains(QString::fromUtf8(utf8)); }

const QStringList& fourDocs()
{
    static const QStringList docs = {
        QStringLiteral("d:\\lab\\docs\\a\\q1.docx"), QStringLiteral("d:\\lab\\docs\\a\\q2.docx"),
        QStringLiteral("d:\\lab\\docs\\b\\q3.docx"), QStringLiteral("d:\\lab\\docs\\b\\q4.docx"),
    };
    return docs;
}

// 7-Zip 覆盖解压:逐个「删掉旧文件 → 建同名新文件」。NTFS 让新文件沿用旧的创建时间,写入事件是抽样上报的。
int firstAlertWhileExtracting(Lab& lab, int pid, const QStringList& paths)
{
    int first = -1;
    qint64 t = 0;
    for (int i = 0; i < paths.size(); ++i) {
        const bool onDelete = lab.remove(pid, paths.at(i), t).score > 0;
        lab.disk.put(paths.at(i), jpeg(static_cast<quint32>(500 + i)), kOld);
        const bool onWrite = i % 8 == 0 && lab.write(pid, paths.at(i), t + 1).score > 0;
        if (first < 0 && (onDelete || onWrite))
            first = i;
        t += 2;
    }
    return first;
}

void testOverwriteExtractionIsQuiet()
{
    const QStringList paths = numbered(QStringLiteral("d:\\lab\\photos\\img-%1.jpg"), 40);
    {
        Lab lab;
        for (int i = 0; i < paths.size(); ++i)
            lab.disk.put(paths.at(i), jpeg(static_cast<quint32>(i)), kOld);
        const int first = firstAlertWhileExtracting(lab, 7101, paths);
        const bool later = lab.ticks(7101, 200, 12).score > 0 || lab.ticks(7101, 2000, 12).score > 0
                           || lab.ticks(7101, 70000, 12).score > 0;
        check(first < 0 && !later, "overwrite extraction (delete, then re-create intact) raises nothing");
        check(lab.disk.reads > 0 && lab.disk.reads <= 2 * paths.size() + 8,
              "each overwritten file is looked at once or twice, no more");
    }
    {
        Lab lab(false);
        for (int i = 0; i < paths.size(); ++i)
            lab.disk.put(paths.at(i), jpeg(static_cast<quint32>(i)), kOld);
        check(firstAlertWhileExtracting(lab, 7102, paths) == 24,
              "without content inspection the same extraction alerts at the 25th file (the old rule)");
    }
}

void testFastExtractionStaysBounded()
{
    // 每毫秒覆盖 2 个文件,共 3000 个。
    const QStringList paths = numbered(QStringLiteral("d:\\lab\\tree\\f-%1.docx"), 3000);
    Lab lab;
    for (int i = 0; i < paths.size(); ++i)
        lab.disk.put(paths.at(i), docx(static_cast<quint32>(i)), kOld);
    bool alerted = false;
    for (int i = 0; i < paths.size(); ++i) {
        if (lab.remove(7201, paths.at(i), i / 2).score > 0)
            alerted = true;
        lab.disk.put(paths.at(i), docx(static_cast<quint32>(5000 + i)), kOld);
    }
    if (lab.ticks(7201, 1700, 60).score > 0)
        alerted = true;
    check(!alerted, "a fast 3000-file overwrite extraction raises nothing");
    check(lab.disk.reads == paths.size(), "and costs exactly one look per file");
}

void testPendingOverflow()
{
    // 同一毫秒里动了 1100 个文件,超过待定表容量(1024):挤出去的也要先看一眼内容再定。
    const QStringList paths = numbered(QStringLiteral("d:\\lab\\bulk\\b-%1.docx"), 1100);
    {
        Lab lab;
        bool alerted = false;
        for (int i = 0; i < paths.size(); ++i) {
            lab.disk.put(paths.at(i), docx(static_cast<quint32>(i)), kOld);
            if (lab.remove(7301, paths.at(i), 0).score > 0)
                alerted = true;
        }
        check(!alerted && lab.disk.reads == paths.size() - 1024,
              "overflowing files that are intact are let go after one look");
    }
    {
        Lab lab;
        Result hit;
        for (int i = 0; i < paths.size(); ++i) {
            const Result r = lab.remove(7302, paths.at(i), 0);   // 文件真的没了
            if (r.score > 0 && hit.score == 0)
                hit = r;
        }
        check(hit.score >= 50 && hit.containmentRequired && !hit.hardSignal,
              "overflowing files that are really gone are counted as deletions");
    }
}

void testMassDeleteStillAlerts()
{
    const QStringList paths = numbered(QStringLiteral("d:\\lab\\archive\\doc-%1.docx"), 30);
    Lab lab;
    bool early = false;
    for (int i = 0; i < paths.size(); ++i) {
        lab.disk.put(paths.at(i), docx(static_cast<quint32>(i)), kOld);
        if (lab.remove(7401, paths.at(i), 2 * i).score > 0)
            early = true;
        lab.disk.take(paths.at(i));
    }
    const Result r = lab.ticks(7401, 200, 20);
    check(!early && r.score >= 50 && r.containmentRequired && !r.hardSignal && mentions(r, "改写 / 删除"),
          "deleting 30 existing documents still alerts once the deletions are confirmed");
}

void testInPlaceEncryption()
{
    {
        // 跨两个目录:第 4 个就报。事件到达时内容已经被就地加密。
        Lab lab;
        const QStringList& docs = fourDocs();
        Result last;
        bool early = false;
        for (int i = 0; i < docs.size(); ++i) {
            lab.disk.put(docs.at(i), scrambled(static_cast<quint32>(i)), kOld);
            last = lab.write(7501, docs.at(i), 5 * i);
            if (i < docs.size() - 1 && last.score > 0)
                early = true;
        }
        check(!early && last.score >= 50 && last.containmentRequired && !last.hardSignal
                  && mentions(last, "无法识别") && mentions(last, "q1.docx"),
              "4 existing documents turned into ciphertext across two folders alert at the 4th, naming files");
        const Result after = lab.tick(7501, 40);
        check(after.score >= 50 && after.containmentRequired,
              "subsequent activity retains containment while the original decision is pending");
    }
    {
        // 同一目录同一种文件:要 8 个。
        Lab lab;
        const QStringList pics = numbered(QStringLiteral("d:\\lab\\album\\p-%1.jpg"), 8);
        int firstAlert = -1;
        for (int i = 0; i < pics.size(); ++i) {
            lab.disk.put(pics.at(i), scrambled(static_cast<quint32>(i)), kOld);
            if (lab.write(7502, pics.at(i), 5 * i).score > 0 && firstAlert < 0)
                firstAlert = i;
        }
        check(firstAlert == 7, "ciphertext confined to one folder and one file type needs 8 files");
    }
    {
        // 同一目录两种文件:4 个。
        Lab lab;
        const QStringList mixed = {
            QStringLiteral("d:\\lab\\mix\\a.jpg"), QStringLiteral("d:\\lab\\mix\\b.jpg"),
            QStringLiteral("d:\\lab\\mix\\c.pdf"), QStringLiteral("d:\\lab\\mix\\d.xlsx"),
        };
        int firstAlert = -1;
        for (int i = 0; i < mixed.size(); ++i) {
            lab.disk.put(mixed.at(i), scrambled(static_cast<quint32>(i)), kOld);
            if (lab.write(7503, mixed.at(i), 5 * i).score > 0 && firstAlert < 0)
                firstAlert = i;
        }
        check(firstAlert == 3, "ciphertext across file types in one folder alerts at the 4th");
    }
    {
        // 写入事件先到、内容后变:当场看到的还是旧内容,50ms 后回头看才是乱码。
        Lab lab;
        const QStringList& docs = fourDocs();
        bool early = false;
        for (int i = 0; i < docs.size(); ++i) {
            lab.disk.put(docs.at(i), docx(static_cast<quint32>(i)), kOld);
            if (lab.write(7504, docs.at(i), i).score > 0)
                early = true;
            lab.disk.put(docs.at(i), scrambled(static_cast<quint32>(i)), kOld);
        }
        const Result r = lab.ticks(7504, 60, 3);
        check(!early && r.score >= 50 && r.containmentRequired && mentions(r, "无法识别"),
              "a write that lands after its event is caught at the look-back");
    }
    {
        // 保存文档:内容换了,但还是好文档。
        Lab lab;
        const QStringList docs = numbered(QStringLiteral("d:\\lab\\work\\draft-%1.docx"), 40);
        bool alerted = false;
        for (int i = 0; i < docs.size(); ++i) {
            lab.disk.put(docs.at(i), docx(static_cast<quint32>(i)), kOld);
            if (lab.write(7505, docs.at(i), 3 * i).score > 0)
                alerted = true;
            lab.disk.put(docs.at(i), docx(static_cast<quint32>(900 + i)), kOld);
        }
        if (lab.ticks(7505, 300, 12).score > 0 || lab.ticks(7505, 2000, 12).score > 0)
            alerted = true;
        check(!alerted, "rewriting 40 existing documents with intact content raises nothing");
    }
}

void testRenameWithAddedSuffix()
{
    const QStringList& docs = fourDocs();
    {
        // 事件到达时改名已经完成:源路径不在了,目标沿用原文件的创建时间。
        Lab lab;
        int firstAlert = -1;
        for (int i = 0; i < docs.size(); ++i) {
            const QString renamed = docs.at(i) + QStringLiteral(".k7x");
            lab.disk.put(renamed, scrambled(static_cast<quint32>(i)), kOld);
            const bool onSource = lab.write(7601, docs.at(i), 4 * i).score > 0;
            const bool onTarget = lab.write(7601, renamed, 4 * i).score > 0;
            if ((onSource || onTarget) && firstAlert < 0)
                firstAlert = i;
        }
        check(firstAlert == 3, "encrypt-and-rename (q1.docx -> q1.docx.k7x) alerts at the 4th file");
    }
    {
        // 事件先到、改名后落地;同一目录同一种文件的 4 个。源和目标是同一个受害文件,不能数成 8 个。
        Lab lab;
        const QStringList pics = numbered(QStringLiteral("d:\\lab\\album\\p-%1.jpg"), 4);
        bool alerted = false;
        for (int i = 0; i < pics.size(); ++i) {
            lab.disk.put(pics.at(i), scrambled(static_cast<quint32>(i)), kOld);
            if (lab.write(7602, pics.at(i), 4 * i).score > 0)
                alerted = true;
            if (lab.write(7602, pics.at(i) + QStringLiteral(".k7x"), 4 * i).score > 0)
                alerted = true;
        }
        for (int i = 0; i < pics.size(); ++i) {
            lab.disk.take(pics.at(i));
            lab.disk.put(pics.at(i) + QStringLiteral(".k7x"), scrambled(static_cast<quint32>(i)), kOld);
        }
        if (lab.ticks(7602, 100, 6).score > 0 || lab.ticks(7602, 1700, 6).score > 0)
            alerted = true;
        check(!alerted, "a renamed victim is counted once, not once per name");
    }
}

void testCipherCopies()
{
    const QStringList& docs = fourDocs();
    {
        // 先在旁边写出加密副本,再删原件。
        Lab lab;
        bool early = false;
        for (int i = 0; i < docs.size(); ++i) {
            lab.disk.put(docs.at(i), docx(static_cast<quint32>(i)), kOld);
            const QString copy = docs.at(i) + QStringLiteral(".k7x");
            lab.disk.put(copy, scrambled(static_cast<quint32>(i)), i);
            if (lab.write(7701, copy, i).score > 0)
                early = true;
        }
        if (lab.ticks(7701, 100, 3).score > 0)
            early = true;
        check(!early, "ciphertext copies alone do not alert while the originals are still there");
        int firstAlert = -1;
        for (int i = 0; i < docs.size(); ++i) {
            lab.disk.take(docs.at(i));
            if (lab.remove(7701, docs.at(i), 200 + i).score > 0 && firstAlert < 0)
                firstAlert = i;
        }
        check(firstAlert == 3, "deleting the originals of 4 ciphertext copies alerts at the 4th, without waiting");
    }
    {
        // 先删原件,副本随后才被看到。
        Lab lab;
        bool early = false;
        for (int i = 0; i < docs.size(); ++i) {
            lab.disk.put(docs.at(i), docx(static_cast<quint32>(i)), kOld);
            if (lab.remove(7702, docs.at(i), i).score > 0)
                early = true;
            lab.disk.take(docs.at(i));
        }
        for (int i = 0; i < docs.size(); ++i) {
            const QString copy = docs.at(i) + QStringLiteral(".k7x");
            lab.disk.put(copy, scrambled(static_cast<quint32>(i)), 10 + i);
            if (lab.write(7702, copy, 10 + i).score > 0)
                early = true;
        }
        const Result r = lab.ticks(7702, 100, 3);
        check(!early && r.score >= 50 && r.containmentRequired && mentions(r, "无法识别"),
              "originals deleted before their ciphertext copies are seen are matched up afterwards");
    }
    {
        // 下载工具、加密工具的产物不算乱码副本。
        Lab lab;
        bool alerted = false;
        for (int i = 0; i < 12; ++i) {
            const QString original = QStringLiteral("d:\\lab\\sync\\%1\\report.docx").arg(i);
            lab.disk.put(original, docx(static_cast<quint32>(i)), kOld);
            const QString out = original + (i % 2 == 0 ? QStringLiteral(".gpg") : QStringLiteral(".crdownload"));
            lab.disk.put(out, scrambled(static_cast<quint32>(i)), i);
            if (lab.write(7703, out, i).score > 0)
                alerted = true;
        }
        check(!alerted && lab.disk.reads == 0, "output of encryption / download tools is not even looked at");
    }
}

void testRansomwareExtensionNeedsBinaryContent()
{
    {
        Lab lab;
        bool alerted = false;
        for (int i = 0; i < 6; ++i) {
            const QString book = QStringLiteral("d:\\lab\\books\\vol-%1.djvu").arg(i);
            lab.disk.put(book, djvu(static_cast<quint32>(i)), i);
            if (lab.write(7801, book, i).score > 0)
                alerted = true;
        }
        if (lab.ticks(7801, 2000, 6).score > 0)
            alerted = true;
        check(!alerted, "real DjVu books are not ransomware output");
    }
    {
        Lab lab;
        bool alerted = false;
        for (int i = 0; i < 3; ++i) {
            const QString lock = QStringLiteral("d:\\lab\\work\\job-%1.locked").arg(i);
            lab.disk.put(lock, QByteArray("pid 4242\n"), i);
            if (lab.write(7802, lock, i).score > 0)
                alerted = true;
            const QString flag = QStringLiteral("d:\\lab\\work\\run-%1.lockfile").arg(i);
            lab.disk.put(flag, QByteArray(), i);
            if (lab.write(7802, flag, i).score > 0)
                alerted = true;
        }
        for (qint64 t = 2000; t <= 12000; t += 2000)
            if (lab.ticks(7802, t, 3).score > 0)
                alerted = true;
        check(!alerted, "text and empty lock files named .locked / .lockfile are not ransomware output");
    }
    {
        Lab lab;
        const QStringList& docs = fourDocs();
        Result third;
        bool early = false;
        for (int i = 0; i < 3; ++i) {
            const QString out = docs.at(i) + QStringLiteral(".lockbit");
            lab.disk.put(out, scrambled(static_cast<quint32>(i)), kOld);
            third = lab.write(7803, out, i);
            if (i < 2 && third.score > 0)
                early = true;
        }
        check(!early && third.score >= 60 && third.hardSignal,
              "binary content under a known ransomware extension is a hard signal at the 3rd file");
        const Result next = lab.tick(7803, 10);
        check(next.score >= 60 && next.hardSignal, "once convicted, every further write keeps reporting");
    }
    {
        Lab lab(false);
        int firstAlert = -1;
        for (int i = 0; i < 6; ++i) {
            const QString book = QStringLiteral("d:\\lab\\books\\vol-%1.djvu").arg(i);
            if (lab.write(7804, book, i).score > 0 && firstAlert < 0)
                firstAlert = i;
        }
        check(firstAlert == 2, "without content inspection the extension alone still counts (the old rule)");
    }
}

void testKernelDeniedOperationsDoNotCount()
{
    const QStringList paths = numbered(QStringLiteral("d:\\lab\\guarded\\doc-%1.docx"), 30);
    for (const bool inspect : { false, true }) {
        Lab lab(inspect);
        bool alerted = false;
        for (int i = 0; i < paths.size(); ++i) {
            lab.disk.put(paths.at(i), docx(static_cast<quint32>(i)), kOld);
            bulwark::SecurityEvent e = deleteAt(7901, paths.at(i), i);
            e.kernelBlocked = true;
            if (lab.monitor.observe(e).score > 0)
                alerted = true;
        }
        if (lab.ticks(7901, 2000, 6).score > 0)
            alerted = true;
        check(!alerted && lab.disk.reads == 0,
              inspect ? "operations the kernel refused are not counted (content mode)"
                      : "operations the kernel refused are not counted (count-only mode)");
    }
}

void testRansomNotesShareOneName()
{
    {
        Lab lab;
        const bool a = lab.write(8001, QStringLiteral("d:\\lab\\manual\\a\\how-to-decrypt-archives.html"), 0).score > 0;
        const bool b = lab.write(8001, QStringLiteral("d:\\lab\\manual\\b\\decrypt-tool-guide.html"), 1).score > 0;
        const bool c = lab.write(8001, QStringLiteral("d:\\lab\\manual\\c\\decrypt_faq.txt"), 2).score > 0;
        check(!a && !b && !c, "three differently named pages about decryption are not a ransom note campaign");
    }
    {
        Lab lab;
        const bool a = lab.write(8002, QStringLiteral("d:\\lab\\docs\\a\\_readme.txt"), 0).score > 0;
        const bool b = lab.write(8002, QStringLiteral("d:\\lab\\docs\\b\\_readme.txt"), 1).score > 0;
        const Result c = lab.write(8002, QStringLiteral("d:\\lab\\docs\\c\\_readme.txt"), 2);
        check(!a && !b && c.score >= 60 && c.hardSignal, "the same note dropped into 3 folders is a hard signal");
    }
}

void testUnknownTypesFollowTheOldRule()
{
    {
        Lab lab;
        const QStringList saves = numbered(QStringLiteral("d:\\lab\\save\\slot-%1.dat"), 30);
        bool early = false;
        for (int i = 0; i < saves.size(); ++i) {
            lab.disk.put(saves.at(i), scrambled(static_cast<quint32>(i)), kOld);
            if (lab.write(8101, saves.at(i), i).score > 0)
                early = true;
        }
        if (lab.ticks(8101, 300, 12).score > 0)
            early = true;
        const Result r = lab.ticks(8101, 1600, 20);
        check(!early && r.score >= 50 && r.containmentRequired && mentions(r, "改写 / 删除"),
              "30 rewritten files of an unknown type alert by the old rule once they have settled");
    }
    {
        Lab lab;
        const QStringList saves = numbered(QStringLiteral("d:\\lab\\save\\slot-%1.dat"), 20);
        bool alerted = false;
        for (int i = 0; i < saves.size(); ++i) {
            lab.disk.put(saves.at(i), scrambled(static_cast<quint32>(i)), kOld);
            if (lab.write(8102, saves.at(i), i).score > 0)
                alerted = true;
        }
        if (lab.ticks(8102, 1600, 20).score > 0)
            alerted = true;
        check(!alerted, "20 rewritten files of an unknown type stay under the old threshold");
    }
    {
        // 批量改名 / 移走:动过的已有文件不见了,按原来的算法计入。
        Lab lab;
        const QStringList docs = numbered(QStringLiteral("d:\\lab\\inbox\\scan-%1.pdf"), 30);
        bool early = false;
        for (int i = 0; i < docs.size(); ++i) {
            lab.disk.put(docs.at(i), pdf(static_cast<quint32>(i)), kOld);
            if (lab.write(8103, docs.at(i), i).score > 0)
                early = true;
            lab.disk.take(docs.at(i));
        }
        if (lab.ticks(8103, 300, 12).score > 0)
            early = true;
        const Result r = lab.ticks(8103, 1600, 20);
        check(!early && r.score >= 50 && r.containmentRequired,
              "30 existing files that vanish after being touched alert by the old rule");
    }
}

void testBusyReadsAreRetried()
{
    const QStringList paths = numbered(QStringLiteral("d:\\lab\\photos\\img-%1.jpg"), 30);
    {
        Lab lab;
        for (int i = 0; i < paths.size(); ++i)
            lab.disk.put(paths.at(i), jpeg(static_cast<quint32>(i)), kOld);
        lab.disk.busy = true;
        bool alerted = false;
        for (int i = 0; i < paths.size(); ++i)
            if (lab.remove(8201, paths.at(i), i).score > 0)
                alerted = true;
        for (const qint64 t : { 100, 300, 800, 1700 })
            if (lab.ticks(8201, t, 10).score > 0)
                alerted = true;
        check(!alerted, "reads that time out or hit a locked file are retried, never counted");
        lab.disk.busy = false;
        if (lab.ticks(8201, 3300, 20).score > 0)
            alerted = true;
        check(!alerted, "and the files turn out intact once they can be read");
    }
    {
        Lab lab;
        lab.disk.unreadable = true;
        bool early = false;
        for (int i = 0; i < paths.size(); ++i)
            if (lab.remove(8202, paths.at(i), i).score > 0)
                early = true;
        const Result r = lab.ticks(8202, 100, 20);
        check(!early && r.score >= 50 && r.containmentRequired,
              "where content cannot be read at all (network drive) the old rule applies");
    }
}

void testShortBurstsSettleLater()
{
    {
        // 一阵很短的删除,没来得及回头看就停了:它下一次有动静时单独结账。
        const QStringList paths = numbered(QStringLiteral("d:\\lab\\archive\\doc-%1.docx"), 30);
        Lab lab;
        bool early = false;
        for (int i = 0; i < paths.size(); ++i)
            if (lab.remove(8301, paths.at(i), i / 6).score > 0)
                early = true;
        const Result r = lab.ticks(8301, 300000, 5);
        check(!early && r.score >= 50 && r.containmentRequired,
              "a burst too short to be looked at is settled at the process's next activity");
    }
    {
        // 相隔几分钟的两小阵各算各的。
        const QStringList paths = numbered(QStringLiteral("d:\\lab\\archive\\doc-%1.docx"), 30);
        Lab lab;
        bool alerted = false;
        for (int i = 0; i < 15; ++i)
            if (lab.remove(8302, paths.at(i), i / 6).score > 0)
                alerted = true;
        for (int i = 15; i < 30; ++i)
            if (lab.remove(8302, paths.at(i), 300000 + 2 * i).score > 0)
                alerted = true;
        if (lab.ticks(8302, 300200, 20).score > 0 || lab.ticks(8302, 302000, 20).score > 0)
            alerted = true;
        check(!alerted, "two small bursts minutes apart are not added together");
    }
}

void testEngineEndToEnd()
{
    const QStringList photos = numbered(QStringLiteral("d:\\lab\\photos\\img-%1.jpg"), 40);
    {
        // 未签名的解压工具覆盖 40 个已有文件:全程放行。
        FakeDisk disk;
        bulwark::engine::RuleEngine engine;
        engine.trustSignedActors = false;
        engine.setFileStateProbe([&disk](const QString& p) { return disk.state(p); });
        engine.setContentProbe([&disk](const QString& p) { return disk.sample(p); });
        bool allAllowed = true;
        for (int i = 0; i < photos.size(); ++i) {
            disk.put(photos.at(i), jpeg(static_cast<quint32>(i)), kOld);
            bulwark::SecurityEvent e = deleteAt(8401, photos.at(i), 2 * i);
            allAllowed = engine.evaluate(e).action == bulwark::VerdictAction::Allow && !e.hasThreatIndicator
                         && allAllowed;
            disk.put(photos.at(i), jpeg(static_cast<quint32>(700 + i)), kOld);
        }
        for (int i = 0; i < 20; ++i) {
            bulwark::SecurityEvent e = writeAt(8401, tickPath(2000 + i), 2000 + i);
            allAllowed = engine.evaluate(e).action == bulwark::VerdictAction::Allow && allAllowed;
        }
        check(allAllowed && disk.reads > 0, "engine: an unsigned extractor overwriting 40 files is allowed throughout");
    }
    {
        // 未签名程序就地加密 4 个文档。
        FakeDisk disk;
        bulwark::engine::RuleEngine engine;
        engine.trustSignedActors = false;
        engine.setFileStateProbe([&disk](const QString& p) { return disk.state(p); });
        engine.setContentProbe([&disk](const QString& p) { return disk.sample(p); });
        const QStringList& docs = fourDocs();
        bool early = false;
        bulwark::SecurityEvent last;
        bulwark::Verdict verdict;
        for (int i = 0; i < docs.size(); ++i) {
            disk.put(docs.at(i), scrambled(static_cast<quint32>(i)), kOld);
            last = writeAt(8402, docs.at(i), 5 * i);
            verdict = engine.evaluate(last);
            if (i < docs.size() - 1 && verdict.action != bulwark::VerdictAction::Allow)
                early = true;
        }
        check(!early && verdict.action != bulwark::VerdictAction::Allow && last.hasThreatIndicator
                  && last.ransomwareContainmentRequired,
              "engine: the 4th document turned into ciphertext is stopped and marked for containment");
    }
    {
        // Signed editors use the same content checks and retain valid images.
        FakeDisk disk;
        bulwark::engine::RuleEngine engine;
        engine.trustSignedActors = false;
        engine.setFileStateProbe([&disk](const QString& p) { return disk.state(p); });
        engine.setContentProbe([&disk](const QString& p) { return disk.sample(p); });
        for (int i = 0; i < photos.size(); ++i) {
            disk.put(photos.at(i), jpeg(static_cast<quint32>(i)), kOld);
            bulwark::SecurityEvent e = writeAt(8403, photos.at(i), 2 * i);
            e.actorPath = QStringLiteral("C:\\Lab\\signed-editor.exe");
            e.actorSigned = true;
            engine.evaluate(e);
        }
        check(disk.reads > 0, "engine: signed actors are subject to content inspection too");
    }
}

}

int main()
{
    testCanaryBlocksImmediately();
    testContentClassifier();
    testOverwriteExtractionIsQuiet();
    testFastExtractionStaysBounded();
    testPendingOverflow();
    testMassDeleteStillAlerts();
    testInPlaceEncryption();
    testRenameWithAddedSuffix();
    testCipherCopies();
    testRansomwareExtensionNeedsBinaryContent();
    testKernelDeniedOperationsDoNotCount();
    testRansomNotesShareOneName();
    testUnknownTypesFollowTheOldRule();
    testBusyReadsAreRetried();
    testShortBurstsSettleLater();
    testEngineEndToEnd();

    std::printf("%d checks, %d failed\n", gChecks, gFailed);
    return gFailed == 0 ? 0 : 1;
}
