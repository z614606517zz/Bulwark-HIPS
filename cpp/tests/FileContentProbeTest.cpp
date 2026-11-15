#include "bulwark/engine/FileContentClassifier.h"
#include "bulwark/service/FileContentProbe.h"

#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QString>
#include <QTemporaryDir>

#include <cstdio>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace {

using bulwark::engine::FileContentClassifier;
using bulwark::engine::FileContentSample;
using bulwark::service::FileContentProbe;
using Kind = FileContentSample::Kind;

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

bool writeFile(const QString& path, const QByteArray& bytes)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly))
        return false;
    const bool ok = f.write(bytes) == bytes.size();
    f.close();
    return ok;
}

QByteArray patterned(int size)
{
    QByteArray b(size, Qt::Uninitialized);
    for (int i = 0; i < size; ++i)
        b[i] = static_cast<char>('a' + i % 26);
    return b;
}

void testReadHead(const QString& dir)
{
    QByteArray body("PK\x03\x04", 4);
    body.append(patterned(996));
    const QString small = dir + QStringLiteral("/small.docx");
    check(writeFile(small, body), "fixture: small file written");
    const FileContentSample s = FileContentProbe::readHead(small);
    check(s.kind == Kind::Present && s.size == body.size() && s.head == body,
          "a small file is returned whole (forward slashes accepted)");

    const QByteArray bigBody = patterned(10000);
    const QString big = QDir::toNativeSeparators(dir + QStringLiteral("/big.bin"));
    check(writeFile(big, bigBody), "fixture: big file written");
    const FileContentSample b = FileContentProbe::readHead(big);
    check(b.kind == Kind::Present && b.size == 10000 && b.head.size() == FileContentClassifier::kHeadBytes
              && b.head == bigBody.left(FileContentClassifier::kHeadBytes),
          "only the head of a big file is read; the reported size is the real one");

    const QString empty = dir + QStringLiteral("/empty.txt");
    check(writeFile(empty, QByteArray()), "fixture: empty file written");
    const FileContentSample e = FileContentProbe::readHead(empty);
    check(e.kind == Kind::Present && e.size == 0 && e.head.isEmpty(), "an empty file is present with no content");

    check(FileContentProbe::readHead(dir + QStringLiteral("/absent.docx")).kind == Kind::Missing,
          "a file that does not exist is missing");
    check(FileContentProbe::readHead(dir + QStringLiteral("/no-such-dir/absent.docx")).kind == Kind::Missing,
          "a file under a directory that does not exist is missing");
    check(FileContentProbe::readHead(dir).kind == Kind::Missing, "a directory is not a file");

    // 网络路径、相对路径在任何读盘之前就被挡掉:服务器不可达时一次打开能卡数秒。
    check(FileContentProbe::readHead(QStringLiteral("\\\\nowhere.invalid\\share\\report.docx")).kind
              == Kind::Unavailable,
          "a network path is never opened");
    check(FileContentProbe::readHead(QStringLiteral("report.docx")).kind == Kind::Unavailable,
          "a relative path is not read");
    check(FileContentProbe::readHead(QString()).kind == Kind::Unavailable, "an empty path is not read");
}

void testBusyFiles(const QString& dir)
{
    const QString locked = QDir::toNativeSeparators(dir + QStringLiteral("/locked.xlsx"));
    check(writeFile(locked, patterned(2000)), "fixture: file to lock written");
    const std::wstring lockedW = locked.toStdWString();
    const HANDLE h = ::CreateFileW(lockedW.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
    check(h != INVALID_HANDLE_VALUE, "fixture: exclusive handle opened");
    check(FileContentProbe::readHead(locked).kind == Kind::Busy,
          "a file held exclusively by another handle is busy (retry later), not unreadable");
    if (h != INVALID_HANDLE_VALUE)
        ::CloseHandle(h);
    check(FileContentProbe::readHead(locked).kind == Kind::Present, "once released the same file is readable");

    // 删除已经下达、句柄还没关:文件马上就没了,不能当成「还在、内容完好」。
    const QString doomed = QDir::toNativeSeparators(dir + QStringLiteral("/doomed.pdf"));
    check(writeFile(doomed, QByteArray("%PDF-1.7\n") + patterned(500)), "fixture: file to delete written");
    const std::wstring doomedW = doomed.toStdWString();
    const HANDLE d = ::CreateFileW(doomedW.c_str(), DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    FILE_DISPOSITION_INFO info{};
    info.DeleteFile = TRUE;
    const bool marked = d != INVALID_HANDLE_VALUE
                        && ::SetFileInformationByHandle(d, FileDispositionInfo, &info, sizeof(info)) != FALSE;
    check(marked, "fixture: file marked delete-pending");
    const Kind pending = FileContentProbe::readHead(doomed).kind;
    check(pending == Kind::Busy || pending == Kind::Missing, "a delete-pending file is never reported as present");
    if (d != INVALID_HANDLE_VALUE)
        ::CloseHandle(d);
    check(FileContentProbe::readHead(doomed).kind == Kind::Missing,
          "after the last handle closes the deleted file is missing");
}

void testThreadedProbe(const QString& dir)
{
    const QByteArray body = QByteArray("%PDF-1.7\n") + patterned(3000);
    const QString path = QDir::toNativeSeparators(dir + QStringLiteral("/report.pdf"));
    check(writeFile(path, body), "fixture: probe file written");

    // 超时放宽:测试机正忙时一次读盘也可能慢,这里只验证问答不串。
    FileContentProbe probe(5000);
    bool same = true;
    for (int i = 0; i < 200; ++i) {
        const FileContentSample s = probe.sample(path);
        same = same && s.kind == Kind::Present && s.head == body && s.size == body.size();
    }
    check(same, "the threaded probe returns the file's content on every call");
    check(probe.sample(dir + QStringLiteral("/absent.bin")).kind == Kind::Missing,
          "the threaded probe reports a missing file as missing");
    const FileContentSample again = probe.sample(path);
    check(again.kind == Kind::Present && again.head == body, "answers do not leak from one request to the next");

    {
        FileContentProbe shortLived(5000);
        check(shortLived.sample(path).kind == Kind::Present, "a second probe works independently");
    }
    check(probe.sample(path).kind == Kind::Present, "the first probe still works after another one is destroyed");
}

}

int main()
{
    QTemporaryDir work;
    if (!work.isValid()) {
        std::fprintf(stderr, "FAIL: cannot create a temporary directory\n");
        return 1;
    }
    const QString dir = work.path();

    testReadHead(dir);
    testBusyFiles(dir);
    testThreadedProbe(dir);

    std::printf("%d checks, %d failed\n", gChecks, gFailed);
    return gFailed == 0 ? 0 : 1;
}
