#include "bulwark/service/MaintenanceGate.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QFile>
#include <QLocalSocket>
#include <QProcess>
#include <QString>
#include <QStringList>
#include <QTemporaryDir>
#include <QTimer>

#include <cstdio>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

namespace {

using bulwark::service::MaintenanceGate;

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

void checkReply(const QByteArray& got, const char* want, const char* name)
{
    ++gChecks;
    if (got == want)
        return;
    ++gFailed;
    std::fprintf(stderr, "FAIL: %s (got '%s', want '%s')\n", name, got.constData(), want);
}

int gSkipped = 0;

// 这一项因为运行环境没能跑成,没有结论:不算通过,也不算失败。
void skip(const char* name, const QByteArray& why)
{
    ++gSkipped;
    std::fprintf(stderr, "SKIP: %s (%s)\n", name, why.constData());
}

bool writeFile(const QString& path, const QByteArray& bytes)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly))
        return false;
    return f.write(bytes) == bytes.size();
}

QByteArray readFile(const QString& path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return QByteArray();
    return f.readAll();
}

bool selfIsElevated()
{
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    TOKEN_ELEVATION elevation{};
    DWORD got = 0;
    const bool elevated = ::GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &got)
        && elevation.TokenIsElevated != 0;
    ::CloseHandle(token);
    return elevated;
}

// 只活在本进程内存里的临时签名密钥:测试不碰发布密钥,也不往密钥库里写东西。
struct TestKey {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    QByteArray publicXY;

    TestKey()
    {
        if (!BCRYPT_SUCCESS(::BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0)))
            return;
        if (!BCRYPT_SUCCESS(::BCryptGenerateKeyPair(algorithm, &key, 256, 0))
            || !BCRYPT_SUCCESS(::BCryptFinalizeKeyPair(key, 0)))
            return;
        UCHAR blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64] = {};
        ULONG got = 0;
        if (BCRYPT_SUCCESS(::BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof(blob), &got, 0))
            && got == sizeof(blob))
            publicXY = QByteArray(reinterpret_cast<const char*>(blob) + sizeof(BCRYPT_ECCKEY_BLOB), 64);
    }
    ~TestKey()
    {
        if (key)
            ::BCryptDestroyKey(key);
        if (algorithm)
            ::BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    TestKey(const TestKey&) = delete;
    TestKey& operator=(const TestKey&) = delete;

    // 按发布签名的格式给 content 追加标记和签名。
    QByteArray sign(const QByteArray& content) const
    {
        QByteArray digest = QCryptographicHash::hash(content, QCryptographicHash::Sha256);
        UCHAR signature[64] = {};
        ULONG got = 0;
        if (!BCRYPT_SUCCESS(::BCryptSignHash(key, nullptr, reinterpret_cast<PUCHAR>(digest.data()),
                                            static_cast<ULONG>(digest.size()), signature,
                                            sizeof(signature), &got, 0))
            || got != sizeof(signature))
            return QByteArray();
        QByteArray out = content;
        out.append("BULWARK-RELSIG1", 16);
        out.append(reinterpret_cast<const char*>(signature), sizeof(signature));
        return out;
    }
};

// 连上通道、发出请求,返回服务端答复的第一行。客户端和服务端在同一个进程里,靠轮询事件循环推进。
QByteArray roundTrip(const QString& pipe, const QByteArray& request)
{
    QLocalSocket client;
    client.connectToServer(pipe);
    QElapsedTimer timer;
    timer.start();
    while (client.state() != QLocalSocket::ConnectedState && timer.elapsed() < 5000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        client.waitForConnected(20);
    }
    if (client.state() != QLocalSocket::ConnectedState)
        return QByteArray("<no connection>");
    client.write(request);
    client.flush();
    QByteArray reply;
    while (!reply.contains('\n') && timer.elapsed() < 8000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        client.waitForReadyRead(20);
        reply += client.readAll();
    }
    client.disconnectFromServer();
    QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    return reply.trimmed();
}

void letGateSettle(int milliseconds)
{
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < milliseconds) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        ::Sleep(5);
    }
}

struct ClientRun {
    // false:子进程没跑成(起不来,或者一个字都没输出就被外部结束),通道的行为无从判断。
    bool conclusive = true;
    QByteArray reply;
};

// 把 exe 当作客户端起一个子进程去连通道(见 client()),返回它打印的答复。服务端在本进程,靠轮询推进。
ClientRun runClient(const QString& exe, const QString& pipe, const QString& request)
{
    QProcess process;
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start(exe, {QStringLiteral("--client"), pipe, request});
    QElapsedTimer timer;
    timer.start();
    while (process.state() != QProcess::NotRunning && timer.elapsed() < 20000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        process.waitForFinished(20);
    }
    if (process.state() != QProcess::NotRunning) {
        process.kill();
        process.waitForFinished(2000);
        return {true, QByteArray("<client did not finish>")};
    }
    if (process.error() == QProcess::FailedToStart)
        return {false, "<client failed to start: " + process.errorString().toUtf8() + '>'};
    const QByteArray output = process.readAllStandardOutput().trimmed();
    // client() 自己只会以 0、2、3 退出,而且退出前必定打印一行;没有输出、退出码 1,是被外部 TerminateProcess 的样子。
    if (output.isEmpty() && process.exitStatus() == QProcess::NormalExit && process.exitCode() == 1)
        return {false, QByteArray("<client was terminated from outside before it printed anything>")};
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        return {true, output + " <client exit code 0x"
                          + QByteArray::number(static_cast<quint32>(process.exitCode()), 16) + '>'};
    }
    return {true, output};
}

void testSignatureFormat(const QByteArray& content)
{
    const TestKey key;
    const TestKey otherKey;
    check(key.publicXY.size() == 64 && otherKey.publicXY.size() == 64, "temporary signing keys");

    const QByteArray good = key.sign(content);
    check(good.size() == content.size() + MaintenanceGate::kReleaseTrailerBytes, "signed copy carries the trailer");
    check(MaintenanceGate::verifyReleaseSignature(good, key.publicXY), "valid release signature is accepted");
    check(!MaintenanceGate::verifyReleaseSignature(good, otherKey.publicXY),
          "signature made with another key is rejected");
    check(!MaintenanceGate::verifyReleaseSignature(good, QByteArray()), "empty public key rejects everything");
    check(!MaintenanceGate::verifyReleaseSignature(good, QByteArray(64, '\0')), "all-zero public key is rejected");
    check(!MaintenanceGate::verifyReleaseSignature(content, key.publicXY), "unsigned content is rejected");

    QByteArray tamperedContent = good;
    tamperedContent[100] = static_cast<char>(tamperedContent.at(100) ^ 0x01);
    check(!MaintenanceGate::verifyReleaseSignature(tamperedContent, key.publicXY),
          "one changed content byte invalidates the signature");

    QByteArray tamperedSignature = good;
    tamperedSignature[good.size() - 1] = static_cast<char>(good.at(good.size() - 1) ^ 0x01);
    check(!MaintenanceGate::verifyReleaseSignature(tamperedSignature, key.publicXY),
          "one changed signature byte is rejected");

    QByteArray extended = good;
    extended.append('\0');
    check(!MaintenanceGate::verifyReleaseSignature(extended, key.publicXY),
          "data appended after the signature is rejected");
    check(!MaintenanceGate::verifyReleaseSignature(good.right(MaintenanceGate::kReleaseTrailerBytes), key.publicXY),
          "a bare trailer is rejected");
}

// 安装程序这条路核对的是「请求方进程的映像」,所以要真的起进程:把本程序复制出几份(签名、错密钥、签后被改),
// 让它们以客户端身份来连。
void testSignedInstallerClients(const QByteArray& content, const QString& dir, const QString& unrelatedReference,
                                const MaintenanceGate::Options& relaxed)
{
    const TestKey key;
    const TestKey otherKey;

    const QByteArray signedImage = key.sign(content);
    QByteArray tampered = signedImage;
    // DOS 存根里的提示文字,改一个字节不影响程序运行。
    tampered[0x50] = static_cast<char>(tampered.at(0x50) ^ 0x01);

    const QString pipe = QStringLiteral("Bulwark.Maintenance.Test.Signed.%1").arg(::GetCurrentProcessId());
    MaintenanceGate::Options options = relaxed;
    options.releasePublicKey = key.publicXY;

    int granted = 0;
    int rejected = 0;
    MaintenanceGate::Requester lastGranted = MaintenanceGate::Requester::None;
    MaintenanceGate gate;
    gate.setOptions(options);
    gate.onStandbyRequested = [&granted, &lastGranted](const MaintenanceGate::Verdict& v) {
        ++granted;
        lastGranted = v.requester;
        return true;
    };
    gate.onRejected = [&rejected](const MaintenanceGate::Verdict& v) {
        ++rejected;
        std::fprintf(stderr, "note: rejected: %s\n", v.reason.toUtf8().constData());
    };
    check(gate.start(pipe, unrelatedReference), "gate listens for installer clients");

    // 每次尝试都写一份新文件再起进程。装着实时防护的机器上,这种刚落地就执行的程序偶尔会被安全软件结束并移走
    // (子进程没有输出、退出码 1,随后同一个文件拒绝访问、再后来不存在)。那样的一次尝试说明不了通道的行为:
    // 换一份文件重来,三次都没跑成就记为跳过,不记为通过也不记为失败。
    int serial = 0;
    const auto expect = [&](const QByteArray& image, const char* request, const char* want, int wantGranted,
                            int wantRejected, const char* name) {
        const QByteArray callbacks = QByteArray(name) + " (callbacks reached)";
        QByteArray why;
        for (int round = 0; round < 3; ++round) {
            const QString exe = dir + QStringLiteral("/client-%1.exe").arg(++serial);
            if (!writeFile(exe, image)) {
                check(false, "write a signed client copy");
                return;
            }
            const int grantedBefore = granted;
            const int rejectedBefore = rejected;
            const ClientRun run = runClient(exe, pipe, QString::fromLatin1(request));
            if (run.conclusive) {
                checkReply(run.reply, want, name);
                check(granted - grantedBefore == wantGranted && rejected - rejectedBefore == wantRejected,
                      callbacks.constData());
                return;
            }
            why = run.reply;
            std::fprintf(stderr, "note: attempt %d of '%s': %s\n", round + 1, name, why.constData());
            // 被结束的子进程可能已经把请求写进了管道:先让通道把它处理完,免得算到下一次尝试头上。
            letGateSettle(300);
        }
        skip(name, why);
    };

    expect(signedImage, "BULWARK-INSTALL 1", "OK", 1, 0,
           "process whose image carries a valid release signature is granted");
    check(granted == 0 || lastGranted == MaintenanceGate::Requester::SignedInstaller,
          "signed installer reaches the standby callback as an installer");
    expect(signedImage, "BULWARK-UNINSTALL 1", "DENY", 0, 1,
           "signed installer may not send the uninstaller's request");
    expect(otherKey.sign(content), "BULWARK-INSTALL 1", "DENY", 0, 1, "image signed with another key is denied");
    expect(tampered, "BULWARK-INSTALL 1", "DENY", 0, 1, "image modified after signing is denied");

    gate.setOptions(relaxed);
    expect(signedImage, "BULWARK-INSTALL 1", "DENY", 0, 1,
           "without a configured public key no installer is granted");
}

void runTests()
{
    const quint32 pid = static_cast<quint32>(::GetCurrentProcessId());
    QTemporaryDir tmp;
    check(tmp.isValid(), "temporary directory");

    const QByteArray bytes = readFile(QCoreApplication::applicationFilePath());
    check(bytes.size() > 1024, "read own image");
    QByteArray flipped = bytes;
    flipped[flipped.size() - 1] = static_cast<char>(flipped.at(flipped.size() - 1) ^ 0x01);

    const QString same = tmp.filePath(QStringLiteral("same.exe"));
    const QString differ = tmp.filePath(QStringLiteral("differ.exe"));
    const QString shorter = tmp.filePath(QStringLiteral("shorter.exe"));
    check(writeFile(same, bytes) && writeFile(differ, flipped)
              && writeFile(shorter, bytes.left(bytes.size() - 1)),
          "write reference files");

    MaintenanceGate::Options relaxed;
    relaxed.requireElevatedAdministrator = false;
    relaxed.requireInteractiveSession = false;

    const MaintenanceGate::Verdict accepted = MaintenanceGate::verifyClient(pid, same, relaxed);
    check(accepted.ok && accepted.requester == MaintenanceGate::Requester::Uninstaller,
          "process whose image equals the reference is accepted as the uninstaller");
    check(!MaintenanceGate::verifyClient(pid, differ, relaxed).ok,
          "one differing byte is rejected");
    check(!MaintenanceGate::verifyClient(pid, shorter, relaxed).ok,
          "reference of a different length is rejected");
    check(!MaintenanceGate::verifyClient(pid, tmp.filePath(QStringLiteral("missing.exe")), relaxed).ok,
          "missing reference is rejected");
    check(!MaintenanceGate::verifyClient(0, same, relaxed).ok, "pid 0 is rejected");
    check(!MaintenanceGate::verifyClient(4, same, relaxed).ok, "the System process is rejected");

    DWORD session = 0;
    ::ProcessIdToSessionId(static_cast<DWORD>(pid), &session);
    const bool strictShouldPass = selfIsElevated() && session > 0;
    check(MaintenanceGate::verifyClient(pid, same, MaintenanceGate::Options{}).ok == strictShouldPass,
          "default options demand an elevated client in an interactive session");

    const QString pipe = QStringLiteral("Bulwark.Maintenance.Test.%1").arg(pid);
    {
        int granted = 0;
        int rejected = 0;
        MaintenanceGate gate;
        gate.setOptions(relaxed);
        gate.onStandbyRequested = [&granted](const MaintenanceGate::Verdict& v) {
            ++granted;
            return v.ok;
        };
        gate.onRejected = [&rejected](const MaintenanceGate::Verdict&) { ++rejected; };
        check(gate.start(pipe, same), "gate listens");

        checkReply(roundTrip(pipe, "BULWARK-UNINSTALL 1\n"), "OK",
              "well-formed request from a verified client is granted");
        check(granted == 1 && rejected == 0, "grant callback ran exactly once");
        checkReply(roundTrip(pipe, "BULWARK-UNINSTALL 1\r\n"), "OK", "CRLF line ending is accepted");
        checkReply(roundTrip(pipe, "STOP\n"), "DENY", "unknown request is denied");
        check(granted == 2 && rejected == 1, "unknown request only reaches the reject callback");
        checkReply(roundTrip(pipe, QByteArray(400, 'A')), "DENY",
              "oversized request without a newline is denied");
        check(granted == 2 && rejected == 2, "oversized request only reaches the reject callback");
        checkReply(roundTrip(pipe, "BULWARK-INSTALL 1\n"), "DENY",
              "the uninstaller may not send the installer's request");
        check(granted == 2 && rejected == 3, "installer request from the uninstaller only reaches the reject callback");

        gate.onStandbyRequested = [&granted](const MaintenanceGate::Verdict&) {
            ++granted;
            return false;
        };
        checkReply(roundTrip(pipe, "BULWARK-UNINSTALL 1\n"), "DENY",
              "request is denied when the service could not enter standby");
    }
    {
        int granted = 0;
        int rejected = 0;
        MaintenanceGate gate;
        gate.setOptions(relaxed);
        gate.onStandbyRequested = [&granted](const MaintenanceGate::Verdict&) {
            ++granted;
            return true;
        };
        gate.onRejected = [&rejected](const MaintenanceGate::Verdict&) { ++rejected; };
        check(gate.start(pipe, differ), "gate listens with another reference");
        checkReply(roundTrip(pipe, "BULWARK-UNINSTALL 1\n"), "DENY",
              "client that is not a copy of the reference is denied");
        check(granted == 0 && rejected == 1, "unverified client never reaches the standby callback");
    }

    testSignatureFormat(bytes);
    testSignedInstallerClients(bytes, tmp.path(), differ, relaxed);
}

// 子进程客户端:--client <管道名> <请求行>。连上、发请求、把答复的第一行打印出来。
int client(const QStringList& args)
{
    QLocalSocket socket;
    socket.connectToServer(args.at(2));
    if (!socket.waitForConnected(5000)) {
        std::printf("<no connection>\n");
        return 2;
    }
    socket.write(args.at(3).toUtf8() + '\n');
    socket.flush();
    QByteArray reply;
    QElapsedTimer timer;
    timer.start();
    while (!reply.contains('\n') && timer.elapsed() < 10000) {
        socket.waitForReadyRead(100);
        reply += socket.readAll();
        if (socket.state() != QLocalSocket::ConnectedState && socket.bytesAvailable() == 0)
            break;
    }
    if (reply.trimmed().isEmpty()) {
        std::printf("<no reply after %lld ms: %s>\n", static_cast<long long>(timer.elapsed()),
                    socket.errorString().toUtf8().constData());
        return 3;
    }
    std::printf("%s\n", reply.trimmed().constData());
    return 0;
}

// 联调用:--serve <管道名> <基准文件> <秒数> [发布公钥的十六进制]。不要求提权,便于拿真实的安装/卸载程序来连。
int serve(const QStringList& args)
{
    MaintenanceGate::Options options;
    options.requireElevatedAdministrator = false;
    if (args.size() == 6)
        options.releasePublicKey = QByteArray::fromHex(args.at(5).toLatin1());
    MaintenanceGate gate;
    gate.setOptions(options);
    gate.onStandbyRequested = [](const MaintenanceGate::Verdict& v) {
        std::printf("GRANTED %s\n", v.reason.toUtf8().constData());
        std::fflush(stdout);
        return true;
    };
    gate.onRejected = [](const MaintenanceGate::Verdict& v) {
        std::printf("REJECTED %s\n", v.reason.toUtf8().constData());
        std::fflush(stdout);
    };
    if (!gate.start(args.at(2), args.at(3))) {
        std::printf("LISTEN FAILED %s\n", gate.errorString().toUtf8().constData());
        return 2;
    }
    std::printf("LISTENING\n");
    std::fflush(stdout);
    QTimer::singleShot(args.at(4).toInt() * 1000, QCoreApplication::instance(), &QCoreApplication::quit);
    return QCoreApplication::exec();
}

}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    const QStringList args = QCoreApplication::arguments();
    if ((args.size() == 5 || args.size() == 6) && args.at(1) == QStringLiteral("--serve"))
        return serve(args);
    if (args.size() == 4 && args.at(1) == QStringLiteral("--client"))
        return client(args);

    runTests();
    std::printf("maintenance_gate_unit: %d checks, %d failed, %d skipped\n", gChecks, gFailed, gSkipped);
    if (gFailed != 0)
        return 1;
    // 77 在 CMakeLists 里登记为 SKIP_RETURN_CODE:有项目没跑成时 ctest 显示 Skipped,而不是 Passed。
    return gSkipped == 0 ? 0 : 77;
}
