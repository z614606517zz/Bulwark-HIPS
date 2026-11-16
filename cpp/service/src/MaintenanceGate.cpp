#include "bulwark/service/MaintenanceGate.h"

#include <QByteArray>
#include <QByteArrayView>
#include <QCryptographicHash>
#include <QDir>
#include <QLocalServer>
#include <QLocalSocket>
#include <QTimer>

#include <cstring>
#include <memory>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

namespace bulwark::service {

namespace {

constexpr qint64 kMaxUninstallerBytes = 8ll * 1024 * 1024;
constexpr qint64 kMaxInstallerBytes = 256ll * 1024 * 1024;
constexpr qint64 kTrailerBytes = MaintenanceGate::kReleaseTrailerBytes;
constexpr int kMaxRequestBytes = 128;
constexpr int kLingerMs = 15000;
constexpr int kRejectLingerMs = 3000;
const char kUninstallRequest[] = "BULWARK-UNINSTALL 1";
const char kInstallRequest[] = "BULWARK-INSTALL 1";
const char kReleaseMarker[16] = {'B', 'U', 'L', 'W', 'A', 'R', 'K', '-', 'R', 'E', 'L', 'S', 'I', 'G', '1', '\0'};

class Handle {
public:
    explicit Handle(HANDLE h) : h_(h) {}
    ~Handle() {
        if (valid())
            ::CloseHandle(h_);
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    bool valid() const { return h_ != nullptr && h_ != INVALID_HANDLE_VALUE; }
    HANDLE get() const { return h_; }

private:
    HANDLE h_;
};

quint32 clientPidOf(qintptr socketDescriptor) {
    if (socketDescriptor == -1 || socketDescriptor == 0)
        return 0;
    ULONG pid = 0;
    if (!::GetNamedPipeClientProcessId(reinterpret_cast<HANDLE>(socketDescriptor), &pid))
        return 0;
    return static_cast<quint32>(pid);
}

QString imagePathOf(HANDLE process) {
    wchar_t buf[1024] = {};
    DWORD sz = static_cast<DWORD>(sizeof(buf) / sizeof(buf[0]));
    if (!::QueryFullProcessImageNameW(process, 0, buf, &sz))
        return QString();
    return QString::fromWCharArray(buf, static_cast<int>(sz));
}

bool isElevatedAdministrator(HANDLE process) {
    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &rawToken))
        return false;
    const Handle token(rawToken);

    TOKEN_ELEVATION elevation{};
    DWORD got = 0;
    if (!::GetTokenInformation(token.get(), TokenElevation, &elevation, sizeof(elevation), &got)
        || elevation.TokenIsElevated == 0)
        return false;

    BYTE sidBuffer[SECURITY_MAX_SID_SIZE] = {};
    DWORD sidSize = sizeof(sidBuffer);
    if (!::CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, sidBuffer, &sidSize))
        return false;
    HANDLE rawImpersonation = nullptr;
    if (!::DuplicateToken(token.get(), SecurityIdentification, &rawImpersonation))
        return false;
    const Handle impersonation(rawImpersonation);
    BOOL isAdmin = FALSE;
    return ::CheckTokenMembership(impersonation.get(), sidBuffer, &isAdmin) && isAdmin;
}

std::wstring nativePath(const QString& path) {
    return QDir::toNativeSeparators(path).toStdWString();
}

// 只共享读:句柄存续期间,这个文件不能被改写、改名或删除,它所在的各级目录也不能被改名。
HANDLE openPinned(const QString& path) {
    return ::CreateFileW(nativePath(path).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                         OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
}

qint64 sizeOf(HANDLE file) {
    LARGE_INTEGER size{};
    return ::GetFileSizeEx(file, &size) ? static_cast<qint64>(size.QuadPart) : -1;
}

bool seekTo(HANDLE file, qint64 offset) {
    LARGE_INTEGER position{};
    position.QuadPart = offset;
    return ::SetFilePointerEx(file, position, nullptr, FILE_BEGIN) != 0;
}

bool readExactly(HANDLE file, char* out, qint64 count) {
    qint64 done = 0;
    while (done < count) {
        const DWORD want = static_cast<DWORD>(qMin<qint64>(count - done, 1 << 20));
        DWORD got = 0;
        if (!::ReadFile(file, out + done, want, &got, nullptr) || got == 0)
            return false;
        done += static_cast<qint64>(got);
    }
    return true;
}

bool readAll(HANDLE file, qint64 maxBytes, QByteArray* out) {
    const qint64 size = sizeOf(file);
    if (size <= 0 || size > maxBytes)
        return false;
    out->resize(static_cast<qsizetype>(size));
    return seekTo(file, 0) && readExactly(file, out->data(), size);
}

// digest 是 SHA-256,signature 指向 64 字节的 r‖s,publicKey 是 64 字节的 X‖Y。
bool verifyDigest(const QByteArray& digest, const char* signature, const QByteArray& publicKey) {
    constexpr ULONG kCoordinateBytes = 32;
    if (digest.size() != 32 || publicKey.size() != static_cast<qsizetype>(2 * kCoordinateBytes))
        return false;

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (!BCRYPT_SUCCESS(::BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0)))
        return false;

    BCRYPT_ECCKEY_BLOB header{};
    header.dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    header.cbKey = kCoordinateBytes;
    QByteArray blob(static_cast<qsizetype>(sizeof(header)) + publicKey.size(), '\0');
    std::memcpy(blob.data(), &header, sizeof(header));
    std::memcpy(blob.data() + sizeof(header), publicKey.constData(), static_cast<size_t>(publicKey.size()));

    bool ok = false;
    BCRYPT_KEY_HANDLE key = nullptr;
    if (BCRYPT_SUCCESS(::BCryptImportKeyPair(algorithm, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key,
                                             reinterpret_cast<PUCHAR>(blob.data()),
                                             static_cast<ULONG>(blob.size()), 0))) {
        ok = BCRYPT_SUCCESS(::BCryptVerifySignature(
            key, nullptr,
            reinterpret_cast<PUCHAR>(const_cast<char*>(digest.constData())), static_cast<ULONG>(digest.size()),
            reinterpret_cast<PUCHAR>(const_cast<char*>(signature)),
            static_cast<ULONG>(MaintenanceGate::kReleaseSignatureBytes), 0));
        ::BCryptDestroyKey(key);
    }
    ::BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}

// 先看末尾标记:没有标记的映像不必整份读出来算哈希。
bool hasValidReleaseSignature(HANDLE file, const QByteArray& publicKey) {
    const qint64 size = sizeOf(file);
    if (size <= kTrailerBytes || size > kMaxInstallerBytes)
        return false;
    char trailer[MaintenanceGate::kReleaseTrailerBytes] = {};
    if (!seekTo(file, size - kTrailerBytes) || !readExactly(file, trailer, kTrailerBytes))
        return false;
    if (std::memcmp(trailer, kReleaseMarker, sizeof(kReleaseMarker)) != 0)
        return false;
    if (!seekTo(file, 0))
        return false;

    QCryptographicHash hash(QCryptographicHash::Sha256);
    QByteArray chunk(1 << 20, Qt::Uninitialized);
    qint64 left = size - kTrailerBytes;
    while (left > 0) {
        const qint64 want = qMin<qint64>(left, chunk.size());
        if (!readExactly(file, chunk.data(), want))
            return false;
        hash.addData(QByteArrayView(chunk.constData(), static_cast<qsizetype>(want)));
        left -= want;
    }
    return verifyDigest(hash.result(), trailer + sizeof(kReleaseMarker), publicKey);
}

// 句柄指向的文件的规范路径(穿过联接点和符号链接之后的真实位置),去掉 \\?\ 前缀。
QString finalPathOf(HANDLE file) {
    wchar_t buf[1024] = {};
    const DWORD n = ::GetFinalPathNameByHandleW(file, buf, static_cast<DWORD>(sizeof(buf) / sizeof(buf[0])),
                                                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (n == 0 || n >= sizeof(buf) / sizeof(buf[0]))
        return QString();
    QString s = QString::fromWCharArray(buf, static_cast<int>(n));
    if (s.startsWith(QStringLiteral("\\\\?\\UNC\\")))
        return QString();
    if (s.startsWith(QStringLiteral("\\\\?\\")))
        s.remove(0, 4);
    return s;
}

QString longPathOf(const QString& path) {
    wchar_t buf[1024] = {};
    const DWORD n = ::GetLongPathNameW(nativePath(path).c_str(), buf,
                                       static_cast<DWORD>(sizeof(buf) / sizeof(buf[0])));
    if (n == 0 || n >= sizeof(buf) / sizeof(buf[0]))
        return path;
    return QString::fromWCharArray(buf, static_cast<int>(n));
}

bool samePath(const QString& a, const QString& b) {
    return QDir::toNativeSeparators(a).compare(QDir::toNativeSeparators(b), Qt::CaseInsensitive) == 0;
}

void closeLater(QLocalSocket* sock, int ms) {
    QObject::connect(sock, &QLocalSocket::disconnected, sock, &QObject::deleteLater);
    QTimer::singleShot(ms, sock, [sock] {
        sock->abort();
        sock->deleteLater();
    });
}

}

MaintenanceGate::MaintenanceGate(QObject* parent) : QObject(parent) {
    server_ = new QLocalServer(this);
    // 和控制管道一样不靠管道 ACL 区分来访者:连上之后按进程逐项核对,不符就拒绝。
    server_->setSocketOptions(QLocalServer::WorldAccessOption);
    connect(server_, &QLocalServer::newConnection, this, [this] { onNewConnection(); });
}

MaintenanceGate::~MaintenanceGate() {
    stop();
}

QString MaintenanceGate::pipeName() {
    return QStringLiteral("Bulwark.Maintenance");
}

bool MaintenanceGate::start(const QString& name, const QString& referenceUninstaller) {
    reference_ = referenceUninstaller;
    QLocalServer::removeServer(name);
    if (!server_->listen(name)) {
        error_ = server_->errorString();
        return false;
    }
    error_.clear();
    return true;
}

void MaintenanceGate::stop() {
    if (server_ && server_->isListening())
        server_->close();
}

bool MaintenanceGate::verifyReleaseSignature(const QByteArray& file, const QByteArray& publicKey) {
    if (file.size() <= kReleaseTrailerBytes)
        return false;
    const qsizetype contentSize = file.size() - kReleaseTrailerBytes;
    const char* trailer = file.constData() + contentSize;
    if (std::memcmp(trailer, kReleaseMarker, sizeof(kReleaseMarker)) != 0)
        return false;
    const QByteArray digest =
        QCryptographicHash::hash(QByteArrayView(file.constData(), contentSize), QCryptographicHash::Sha256);
    return verifyDigest(digest, trailer + sizeof(kReleaseMarker), publicKey);
}

MaintenanceGate::Verdict MaintenanceGate::verifyClient(quint32 pid, const QString& referenceUninstaller,
                                                       const Options& options) {
    Verdict v;
    v.pid = pid;
    if (pid == 0) {
        v.reason = QStringLiteral("无法确定请求方进程");
        return v;
    }

    // 这个句柄一直拿到核对结束,PID 不会在中途被另一个进程复用。
    const Handle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE,
                                       static_cast<DWORD>(pid)));
    if (!process.valid()) {
        v.reason = QStringLiteral("无法打开请求方进程(PID %1,错误 %2)").arg(pid).arg(::GetLastError());
        return v;
    }

    DWORD sessionId = 0;
    if (::ProcessIdToSessionId(static_cast<DWORD>(pid), &sessionId))
        v.sessionId = static_cast<int>(sessionId);
    if (options.requireInteractiveSession && v.sessionId <= 0) {
        v.reason = QStringLiteral("请求方不在交互会话内(PID %1,会话 %2)").arg(pid).arg(v.sessionId);
        return v;
    }

    if (options.requireElevatedAdministrator && !isElevatedAdministrator(process.get())) {
        v.reason = QStringLiteral("请求方不是已提升的 Administrators 进程(PID %1)").arg(pid);
        return v;
    }

    v.imagePath = imagePathOf(process.get());
    if (v.imagePath.trimmed().isEmpty()) {
        v.reason = QStringLiteral("无法解析请求方的映像路径(PID %1)").arg(pid);
        return v;
    }
    const QString who = QStringLiteral("PID %1:%2").arg(QString::number(pid), v.imagePath);

    // 路径是会变的:进程启动后映像文件可以被改名,原位置再放一份真的卸载程序或安装包,或者把某一级目录
    // 换成联接点。所以这样核对:按路径打开并钉住该文件 → 句柄的规范路径必须就是这条路径(没有被重定向)
    // → 内容过关 → 钉着的同时再问一次进程映像路径,必须没变。钉住期间那个位置换不了文件,两次都指向它
    // 就说明进程映像正是我们读到的这个文件。
    const Handle image(openPinned(v.imagePath));
    if (!image.valid()) {
        v.reason = QStringLiteral("无法打开请求方映像以供核对(%1,错误 %2)").arg(who, QString::number(::GetLastError()));
        return v;
    }
    const QString finalPath = finalPathOf(image.get());
    if (finalPath.isEmpty() || !samePath(finalPath, longPathOf(v.imagePath))) {
        v.reason = QStringLiteral("请求方映像路径被重定向或无法规范化(%1)").arg(who);
        return v;
    }

    QByteArray expected;
    bool haveReference = false;
    {
        const Handle reference(openPinned(referenceUninstaller));
        haveReference = reference.valid() && readAll(reference.get(), kMaxUninstallerBytes, &expected);
    }
    if (haveReference && sizeOf(image.get()) == expected.size()) {
        QByteArray actual;
        if (readAll(image.get(), kMaxUninstallerBytes, &actual) && actual == expected)
            v.requester = Requester::Uninstaller;
    }
    if (v.requester == Requester::None && !options.releasePublicKey.isEmpty()
        && hasValidReleaseSignature(image.get(), options.releasePublicKey))
        v.requester = Requester::SignedInstaller;

    if (v.requester == Requester::None) {
        QString why = haveReference
            ? QStringLiteral("请求方不是安装目录内卸载程序的副本")
            : QStringLiteral("安装目录内没有可用的卸载程序作基准");
        if (!options.releasePublicKey.isEmpty())
            why += QStringLiteral(",请求方也不带有效的发布签名");
        v.reason = QStringLiteral("%1(%2)").arg(why, who);
        return v;
    }

    const QString again = imagePathOf(process.get());
    if (!samePath(again, v.imagePath) || ::WaitForSingleObject(process.get(), 0) != WAIT_TIMEOUT) {
        v.requester = Requester::None;
        v.reason = QStringLiteral("核对期间请求方映像路径发生变化或进程已退出(%1)").arg(who);
        return v;
    }

    v.ok = true;
    v.reason = QStringLiteral("PID %1 · 会话 %2 · %3(%4)")
                   .arg(QString::number(pid), QString::number(v.sessionId), v.imagePath,
                        v.requester == Requester::Uninstaller
                            ? QStringLiteral("与安装目录内卸载程序逐字节相同")
                            : QStringLiteral("带有效的发布签名"));
    return v;
}

void MaintenanceGate::onNewConnection() {
    while (QLocalSocket* sock = server_->nextPendingConnection()) {
        const Verdict verdict =
            verifyClient(clientPidOf(sock->socketDescriptor()), reference_, options_);
        if (!verdict.ok) {
            if (onRejected)
                onRejected(verdict);
            sock->write("DENY\n");
            sock->flush();
            closeLater(sock, kRejectLingerMs);
            continue;
        }

        const auto buffer = std::make_shared<QByteArray>();
        const auto answered = std::make_shared<bool>(false);
        connect(sock, &QLocalSocket::readyRead, this, [this, sock, verdict, buffer, answered] {
            if (*answered) {
                sock->readAll();
                return;
            }
            *buffer += sock->readAll();
            const qsizetype nl = buffer->indexOf('\n');
            if (nl < 0 && buffer->size() <= kMaxRequestBytes)
                return;
            *answered = true;
            handleRequest(sock, verdict, nl < 0 ? QByteArray() : buffer->left(nl).trimmed());
        });
        // 答复之后由对方先关闭:服务端先断开的话,对方还没读走的答复会被管道丢掉。
        closeLater(sock, kLingerMs);
    }
}

void MaintenanceGate::handleRequest(QLocalSocket* sock, const Verdict& verdict, const QByteArray& line) {
    // 卸载程序只能发卸载请求,安装程序只能发安装请求。
    const bool matches = (verdict.requester == Requester::Uninstaller && line == kUninstallRequest)
        || (verdict.requester == Requester::SignedInstaller && line == kInstallRequest);
    bool granted = false;
    if (matches) {
        granted = onStandbyRequested ? onStandbyRequested(verdict) : false;
    } else if (onRejected) {
        Verdict bad = verdict;
        bad.ok = false;
        bad.reason = QStringLiteral("请求格式不符,或与请求方身份不符(%1)").arg(verdict.reason);
        onRejected(bad);
    }
    sock->write(granted ? "OK\n" : "DENY\n");
    sock->flush();
}

}
