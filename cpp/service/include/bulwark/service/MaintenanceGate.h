#pragma once
#include <QByteArray>
#include <QObject>
#include <QString>

#include <functional>

class QLocalServer;
class QLocalSocket;

namespace bulwark::service {

// 安装/卸载专用通道。防护生效时服务不接受停止;带界面运行的卸载程序和安装程序经此请求服务先退出防护。
// 这条通道只办这一件事,请求方必须已提权、位于交互会话,并且是下面两种之一:
//   - 卸载程序:进程映像与安装目录内 Uninstall.exe 逐字节相同(NSIS 卸载程序会把自己复制到
//     临时目录再运行,所以比内容而不比路径);
//   - 安装程序:进程映像带有效的发布签名(新安装包每版内容都不同,比不了内容,只能验签)。
// 它挡的是通用的关停手段(sc stop、静默安装/卸载、直接调服务命令、未签名或被改过的安装包);
// 已有管理员权限、专门操纵安装/卸载进程(模拟点击、注入)的程序不在它的防护范围内。
//
// 发布签名的格式:文件末尾 80 字节 = 16 字节标记 "BULWARK-RELSIG1\0" + 64 字节 ECDSA P-256 签名
// (r‖s),签的是标记之前全部内容的 SHA-256。签名工具见 installer/scripts/sign-release.ps1。
class MaintenanceGate : public QObject {
public:
    struct Options {
        bool requireElevatedAdministrator = true;
        bool requireInteractiveSession = true;
        // 发布签名公钥(ECDSA P-256,X‖Y 共 64 字节)。留空则不为任何安装程序退出防护,只认卸载程序。
        QByteArray releasePublicKey;
    };

    enum class Requester { None, Uninstaller, SignedInstaller };

    struct Verdict {
        bool      ok = false;
        quint32   pid = 0;
        int       sessionId = -1;
        Requester requester = Requester::None;
        QString   imagePath;
        QString   reason;
    };

    static constexpr int kReleaseSignatureBytes = 64;
    static constexpr int kReleaseTrailerBytes = 16 + kReleaseSignatureBytes;

    explicit MaintenanceGate(QObject* parent = nullptr);
    ~MaintenanceGate() override;

    static QString pipeName();

    void setOptions(const Options& options) { options_ = options; }

    bool start(const QString& name, const QString& referenceUninstaller);
    void stop();
    QString errorString() const { return error_; }

    // 请求方核对通过且请求与其身份相符时调用;返回 true 表示服务已处于可停止状态。
    std::function<bool(const Verdict&)> onStandbyRequested;
    std::function<void(const Verdict&)> onRejected;

    static Verdict verifyClient(quint32 pid, const QString& referenceUninstaller,
                                const Options& options);

    // file 是整个文件的内容(含末尾签名)。
    static bool verifyReleaseSignature(const QByteArray& file, const QByteArray& publicKey);

private:
    void onNewConnection();
    void handleRequest(QLocalSocket* sock, const Verdict& verdict, const QByteArray& line);

    QLocalServer* server_ = nullptr;
    QString reference_;
    QString error_;
    Options options_;
};

}
