#include "Bootstrap.h"
#include "MainWindow.h"
#include "UiHost.h"
#include "design/Icons.h"
#include "design/Theme.h"
#include "dialogs/PromptDialog.h"

#include <QApplication>
#include <QBuffer>
#include <QByteArray>
#include <QDataStream>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFont>
#include <QImage>
#include <QList>
#include <QLocalServer>
#include <QLocalSocket>
#include <QPixmap>
#include <QSslSocket>
#include <QSystemTrayIcon>
#include <QTimer>

static bool exportAppIco(const QString& path)
{
    const int sizes[] = {16, 20, 24, 32, 48, 64, 128, 256};
    const QIcon badge = AppIcon::appBadge();
    QList<QByteArray> frames;
    QList<int> dims;
    for (int s : sizes) {
        QPixmap pm = badge.pixmap(QSize(s, s));
        if (pm.isNull())
            continue;
        QImage img = pm.toImage().convertToFormat(QImage::Format_ARGB32);
        if (img.width() != s || img.height() != s)
            img = img.scaled(s, s, Qt::IgnoreAspectRatio, Qt::SmoothTransformation);
        QByteArray png;
        QBuffer buf(&png);
        buf.open(QIODevice::WriteOnly);
        if (!img.save(&buf, "PNG"))
            continue;
        buf.close();
        frames.append(png);
        dims.append(s);
    }
    if (frames.isEmpty())
        return false;

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly))
        return false;
    QDataStream ds(&f);
    ds.setByteOrder(QDataStream::LittleEndian);
    const quint16 count = quint16(frames.size());
    ds << quint16(0) << quint16(1) << count;
    quint32 offset = 6u + 16u * count;
    for (int i = 0; i < frames.size(); ++i) {
        const int d = dims[i];
        ds << quint8(d >= 256 ? 0 : d);
        ds << quint8(d >= 256 ? 0 : d);
        ds << quint8(0) << quint8(0);
        ds << quint16(1) << quint16(32);
        ds << quint32(frames[i].size()) << offset;
        offset += quint32(frames[i].size());
    }
    for (const QByteArray& png : frames)
        f.write(png);
    f.close();
    return true;
}

int main(int argc, char* argv[])
{
    if (qEnvironmentVariableIsEmpty("QT_TLS_BACKEND")) {
        QString dir = QFileInfo(QString::fromLocal8Bit(argv[0] ? argv[0] : "")).absolutePath();
        if (dir.isEmpty())
            dir = QDir::currentPath();
        const QString libSsl = dir + QStringLiteral("/libssl-3-x64.dll");
        if (QFile::exists(libSsl))
            qputenv("QT_TLS_BACKEND", "openssl");
    }
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("Bulwark"));
    app.setOrganizationName(QStringLiteral("Bulwark"));
    // 皮肤要在画任何图标之前定下来:应用图标本身就是小垒的头。
    theme::setSkin(theme::savedSkin());
    app.setWindowIcon(AppIcon::appBadge());

    {
        const QStringList args = app.arguments();
        const int idx = args.indexOf(QStringLiteral("--export-icon"));
        if (idx >= 0 && idx + 1 < args.size())
            return exportAppIco(args[idx + 1]) ? 0 : 1;
    }

    app.setQuitOnLastWindowClosed(false);

    const QString kInstanceKey =
        QStringLiteral("BulwarkUI-Instance-") + qEnvironmentVariable("USERNAME", QStringLiteral("default"));
    {
        QLocalSocket probe;
        probe.connectToServer(kInstanceKey);
        if (probe.waitForConnected(250)) {
            probe.write("SHOW");
            probe.flush();
            probe.waitForBytesWritten(250);
            probe.disconnectFromServer();
            return 0;
        }
    }
    QLocalServer::removeServer(kInstanceKey);
    QLocalServer instanceServer;
    instanceServer.listen(kInstanceKey);

    theme::apply(app);

    if (qEnvironmentVariableIsEmpty("BULWARK_UI_SMOKE"))
        bulwark::ui::bootstrap::ensureBackendRunning();

    if (qEnvironmentVariableIsEmpty("BULWARK_UI_SMOKE"))
        bulwark::ui::bootstrap::ensureUiAutoStart();

    const bool startInTray = app.arguments().contains(QStringLiteral("--tray"))
                             && QSystemTrayIcon::isSystemTrayAvailable();

    // 主窗口与它的 WindowGuard 成对创建;换皮肤时由 UiHost 整窗重建(进程不退出、防护不中断)。
    UiHost host(app, true);
    host.start(!startInTray);

    QObject::connect(&instanceServer, &QLocalServer::newConnection, &app, [&instanceServer, &host] {
        while (QLocalSocket* conn = instanceServer.nextPendingConnection()) {
            QObject::connect(conn, &QLocalSocket::disconnected, conn, &QLocalSocket::deleteLater);
            host.bringToFront();
        }
    });

    if (!qEnvironmentVariableIsEmpty("BULWARK_UI_SMOKE")) {
        bulwark::SecurityEvent ev;
        ev.type = bulwark::EventType::RemoteThread;
        ev.actorPath = QStringLiteral("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        ev.target = QString::fromUtf8("explorer.exe (PID 2204)");
        ev.riskScore = 82;
        ev.actorSigned = true;
        ev.actorPublisher = QStringLiteral("Microsoft Windows");
        ev.commandLine = QStringLiteral("powershell -enc SQBFAFgA...");
        ev.riskReasons = {QString::fromUtf8("向系统进程注入远程线程"),
                          QString::fromUtf8("命令行经过编码混淆")};
        ev.techniques = {QStringLiteral("T1055"), QStringLiteral("T1059.001")};
        auto* dlg = new PromptDialog(ev, host.window());
        dlg->show();
        QTimer::singleShot(1500, &app, &QApplication::quit);
    }

    return app.exec();
}
