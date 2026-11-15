#include "WindowGuard.h"
#include "WindowGuardPolicy.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QGuiApplication>
#include <QProcess>
#include <QScreen>
#include <QTimer>
#include <QWidget>

#ifdef Q_OS_WIN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace bulwark::ui {

WindowGuard::WindowGuard(QWidget* mainWindow, QObject* parent)
    : QObject(parent), win_(mainWindow) {}

WindowGuard::~WindowGuard() {
    if (armed_)
        QCoreApplication::instance()->removeNativeEventFilter(this);
}

void WindowGuard::logOnly(const QString& what, const QString& detail) {
    QFile f(QDir::temp().filePath(QStringLiteral("bulwark-ui-guard.log")));
    if (!f.open(QIODevice::Append | QIODevice::Text))
        return;
    f.write(QDateTime::currentDateTime().toString(Qt::ISODate).toUtf8());
    f.write(" | ");
    f.write(what.toUtf8());
    f.write(" | ");
    f.write(detail.toUtf8());
    f.write("\n");
}

void WindowGuard::emitReport(const QString& what, const QString& detail) {
    logOnly(what, detail);
    if (lastReported_ == what)
        return;
    lastReported_ = what;
    if (report_)
        report_(what, detail);
}

void WindowGuard::allowQuit(const QString& reason) {
    quitReason_ = reason.isEmpty() ? QStringLiteral("(未说明)") : reason;
}

void WindowGuard::snapshotGeometry() {
    if (win_ == nullptr)
        return;
    wantW_ = win_->width();
    wantH_ = win_->height();
}

#ifdef Q_OS_WIN

void WindowGuard::hardenMessageFilters() {
    if (win_ == nullptr)
        return;
    const HWND hwnd = reinterpret_cast<HWND>(win_->winId());
    if (hwnd == nullptr)
        return;

    static const UINT kDeny[] = {
        WM_CLOSE,
        WM_QUIT,
        WM_DESTROY,
        WM_SYSCOMMAND,
        WM_QUERYENDSESSION,
        WM_ENDSESSION,
        WM_SETTEXT,
        WM_SETICON,
        WM_ENABLE,
        WM_SHOWWINDOW,
    };
    for (UINT m : kDeny)
        ::ChangeWindowMessageFilterEx(hwnd, m, MSGFLT_DISALLOW, nullptr);
}

bool WindowGuard::physicalInputFresh(unsigned withinMs) {
    LASTINPUTINFO li{};
    li.cbSize = sizeof(li);
    if (!::GetLastInputInfo(&li))
        return true;   // 拿不到这个佐证时不要用它去否决用户:宁可多收一次托盘,也不要死按钮
    return static_cast<DWORD>(::GetTickCount() - li.dwTime) <= withinMs;
}

void WindowGuard::noteUserCloseIntent() {
    closeIntentTick_ = static_cast<quint32>(::GetTickCount());
    haveCloseIntent_ = true;
}

bool WindowGuard::userCloseIntentFresh() const {
    if (!haveCloseIntent_)
        return false;
    const DWORD age = static_cast<DWORD>(::GetTickCount()) - static_cast<DWORD>(closeIntentTick_);
    if (age > kIntentWindowMs)
        return false;
    return true;
}

void WindowGuard::armUserCloseSequence() {
    closeSequenceTick_ = static_cast<quint32>(::GetTickCount());
    pendingUserCloseSequence_ = true;
}

bool WindowGuard::userCloseSequenceFresh() const {
    if (!pendingUserCloseSequence_)
        return false;
    const DWORD age = static_cast<DWORD>(::GetTickCount()) - static_cast<DWORD>(closeSequenceTick_);
    return age <= kIntentWindowMs;
}

void WindowGuard::clearUserCloseSequence() {
    pendingUserCloseSequence_ = false;
    haveCloseIntent_ = false;
}

bool WindowGuard::consumeCloseToTrayAuthorization() {
    const bool lbuttonDown = (::GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
    const bool intentOk = userCloseIntentFresh() || lbuttonDown || physicalInputFresh(kIntentWindowMs);
    if (!closeToTrayAuthorized_ && !intentOk) {
        emitReport(QStringLiteral("窗口关闭消息攻击"),
                   QStringLiteral("Qt closeEvent 在没有 WindowGuard 一次性授权的情况下被调用，"
                                  "已拒绝把主窗口收进托盘。"));
        return false;
    }

    const unsigned age = static_cast<unsigned>(static_cast<DWORD>(::GetTickCount()) -
                                                static_cast<DWORD>(closeToTrayAuthorizationTick_));
    const bool authFresh = closeToTrayAuthorized_
        && window_policy::isCloseAuthorizationFresh(true, age, kCloseAuthorizationMs);
    closeToTrayAuthorized_ = false;
    clearUserCloseSequence();
    if (!authFresh && !intentOk) {
        emitReport(QStringLiteral("窗口关闭消息攻击"),
                   QStringLiteral("WindowGuard 的关闭授权已过期，已拒绝迟到的 closeEvent。"));
        return false;
    }
    return true;
}

bool WindowGuard::nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) {
    if (!armed_ || eventType != QByteArrayLiteral("windows_generic_MSG"))
        return false;

    const MSG* msg = static_cast<const MSG*>(message);
    if (msg == nullptr || win_ == nullptr)
        return false;

    const HWND self = reinterpret_cast<HWND>(win_->effectiveWinId());
    if (self == nullptr)
        return false;
    const bool forSelf = (msg->hwnd == self) || ::IsChild(self, msg->hwnd);
    if (!forSelf) {
        if (msg->message == WM_SYSKEYDOWN && msg->wParam == VK_F4
            && (::GetKeyState(VK_MENU) & 0x8000) != 0)
            noteUserCloseIntent();
        return false;
    }

    switch (msg->message) {
    case WM_NCLBUTTONDOWN:
    case WM_NCLBUTTONUP:
        if (msg->wParam == HTCLOSE)
            noteUserCloseIntent();
        return false;

    case WM_NCLBUTTONDBLCLK:
        if (msg->wParam == HTSYSMENU)
            noteUserCloseIntent();
        return false;

    case WM_SYSKEYDOWN:
        if (msg->wParam == VK_F4 && (::GetKeyState(VK_MENU) & 0x8000) != 0)
            noteUserCloseIntent();
        return false;

    case WM_INITMENU:
        noteUserCloseIntent();
        return false;

    case WM_CLOSE: {
        if (!quitReason_.isEmpty())
            return false;

        const unsigned authorizationAge = static_cast<unsigned>(static_cast<DWORD>(::GetTickCount()) -
                                                                static_cast<DWORD>(closeToTrayAuthorizationTick_));
        const bool closeAuthorization = window_policy::isCloseAuthorizationFresh(
            closeToTrayAuthorized_, authorizationAge, kCloseAuthorizationMs);
        if (window_policy::shouldAllowCloseMessage(false, closeAuthorization))
            return false;

        closeToTrayAuthorized_ = false;
        clearUserCloseSequence();
        emitReport(QStringLiteral("窗口关闭消息攻击"),
                   QStringLiteral("收到外部发来的 WM_CLOSE(没有由真实 SC_CLOSE 生成的一次性"
                                  "关闭授权)，已吞掉。这是「窗口攻击」里最常见的一招:让安全"
                                  "软件界面在用户面前消失。"));
        if (result)
            *result = 0;
        return true;
    }

    case WM_QUERYENDSESSION:
    case WM_ENDSESSION:
        if (!quitReason_.isEmpty())
            return false;
        emitReport(QStringLiteral("窗口关闭消息攻击"),
                   QStringLiteral("收到外部发来的 %1(未经本程序的退出路径),已吞掉 —— 伪造"
                                  "「系统即将关机」能让界面走完整的会话结束流程并真的退出。")
                       .arg(msg->message == WM_QUERYENDSESSION ? QStringLiteral("WM_QUERYENDSESSION")
                                                               : QStringLiteral("WM_ENDSESSION")));
        if (result)
            *result = (msg->message == WM_QUERYENDSESSION) ? FALSE : 0;
        return true;

    case WM_SYSCOMMAND:
        return filterSysClose(static_cast<quintptr>(msg->wParam), result, "queue");

    default:
        return false;
    }
}

bool WindowGuard::windowNativeEvent(const QByteArray& eventType, void* message, qintptr* result) {
    if (!armed_ || win_ == nullptr || eventType != QByteArrayLiteral("windows_generic_MSG"))
        return false;
    const MSG* msg = static_cast<const MSG*>(message);
    if (msg == nullptr || msg->message != WM_SYSCOMMAND)
        return false;
    return filterSysClose(static_cast<quintptr>(msg->wParam), result, "window");
}

bool WindowGuard::filterSysClose(quintptr wParam, qintptr* result, const char* via) {
    if ((wParam & 0xFFF0) != SC_CLOSE || !quitReason_.isEmpty())
        return false;

    const bool lbuttonDown = (::GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
    const bool recentInput = physicalInputFresh(kIntentWindowMs);
    const bool intentFresh = userCloseIntentFresh();
    if (intentFresh || lbuttonDown || recentInput) {
        noteUserCloseIntent();
        armUserCloseSequence();
        closeToTrayAuthorizationTick_ = static_cast<quint32>(::GetTickCount());
        closeToTrayAuthorized_ = true;
        logOnly(QStringLiteral("SC_CLOSE 放行"),
                QStringLiteral("via=%1 intent=%2 lbutton=%3 recent=%4")
                    .arg(QLatin1String(via))
                    .arg(intentFresh ? 1 : 0)
                    .arg(lbuttonDown ? 1 : 0)
                    .arg(recentInput ? 1 : 0));
        return false;
    }
    emitReport(QStringLiteral("窗口系统命令攻击"),
               QStringLiteral("收到外部发来的 WM_SYSCOMMAND(SC_CLOSE)—— 「结束任务」"
                              "/ 伪造关闭按钮点击(没有任何用户操作的痕迹),已吞掉。"));
    if (result)
        *result = 0;
    return true;
}

void WindowGuard::onStateTick() {
    if (win_ == nullptr || relaunching_)
        return;

    const HWND hwnd = reinterpret_cast<HWND>(win_->effectiveWinId());
    if (hwnd == nullptr)
        return;

    const bool nativeVisible = ::IsWindowVisible(hwnd) != FALSE;
    if (window_policy::shouldClearHiddenIntent(expectedHidden_, win_->isMinimized(), nativeVisible))
        expectedHidden_ = false;
    if (pendingUserCloseSequence_ && !userCloseSequenceFresh())
        clearUserCloseSequence();
    if (closeToTrayAuthorized_) {
        const unsigned authorizationAge = static_cast<unsigned>(static_cast<DWORD>(::GetTickCount()) -
                                                                 static_cast<DWORD>(closeToTrayAuthorizationTick_));
        if (!window_policy::isCloseAuthorizationFresh(true, authorizationAge, kCloseAuthorizationMs))
            closeToTrayAuthorized_ = false;
    }

    const bool intentionallyHidden = expectedHidden_ || win_->isMinimized();

    if (!::IsWindowEnabled(hwnd)) {
        ::EnableWindow(hwnd, TRUE);
        emitReport(QStringLiteral("窗口禁用攻击"),
                   QStringLiteral("主窗口被外部进程置为禁用(EnableWindow FALSE)—— 界面看着在、"
                                  "但一个控件都点不动。已恢复为可用。"));
    }

    if (::GetParent(hwnd) != nullptr) {
        ::SetParent(hwnd, nullptr);
        emitReport(QStringLiteral("窗口父子关系劫持"),
                   QStringLiteral("主窗口被外部进程 SetParent 到了另一个窗口下 —— 显示与消息路由"
                                  "都会被那个窗口接管。已恢复为顶层窗口。"));
    }

    if (!intentionallyHidden) {
        RECT r{};
        if (::GetWindowRect(hwnd, &r)) {
            const int w = r.right - r.left;
            const int h = r.bottom - r.top;
            if (w < 80 || h < 60) {
                if (wantW_ > 0 && wantH_ > 0)
                    win_->resize(wantW_, wantH_);
                emitReport(QStringLiteral("窗口尺寸攻击"),
                           QStringLiteral("主窗口被外部压到 %1x%2(接近零尺寸),已恢复。")
                               .arg(w).arg(h));
            } else {
                bool onAnyScreen = false;
                for (const QScreen* sc : QGuiApplication::screens()) {
                    const QRect g = sc->geometry();
                    const QRect wr(r.left, r.top, w, h);
                    if (g.intersected(wr).width() > 60 && g.intersected(wr).height() > 40) {
                        onAnyScreen = true;
                        break;
                    }
                }
                if (!onAnyScreen) {
                    win_->move(QGuiApplication::primaryScreen()->availableGeometry().center() -
                               QPoint(win_->width() / 2, win_->height() / 2));
                    emitReport(QStringLiteral("窗口位移攻击"),
                               QStringLiteral("主窗口被外部挪到所有屏幕之外(%1,%2),用户再也看不到它。"
                                              "已移回主屏中央。").arg(r.left).arg(r.top));
                }
            }
        }
    }

    if (window_policy::shouldRestoreHiddenWindow(expectedHidden_, win_->isMinimized(), nativeVisible)) {
        win_->show();
        if (!::IsWindowVisible(hwnd))
            ::ShowWindow(hwnd, SW_SHOW);
        emitReport(QStringLiteral("窗口隐藏攻击"),
                   QStringLiteral("主窗口在本程序未声明收托盘/隐藏时被置为不可见，符合外部 "
                                  "ShowWindow(SW_HIDE) 攻击。已恢复显示。"));
    }
}

void WindowGuard::onAboutToQuit() {
    if (!quitReason_.isEmpty() || relaunching_)
        return;

    relaunching_ = true;
    emitReport(QStringLiteral("窗口退出消息攻击(WM_QUIT)"),
               QStringLiteral("界面进程在没有任何合法退出请求的情况下被要求退出 —— 典型手法是"
                              "PostThreadMessage(WM_QUIT),它在 Qt 事件分发的最前面被处理,消息"
                              "过滤器结构性拦不住。已记录,并正在把界面重新拉起。"));

    QProcess::startDetached(QCoreApplication::applicationFilePath(),
                           QStringList{ QStringLiteral("--tray") });
}

#else

void WindowGuard::hardenMessageFilters() {}
bool WindowGuard::nativeEventFilter(const QByteArray&, void*, qintptr*) { return false; }
bool WindowGuard::windowNativeEvent(const QByteArray&, void*, qintptr*) { return false; }
bool WindowGuard::filterSysClose(quintptr, qintptr*, const char*) { return false; }
void WindowGuard::onStateTick() {}
void WindowGuard::onAboutToQuit() {}

bool WindowGuard::physicalInputFresh(unsigned) { return true; }
void WindowGuard::noteUserCloseIntent() { haveCloseIntent_ = true; }
bool WindowGuard::userCloseIntentFresh() const { return true; }
void WindowGuard::armUserCloseSequence() { pendingUserCloseSequence_ = true; }
bool WindowGuard::userCloseSequenceFresh() const { return true; }
void WindowGuard::clearUserCloseSequence() { pendingUserCloseSequence_ = false; haveCloseIntent_ = false; }
bool WindowGuard::consumeCloseToTrayAuthorization() { return true; }

#endif

void WindowGuard::arm() {
    if (armed_ || win_ == nullptr)
        return;
    armed_ = true;

    snapshotGeometry();
    hardenMessageFilters();
    QCoreApplication::instance()->installNativeEventFilter(this);

    tick_ = new QTimer(this);
    tick_->setInterval(kTickMs);
    connect(tick_, &QTimer::timeout, this, &WindowGuard::onStateTick);
    tick_->start();

    connect(QCoreApplication::instance(), &QCoreApplication::aboutToQuit,
            this, &WindowGuard::onAboutToQuit);
}

}
