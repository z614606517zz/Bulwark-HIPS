#pragma once
#include "design/Skin.h"

#include <QObject>
#include <QPointer>

class MainWindow;
class QApplication;
class QWidget;

namespace bulwark::ui {
class WindowGuard;
}

// 主窗口的「宿主」:建窗口、挂 WindowGuard、换皮肤时整窗重建。
// 正式界面(main.cpp)与离屏预览的交互模式共用这一份,换皮肤的路径只有一条。
class UiHost : public QObject
{
    Q_OBJECT
public:
    // withGuard=false 只给预览工具用:WindowGuard 会把「非授权退出」当攻击并重新拉起进程。
    UiHost(QApplication& app, bool withGuard, QObject* parent = nullptr);
    ~UiHost() override;

    void start(bool show);
    MainWindow* window() const;
    bulwark::ui::WindowGuard* guard() const;

    // 单实例的第二次启动:把现有窗口请到前台。
    void bringToFront();

signals:
    void windowCreated(MainWindow* window);

private:
    void build(bool show, bool quiet);
    void switchSkin(theme::Skin skin);
    void rebuildFor(theme::Skin skin);

    QApplication& m_app;
    bool m_withGuard;
    QPointer<MainWindow> m_win;
    QPointer<bulwark::ui::WindowGuard> m_guard;
    // 换装转场的浮层(旧外观截图 + 扫过的警示带)。
    QPointer<QWidget> m_wipe;
};
