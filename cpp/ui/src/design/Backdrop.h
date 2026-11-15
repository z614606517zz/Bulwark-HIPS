#pragma once
#include <QFrame>
#include <QPixmap>
#include <QSize>

// 页面底材:机甲 = 装甲面板 + 细网格;卡哇伊 = 粉色信纸 + 波点。
class Backdrop : public QFrame
{
public:
    enum class Kind { Content };
    explicit Backdrop(Kind kind = Kind::Content, QWidget* parent = nullptr);

    static QPixmap render(Kind kind, const QSize& size, qreal dpr);

    QPixmap canvas();

    static void install(QWidget* window);

protected:
    void paintEvent(QPaintEvent*) override;
    void resizeEvent(QResizeEvent*) override;

private:
    Kind m_kind;
    QPixmap m_cache;
};
