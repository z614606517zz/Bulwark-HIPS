#pragma once
#include <QColor>
#include <QFont>
#include <QList>
#include <QString>
#include <QWidget>

class GlowCard;
class QAbstractButton;
class QHBoxLayout;
class QLabel;
class QVBoxLayout;
class QWidget;

// 「金刚」专属版式共用的器件:面板头(斜切色标 + 标题 + 说明 + 代号标签)、带面板头的面板、读数。
// 只在 theme::titan() 时由页面调用;另外两套皮肤的版式不经过这里。
namespace titankit {

struct PanelHead {
    QWidget* widget = nullptr;
    QWidget* marker = nullptr;         // 标题前的色标,状态变了用 setMarkerHue 换色
    QLabel* note = nullptr;            // 标题右边的小字,页面可以随时改
    QHBoxLayout* trailing = nullptr;   // 代号标签右边,放按钮
};
PanelHead panelHead(const QString& title, const QString& note, const QString& tag, const QColor& hue);
void setMarkerHue(QWidget* marker, const QColor& hue);

struct Panel {
    GlowCard* card = nullptr;
    PanelHead head;
    QVBoxLayout* body = nullptr;
};
Panel panel(const QString& title, const QString& note, const QString& tag, const QColor& hue);

// 代号标签,例如「TACHO」「STEP 2」:等宽数字体 + 细描边。
QLabel* labTag(const QString& text);

QFont numFont(int px, QFont::Weight weight = QFont::Bold);

// 设计稿的按钮(.btn):上两角切 7px、下两角切 2px 的键帽,2px 墨线,底下一道 3px 键裙。
// variant:nullptr = 普通,"primary" = 钴蓝主按钮,"ghost" = 无底无框的文字按钮。
// small = 26 高(.btn.sm),否则 32 高。icon 在文字左边,iconRight 在右边(例如 "chevron-right")。
QAbstractButton* button(const QString& text, const char* variant = nullptr, const QString& icon = QString(),
                        const QString& iconRight = QString(), bool small = true);

// 按设计稿 line-height 排的多行字:行高固定,字形按 CSS 的半行距在行内居中,不跟字体度量走。
// 自动折行;text 里的 \n 是硬换行。
QWidget* lined(const QString& text, const QFont& font, const QColor& color, qreal lineHeight,
               Qt::Alignment align = Qt::AlignLeft);

// 「32 项开机自启」这样的读数:大号数字 + 小字。没有数据时显示「—」。
QWidget* reading(QLabel** value, const QString& label);
void setReading(QLabel* value, int n, const QColor& color = QColor());

// 抽屉里的「档案」能力值条:每项一行,名称 + 分节条(value / full 的比例点亮) + 右侧读数。
class SpecBars final : public QWidget
{
public:
    struct Bar {
        QString name;
        double value = 0.0;
        double full = 1.0;
        QColor color;
        QString text;
    };

    explicit SpecBars(QList<Bar> bars);

protected:
    void paintEvent(QPaintEvent*) override;

private:
    QList<Bar> m_bars;
};

}
