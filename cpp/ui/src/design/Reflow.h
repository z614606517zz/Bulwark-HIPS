#pragma once
#include <QBoxLayout>
#include <QEvent>
#include <QLayoutItem>
#include <QObject>
#include <QWidget>

#include <functional>
#include <utility>

namespace ui {

// 盯着一个控件:它每次改变尺寸(以及显示出来)时调一次回调。用来做「窄了就换一种排法」。
class ResizeHook final : public QObject
{
public:
    ResizeHook(QWidget* watched, std::function<void()> fn) : QObject(watched), m_fn(std::move(fn))
    {
        watched->installEventFilter(this);
    }

protected:
    bool eventFilter(QObject* o, QEvent* e) override
    {
        // LayoutRequest:里面的内容最小尺寸变了(样式刚生效、文字换了),控件本身尺寸没变也要重新判断。
        if (e->type() == QEvent::Resize || e->type() == QEvent::Show || e->type() == QEvent::LayoutRequest)
            m_fn();
        return QObject::eventFilter(o, e);
    }

private:
    std::function<void()> m_fn;
};

inline void onResize(QWidget* watched, std::function<void()> fn)
{
    new ResizeHook(watched, std::move(fn));
}

// 一行并排的几项最少要多宽(各项最小宽度 + 间距)。结果与这一行当前是横排还是竖排无关,
// 所以拿它当切换阈值不会来回抖动。
inline int sideBySideWidth(const QBoxLayout* row)
{
    int w = 0;
    int n = 0;
    for (int i = 0; i < row->count(); ++i) {
        const QLayoutItem* it = row->itemAt(i);
        if (it->isEmpty())
            continue;
        w += it->minimumSize().width();
        ++n;
    }
    return w + qMax(0, n - 1) * row->spacing();
}

// 布局眼里这个控件最窄能到多少(和布局自己的算法一致:最小宽度、最小尺寸提示、尺寸策略都算进去)。
inline int minWidthOf(QWidget* w)
{
    return QWidgetItem(w).minimumSize().width();
}

// 竖排布局里的一个可有可无的控件(装饰用的机器人之类):可用高度放得下整套内容就显示,放不下就收起,
// 不让它被挤扁或切掉。「整套内容」的高度在显示 / 收起两种状态下算出来一样;收起后要多出几像素才重新显示,
// 两边都不会来回跳。
inline void showIfFits(QWidget* optional, const QLayout* column, const QSize& available)
{
    const bool hidden = optional->isHidden();
    const int own = qBound(optional->minimumHeight(), optional->minimumSizeHint().height(),
                           optional->maximumHeight());
    // 里面有会折行的文字时,最小高度取决于当前宽度,要按宽度问。
    int rest = column->totalMinimumSize().height();
    if (column->hasHeightForWidth())
        rest = qMax(rest, column->totalMinimumHeightForWidth(available.width()));
    const int full = rest + (hidden ? own : 0);
    const bool fits = available.height() >= full + (hidden ? 8 : 0);
    if (fits == hidden)
        optional->setVisible(fits);
}

}
