// 预览工具(bulwark_prompt_preview)的排版体检:只被 PromptPreviewMain.cpp 包含,不进正式界面。
// 每拍一张图,就把当时可见的每个顶层窗口扫一遍,找出「文字 / 控件显示不全」的地方:
//   - 按钮、文字标签、输入框占位字、下拉框、表头:实际尺寸小于内容需要的尺寸;
//   - 容器:实际尺寸小于布局的最小尺寸(里面的控件必然被压扁);
//   - 任意带字控件:被外层容器裁掉一部分(滚动区里能滚到的方向不算)。
// 自绘控件里用 QPainter 画的字量不出来,那部分只能看图。
// 结果写到 <输出目录>/audit.tsv,并把问题控件框在 <输出目录>/marks/ 下的图上。
#pragma once

#include <QAbstractButton>
#include <QAbstractScrollArea>
#include <QApplication>
#include <QComboBox>
#include <QDir>
#include <QFile>
#include <QHeaderView>
#include <QLabel>
#include <QLayout>
#include <QLineEdit>
#include <QPainter>
#include <QPixmap>
#include <QPlainTextEdit>
#include <QScrollArea>
#include <QSet>
#include <QStyle>
#include <QStyleOptionFrame>
#include <QTextDocument>
#include <QTextStream>
#include <QWidget>

#include <typeinfo>
#include <utility>

#include "widgets/ElidingLabel.h"
#include "widgets/WrapLabel.h"

namespace previewaudit {

struct Mark {
    QRect rect;
    bool hard = true;   // true = 确实显示不全;false = 只是提示(被省略号截短等)
};

struct State {
    bool on = false;
    QString dir;
    QString skin;
    QSet<QString> seen;
    QStringList rows;
};

inline State& st()
{
    static State s;
    return s;
}

inline void enable(const QString& dir)
{
    st().on = true;
    st().dir = dir;
}
inline bool enabled() { return st().on; }
inline void setSkin(const QString& key) { st().skin = key; }

inline QString typeName(const QWidget* w)
{
    QString n = QString::fromLatin1(typeid(*w).name());
    n.remove(QStringLiteral("class "));
    n.remove(QStringLiteral("struct "));
    n.remove(QStringLiteral("`anonymous namespace'::"));
    return n;
}

inline bool isCustom(const QWidget* w) { return !typeName(w).startsWith(QLatin1Char('Q')); }

inline QString oneLine(QString s, int max = 70)
{
    if (Qt::mightBeRichText(s)) {
        QTextDocument doc;
        doc.setHtml(s);
        s = doc.toPlainText();
    }
    s.replace(QLatin1Char('\n'), QStringLiteral(" / "));
    s.replace(QLatin1Char('\r'), QLatin1Char(' '));
    s.replace(QLatin1Char('\t'), QLatin1Char(' '));
    if (s.size() > max)
        s = s.left(max) + QStringLiteral("...");
    return s;
}

inline QString chain(const QWidget* w, const QWidget* top)
{
    QStringList parts;
    for (const QWidget* p = w; p; p = p->parentWidget()) {
        QString s = typeName(p);
        if (!p->objectName().isEmpty() && !p->objectName().startsWith(QLatin1String("qt_")))
            s += QLatin1Char('#') + p->objectName();
        parts.prepend(s);
        if (p == top || parts.size() >= 8)
            break;
    }
    return parts.join(QLatin1Char('/'));
}

inline bool isViewport(const QWidget* w)
{
    const auto* area = qobject_cast<const QAbstractScrollArea*>(w->parentWidget());
    return area && area->viewport() == w;
}

// w 在各层祖先里还露着的部分(w 自己的坐标)。滚动区里能滚到的方向不算被裁。
inline QRect visiblePart(const QWidget* w, const QWidget* top, QString* clipper)
{
    QRect vis = w->rect();
    // 穿过一个能横向 / 纵向滚动的视口之后,那个方向上再往外的祖先都不算裁切(内容只是没滚到)。
    bool freeX = false;
    bool freeY = false;
    for (const QWidget* c = w; c != top && c->parentWidget(); c = c->parentWidget()) {
        const QWidget* p = c->parentWidget();
        QRect pr = p->rect().translated(-w->mapTo(p, QPoint(0, 0)));
        if (isViewport(p)) {
            const auto* area = static_cast<const QAbstractScrollArea*>(p->parentWidget());
            freeX = freeX || area->horizontalScrollBarPolicy() != Qt::ScrollBarAlwaysOff;
            freeY = freeY || area->verticalScrollBarPolicy() != Qt::ScrollBarAlwaysOff;
        }
        if (freeX) {
            pr.setLeft(vis.left());
            pr.setRight(vis.right());
        }
        if (freeY) {
            pr.setTop(vis.top());
            pr.setBottom(vis.bottom());
        }
        const QRect next = vis.intersected(pr);
        if (next != vis && clipper && clipper->isEmpty())
            *clipper = typeName(p) + (p->objectName().isEmpty() ? QString() : QLatin1Char('#') + p->objectName());
        vis = next;
        if (vis.isEmpty())
            break;
    }
    return vis;
}

inline QString sz(const QSize& s) { return QStringLiteral("%1x%2").arg(s.width()).arg(s.height()); }

inline void add(const QWidget* top, const QWidget* w, const QString& scene, const char* kind, bool hard,
                const QString& text, const QSize& have, const QSize& need, const QString& note, QList<Mark>& marks)
{
    const QString path = chain(w, top);
    const QString key = st().skin + QLatin1Char('|') + typeName(top) + QLatin1Char('|') + path + QLatin1Char('|')
                        + QLatin1String(kind) + QLatin1Char('|') + text;
    if (st().seen.contains(key))
        return;
    st().seen.insert(key);
    const QRect r(w->mapTo(top, QPoint(0, 0)), w->size());
    marks.append(Mark{r, hard});
    st().rows << QStringList{st().skin, scene, QLatin1String(kind), hard ? QStringLiteral("hard") : QStringLiteral("info"),
                             typeName(top), typeName(w), oneLine(text), sz(have), sz(need), note,
                             QStringLiteral("%1,%2,%3,%4").arg(r.x()).arg(r.y()).arg(r.width()).arg(r.height()), path}
                     .join(QLatin1Char('\t'));
}

inline void scanWidget(const QWidget* top, QWidget* w, const QString& scene, QList<Mark>& marks)
{
    const QSize have = w->size();
    const bool custom = isCustom(w);
    QString text;
    bool textual = false;

    if (auto* lab = qobject_cast<QLabel*>(w)) {
        const auto* el = dynamic_cast<const ElidingLabel*>(w);
        const auto* wl = dynamic_cast<const WrapLabel*>(w);
        text = el ? el->fullText() : wl ? wl->fullText() : lab->text();
        if (!lab->pixmap().isNull() || text.trimmed().isEmpty())
            return;
        textual = true;
        if (el) {
            if (lab->text() != el->fullText())
                add(top, w, scene, "elided", false, text, have,
                    QSize(lab->fontMetrics().horizontalAdvance(el->fullText()), have.height()),
                    QStringLiteral("shown: ") + oneLine(lab->text(), 40), marks);
            const int needH = lab->fontMetrics().height();
            if (have.height() < needH - 1)
                add(top, w, scene, "label-short", true, text, have, QSize(have.width(), needH), QString(), marks);
        } else if (wl) {
            const int needH = wl->heightForWidth(have.width());
            if (have.height() < needH - 1)
                add(top, w, scene, "label-short", true, text, have, QSize(have.width(), needH),
                    QStringLiteral("wrapped"), marks);
        } else if (lab->wordWrap()) {
            const int needH = lab->heightForWidth(have.width());
            if (needH > 0 && have.height() < needH - 1)
                add(top, w, scene, "label-short", true, text, have, QSize(have.width(), needH),
                    QStringLiteral("wrapped"), marks);
        } else {
            const QSize need = lab->sizeHint();
            if (have.width() < need.width() - 1)
                add(top, w, scene, "label-narrow", true, text, have, need, QString(), marks);
            if (have.height() < need.height() - 1)
                add(top, w, scene, "label-short", true, text, have, need, QString(), marks);
        }
    } else if (auto* btn = qobject_cast<QAbstractButton*>(w)) {
        text = btn->text();
        if (text.isEmpty())
            text = btn->accessibleName();
        if (!btn->text().isEmpty() || custom) {
            textual = true;
            const QSize need = custom ? btn->minimumSizeHint() : btn->sizeHint();
            if (need.isValid()) {
                if (have.width() < need.width() - 1)
                    add(top, w, scene, "button-narrow", true, text, have, need, QString(), marks);
                if (have.height() < need.height() - 1)
                    add(top, w, scene, "button-short", true, text, have, need, QString(), marks);
            }
        }
    } else if (auto* le = qobject_cast<QLineEdit*>(w)) {
        textual = true;
        text = le->text().isEmpty() ? le->placeholderText() : le->text();
        if (le->text().isEmpty() && !le->placeholderText().isEmpty()) {
            QStyleOptionFrame opt;
            opt.initFrom(le);
            const QRect inner = le->style()->subElementRect(QStyle::SE_LineEditContents, &opt, le);
            const QMargins tm = le->textMargins();
            const int avail = inner.width() - tm.left() - tm.right() - 4;
            const int need = le->fontMetrics().horizontalAdvance(le->placeholderText());
            if (need > avail)
                add(top, w, scene, "placeholder-cut", true, text, QSize(avail, have.height()),
                    QSize(need, have.height()), QStringLiteral("widget ") + sz(have), marks);
        }
        const int needH = le->minimumSizeHint().height();
        if (have.height() < needH - 1)
            add(top, w, scene, "field-short", true, text, have, QSize(have.width(), needH), QString(), marks);
    } else if (auto* pe = qobject_cast<QPlainTextEdit*>(w)) {
        textual = true;
        text = pe->toPlainText().isEmpty() ? pe->placeholderText() : pe->toPlainText();
        if (pe->toPlainText().isEmpty() && !pe->placeholderText().isEmpty()) {
            const QSize vp = pe->viewport()->size();
            const int margin = int(pe->document()->documentMargin());
            const QRect need = pe->fontMetrics().boundingRect(QRect(0, 0, qMax(1, vp.width() - 2 * margin), 100000),
                                                              Qt::TextWordWrap, pe->placeholderText());
            if (need.height() > vp.height() - margin)
                add(top, w, scene, "placeholder-cut", true, text, vp, QSize(vp.width(), need.height() + 2 * margin),
                    QStringLiteral("multi-line, widget ") + sz(have), marks);
        }
    } else if (auto* cb = qobject_cast<QComboBox*>(w)) {
        textual = true;
        text = cb->currentText();
        const QSize need = cb->minimumSizeHint();
        if (have.width() < need.width() - 1)
            add(top, w, scene, "combo-narrow", true, text, have, need, QString(), marks);
        if (have.height() < need.height() - 1)
            add(top, w, scene, "combo-short", true, text, have, need, QString(), marks);
    } else if (auto* hv = qobject_cast<QHeaderView*>(w)) {
        if (hv->orientation() == Qt::Horizontal && hv->model()) {
            for (int i = 0; i < hv->count(); ++i) {
                if (hv->isSectionHidden(i))
                    continue;
                const int need = hv->sectionSizeHint(i);
                if (hv->sectionSize(i) < need - 1)
                    add(top, w, scene, "header-cut", true,
                        hv->model()->headerData(i, Qt::Horizontal).toString(),
                        QSize(hv->sectionSize(i), have.height()), QSize(need, have.height()),
                        QStringLiteral("section %1").arg(i), marks);
            }
        }
        return;
    } else if (custom && w->findChildren<QWidget*>(Qt::FindDirectChildrenOnly).isEmpty()) {
        // 自绘的叶子控件:只能核对它自己声明的最小尺寸。
        text = w->accessibleName();
        textual = true;
        const QSize need = w->minimumSizeHint();
        if (need.isValid()) {
            if (have.width() < need.width() - 1)
                add(top, w, scene, "custom-narrow", true, text, have, need, QString(), marks);
            if (have.height() < need.height() - 1)
                add(top, w, scene, "custom-short", true, text, have, need, QString(), marks);
        }
    }

    // 滚动区:某个方向关掉了滚动条,内容却比视口大 —— 多出来的那部分永远看不到。
    if (auto* sa = qobject_cast<QScrollArea*>(w)) {
        if (const QWidget* c = sa->widget()) {
            const QSize vp = sa->viewport()->size();
            const bool overX = sa->horizontalScrollBarPolicy() == Qt::ScrollBarAlwaysOff && c->width() > vp.width() + 1;
            const bool overY = sa->verticalScrollBarPolicy() == Qt::ScrollBarAlwaysOff && c->height() > vp.height() + 1;
            if (overX || overY) {
                // 顺手记下内容布局前两层各项的最小宽度,方便看出是哪一块把整页撑宽的。
                QStringList mins;
                if (const QLayout* lay = c->layout()) {
                    for (int i = 0; i < lay->count(); ++i) {
                        QLayoutItem* it = lay->itemAt(i);
                        if (const QLayout* sub = it->layout()) {
                            QStringList parts;
                            for (int k = 0; k < sub->count(); ++k)
                                parts << QString::number(sub->itemAt(k)->minimumSize().width());
                            mins << QLatin1Char('[') + parts.join(QLatin1Char('+')) + QLatin1Char(']');
                        } else {
                            mins << QString::number(it->minimumSize().width());
                        }
                    }
                }
                add(top, w, scene, "scroll-overflow", true, w->objectName(), vp, c->size(),
                    QStringLiteral("%1%2 no scrollbar; mins %3")
                        .arg(overX ? QStringLiteral("x") : QString(), overY ? QStringLiteral("y") : QString(),
                             mins.join(QLatin1Char(' '))),
                    marks);
            }
        }
    }

    // 容器:布局的最小尺寸放不进去,里面的控件就被压扁了。
    if (QLayout* lay = w->layout(); lay && !lay->isEmpty()) {
        const QSize min = lay->totalMinimumSize();
        int needH = min.height();
        if (lay->hasHeightForWidth())
            needH = qMax(needH, lay->totalMinimumHeightForWidth(have.width()));
        if (have.width() < min.width() - 1 || have.height() < needH - 1)
            add(top, w, scene, "container-squeezed", true, w->objectName(), have, QSize(min.width(), needH),
                QString(), marks);
    }

    if (textual && !have.isEmpty()) {
        QString clipper;
        const QRect vis = visiblePart(w, top, &clipper);
        const int lostW = have.width() - vis.width();
        const int lostH = have.height() - vis.height();
        if (lostW > 1 || lostH > 1)
            add(top, w, scene, "clipped-by-parent", true, text, vis.size(), have,
                QStringLiteral("by ") + clipper, marks);
    }
}

inline void scanTop(QWidget* top, const QString& scene)
{
    QList<Mark> marks;
    scanWidget(top, top, scene, marks);
    const QList<QWidget*> all = top->findChildren<QWidget*>();
    for (QWidget* w : all)
        if (w->isVisibleTo(top))
            scanWidget(top, w, scene, marks);
    if (marks.isEmpty())
        return;
    QPixmap shot = top->grab();
    if (shot.isNull())
        return;
    {
        QPainter p(&shot);
        for (const Mark& m : std::as_const(marks)) {
            p.setPen(QPen(m.hard ? QColor(0xFF, 0x00, 0x40) : QColor(0x00, 0x90, 0xFF), 2));
            p.setBrush(Qt::NoBrush);
            p.drawRect(m.rect.adjusted(-2, -2, 1, 1));
        }
    }
    const QString dir = QDir(st().dir).filePath(QStringLiteral("marks"));
    QDir().mkpath(dir);
    shot.save(QDir(dir).filePath(scene + QLatin1Char('_') + typeName(top) + QStringLiteral(".png")));
}

// 扫一遍此刻可见的全部顶层窗口。scene 是刚存下的那张图的名字。
inline void scanAll(const QString& scene)
{
    if (!st().on)
        return;
    const QList<QWidget*> tops = QApplication::topLevelWidgets();
    for (QWidget* top : tops)
        if (top->isVisible() && !top->size().isEmpty())
            scanTop(top, scene);
}

inline void flush()
{
    if (!st().on)
        return;
    QFile f(QDir(st().dir).filePath(QStringLiteral("audit.tsv")));
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return;
    QTextStream ts(&f);
    ts.setEncoding(QStringConverter::Utf8);
    ts.setGenerateByteOrderMark(true);
    ts << "skin\tscene\tkind\tlevel\twindow\twidget\ttext\thave\tneed\tnote\trect\tpath\n";
    for (const QString& row : std::as_const(st().rows))
        ts << row << "\n";
}

}
