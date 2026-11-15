#include "design/RecordDelegate.h"
#include "design/Format.h"
#include "design/Icons.h"
#include "design/RecordModel.h"
#include "design/Sticker.h"
#include "design/Theme.h"

#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QScrollBar>
#include <QTimer>

namespace {

QFont sized(QFont f, qreal pt, QFont::Weight w)
{
    f.setPointSizeF(pt);
    f.setWeight(w);
    return f;
}

QFont mono(qreal pt)
{
    QFont f;
    f.setFamilies({QStringLiteral("Cascadia Mono"), QStringLiteral("Consolas")});
    f.setPointSizeF(pt);
    return f;
}

QColor colorOr(const QVariant& v, const QColor& fallback)
{
    const QColor c = v.value<QColor>();
    return c.isValid() ? c : fallback;
}

qreal drawCapsule(QPainter* p, const QRectF& r, const QString& text, const QColor& c, const QFont& f,
                  bool solid = false)
{
    const QRectF b = r.adjusted(0.8, 0.8, -0.8, -0.8);
    const QPainterPath path = theme::panelPath(b, theme::mecha() ? 4.0 : b.height() / 2.7);
    p->fillPath(path, solid ? c : theme::blend(c, theme::surface(), 0.14));
    p->strokePath(path, QPen(solid ? theme::ink() : c, 1.6, Qt::SolidLine, Qt::FlatCap,
                             theme::mecha() ? Qt::MiterJoin : Qt::RoundJoin));
    p->setFont(f);
    p->setPen(solid ? theme::textOn(c) : c);
    p->drawText(r, Qt::AlignCenter, text);
    return r.width();
}

Qt::PenJoinStyle joinStyle() { return theme::mecha() ? Qt::MiterJoin : Qt::RoundJoin; }

}

RecordDelegate::RecordDelegate(QObject* parent) : QStyledItemDelegate(parent) {}

QSize RecordDelegate::sizeHint(const QStyleOptionViewItem&, const QModelIndex& idx) const
{
    if (idx.data(rec::Header).toBool())
        return {200, idx.data(rec::Leading).toBool() ? kHeaderH - 8 : kHeaderH};
    return {200, kRowH};
}

void RecordDelegate::paint(QPainter* p, const QStyleOptionViewItem& opt, const QModelIndex& idx) const
{
    if (idx.data(rec::Header).toBool())
        paintHeader(p, opt.rect, idx, false);
    else
        paintRecord(p, opt, idx);
}

void RecordDelegate::paintHeader(QPainter* p, const QRect& band, const QModelIndex& header, bool pinned) const
{
    p->save();
    p->setRenderHint(QPainter::Antialiasing, true);
    QRectF r(band);
    if (pinned) {
        p->fillRect(r, theme::surface());
        p->setPen(QPen(theme::ink(), 2.0));
        p->drawLine(QPointF(r.left() + 12, r.bottom()), QPointF(r.right() - 12, r.bottom()));
    } else if (!header.data(rec::Leading).toBool()) {
        r.setTop(r.top() + 8);
    }

    const QString group = header.data(rec::Group).toString();
    qreal x = r.left() + 18;
    const qreal cy = r.center().y();
    if (m_collapsible) {
        const bool collapsed = m_isCollapsed && m_isCollapsed(group);
        AppIcon::draw(*p, collapsed ? QStringLiteral("chevron-right") : QStringLiteral("chevron-down"),
                      QRectF(x - 2, cy - 7, 14, 14), theme::textMuted(), 1.7);
        x += 18;
    }

    const QColor gc = colorOr(header.data(rec::GroupColor),
                              m_identity.isValid() ? m_identity : theme::textMuted());
    sticker::lamp(*p, QRectF(x - 2, cy - 5, 14, 10), gc);
    x += 18;
    QFont ef = sized(p->font(), 9.0, QFont::Black);
    ef.setLetterSpacing(QFont::AbsoluteSpacing, 0.8);
    const QString title = header.data(Qt::DisplayRole).toString();
    const QFontMetricsF efm(ef);
    p->setFont(ef);
    p->setPen(theme::textPrimary());
    // 金刚的分组备注是整句说明(「文件夹及其子目录中运行的所有程序…」),给它半行宽。
    const qreal noteW = theme::titan() ? qMax<qreal>(180.0, r.width() * 0.5) : 180.0;
    const QString shownTitle = efm.elidedText(title, Qt::ElideRight, qMax<qreal>(40, r.right() - x - noteW));
    p->drawText(QRectF(x, r.top(), r.width(), r.height()), Qt::AlignLeft | Qt::AlignVCenter, shownTitle);
    x += efm.horizontalAdvance(shownTitle) + 8;

    const QFont cf = sized(p->font(), 8.8, QFont::Normal);
    p->setFont(cf);
    p->setPen(theme::textMuted());
    p->drawText(QRectF(x, r.top(), 60, r.height()), Qt::AlignLeft | Qt::AlignVCenter,
                QString::number(header.data(rec::GroupCount).toInt()));

    const QString note = header.data(rec::GroupNote).toString();
    if (!note.isEmpty())
        p->drawText(QRectF(r.right() - 18 - noteW, r.top(), noteW, r.height()),
                    Qt::AlignRight | Qt::AlignVCenter,
                    QFontMetricsF(cf).elidedText(note, Qt::ElideRight, noteW));
    p->restore();
}

void RecordDelegate::paintRecord(QPainter* p, const QStyleOptionViewItem& opt, const QModelIndex& idx) const
{
    p->save();
    p->setRenderHint(QPainter::Antialiasing, true);
    const QRect r = opt.rect;
    const bool selected = opt.state.testFlag(QStyle::State_Selected);
    const bool hover = opt.state.testFlag(QStyle::State_MouseOver);
    const bool focus = opt.state.testFlag(QStyle::State_HasFocus);
    const bool dim = idx.data(rec::Dim).toBool();
    const QRectF card = QRectF(r).adjusted(6, 2, -6, -2);

    const QPainterPath cardPath = theme::panelPath(card.adjusted(1, 1, -1, -1), theme::mecha() ? 7.0 : 10.0);
    if (selected) {
        p->fillPath(cardPath, theme::blend(theme::accent(), theme::surface(), theme::mecha() ? 0.16 : 0.24));
        p->strokePath(cardPath, QPen(theme::ink(), 2.0, Qt::SolidLine, Qt::FlatCap, joinStyle()));
    } else {
        if (hover)
            p->fillPath(cardPath, theme::tint(theme::overlay(), 0.045));
        if (focus)
            p->strokePath(cardPath, QPen(theme::accentDeep(), 1.6, Qt::DashLine, Qt::FlatCap, joinStyle()));
    }

    const QColor accent = idx.data(rec::Accent).value<QColor>();
    if (accent.isValid())
        p->fillRect(QRectF(card.left() + 3, card.top() + 10, 4.0, card.height() - 20), accent);

    qreal lead = card.left() + 10;
    if (m_checkable) {
        const QRectF cb(card.left() + 12, r.center().y() - 9.0, 18.0, 18.0);
        const QRectF rim = cb.adjusted(1, 1, -1, -1);
        const QPainterPath box = theme::panelPath(rim, theme::mecha() ? 2.0 : 5.0);
        p->fillPath(box, selected ? (theme::mecha() ? theme::accent() : theme::cyan()) : theme::field());
        p->strokePath(box, QPen(theme::rim(), 2.0, Qt::SolidLine, Qt::FlatCap, joinStyle()));
        if (selected)
            AppIcon::draw(*p, QStringLiteral("check"), cb.adjusted(3.4, 3.4, -3.4, -3.4),
                          theme::mecha() ? theme::accentInk() : theme::ink(), 2.2);
        lead = cb.right() + 12;
    }

    constexpr qreal box = 32;
    // 金刚:导轨挪到图标左边,每条记录一个菱形节点(颜色 = 处置结果),图标块随之右移。
    const bool diamondRail = m_rail && theme::titan();
    if (diamondRail)
        lead += 18;
    const qreal ix = lead;
    const qreal iy = r.center().y() - box / 2.0;
    if (m_rail) {
        const QAbstractItemModel* m = idx.model();
        const QModelIndex prev = idx.sibling(idx.row() - 1, 0);
        const QModelIndex next = idx.row() + 1 < m->rowCount() ? idx.sibling(idx.row() + 1, 0) : QModelIndex();
        const bool up = prev.isValid() && !prev.data(rec::Header).toBool();
        const bool down = next.isValid() && !next.data(rec::Header).toBool();
        const qreal cx = diamondRail ? ix - 11.0 : ix + box / 2.0;
        const qreal top = up ? r.top() : r.center().y();
        const qreal bottom = down ? r.bottom() + 1 : r.center().y();
        if (bottom > top) {
            p->setPen(QPen(theme::rim(), 2.0, Qt::DotLine));
            p->drawLine(QPointF(cx, top), QPointF(cx, bottom));
        }
        if (diamondRail) {
            const qreal cy = r.center().y();
            const QPolygonF node{QPointF(cx, cy - 5.5), QPointF(cx + 5.5, cy), QPointF(cx, cy + 5.5), QPointF(cx - 5.5, cy)};
            p->setPen(QPen(theme::ink(), 1.5, Qt::SolidLine, Qt::SquareCap, Qt::MiterJoin));
            p->setBrush(colorOr(idx.data(rec::PillColor), theme::textMuted()));
            p->drawPolygon(node);
        }
    }
    QColor ic = colorOr(idx.data(rec::IconColor), theme::textSecondary());
    if (dim)
        ic = theme::blend(ic, theme::surface(), 0.55);
    {
        const QRectF t(ix + 1, iy + 1, box - 2, box - 2);
        const QPainterPath tile = theme::panelPath(t, theme::mecha() ? 8.0 : 8.0);
        // 浅色皮肤:淡色瓦片上画墨色图标;金刚:暗色瓦片上画本色图标(暗底上墨色图标看不见)。
        const bool darkTile = theme::titan();
        p->fillPath(tile, theme::blend(ic, theme::surface(), darkTile ? 0.24 : theme::mecha() ? 0.30 : 0.42));
        p->strokePath(tile, QPen(theme::ink(), 1.7, Qt::SolidLine, Qt::FlatCap, joinStyle()));
        AppIcon::draw(*p, idx.data(rec::Icon).toString(), QRectF(ix + 8, iy + 8, 16, 16),
                      dim ? theme::textMuted() : (darkTile ? ic : theme::ink()), 1.9);
    }

    qreal right = card.right() - 12;
    const QDateTime when = idx.data(rec::Time).toDateTime();
    const QString meta = when.isValid() ? fmt::relativeTime(when) : idx.data(rec::Meta).toString();
    if (!meta.isEmpty()) {
        const QFont mf = sized(opt.font, 9.0, QFont::Normal);
        const qreal w = QFontMetricsF(mf).horizontalAdvance(meta);
        p->setFont(mf);
        p->setPen(theme::textMuted());
        p->drawText(QRectF(right - w, r.top(), w + 1, r.height()), Qt::AlignRight | Qt::AlignVCenter, meta);
        right -= w + 14;
    }
    const QString pill = idx.data(rec::Pill).toString();
    if (!pill.isEmpty()) {
        const QFont pf = sized(opt.font, 8.8, QFont::DemiBold);
        const qreal w = QFontMetricsF(pf).horizontalAdvance(pill) + 18;
        drawCapsule(p, QRectF(right - w, r.center().y() - 11, w, 22), pill,
                    colorOr(idx.data(rec::PillColor), theme::textSecondary()), pf, idx.data(rec::PillSolid).toBool());
        right -= w + 10;
    }
    const QString score = idx.data(rec::Score).toString();
    if (!score.isEmpty()) {
        const QFont sf = sized(opt.font, 11.0, QFont::Bold);
        const qreal w = QFontMetricsF(sf).horizontalAdvance(score);
        p->setFont(sf);
        p->setPen(colorOr(idx.data(rec::ScoreColor), theme::textSecondary()));
        p->drawText(QRectF(right - w, r.top(), w + 1, r.height()), Qt::AlignRight | Qt::AlignVCenter, score);
        right -= w + 12;
    }

    const qreal tx = ix + box + 12;
    const qreal tw = qMax<qreal>(40.0, right - tx);
    const QString title = idx.data(Qt::DisplayRole).toString();
    const QString sub = idx.data(rec::Subtitle).toString();
    const QStringList chips = idx.data(rec::Chips).toStringList();
    const QVariantList chipColors = idx.data(rec::ChipColors).toList();
    const bool two = !sub.isEmpty() || !chips.isEmpty();

    const QFont tf = sized(opt.font, 10.0, QFont::DemiBold);
    p->setFont(tf);
    p->setPen(dim ? theme::textSecondary() : theme::textPrimary());
    const QRectF titleR(tx, two ? r.top() + 9 : r.top(), tw, two ? 22 : r.height());
    p->drawText(titleR, Qt::AlignLeft | Qt::AlignVCenter,
                QFontMetricsF(tf).elidedText(title, Qt::ElideRight, tw));

    if (two) {
        qreal x = tx;
        const qreal y = r.top() + 32;
        constexpr qreal lh = 19;
        const QFont cf = sized(opt.font, 8.5, QFont::Medium);
        const QFontMetricsF cfm(cf);
        qreal chipsW = 0;
        for (const QString& c : chips)
            chipsW += cfm.horizontalAdvance(c) + 14 + 6;

        if (!sub.isEmpty()) {
            const bool isMono = idx.data(rec::SubtitleMono).toBool();
            const QFont sf = isMono ? mono(8.8) : sized(opt.font, 9.0, QFont::Normal);
            const QFontMetricsF sfm(sf);
            const qreal avail = chips.isEmpty() ? tw : qMax(tw * 0.5, tw - chipsW - 8);
            const QString s = sfm.elidedText(sub, isMono ? Qt::ElideMiddle : Qt::ElideRight, avail);
            p->setFont(sf);
            p->setPen(theme::textMuted());
            p->drawText(QRectF(x, y, avail, lh), Qt::AlignLeft | Qt::AlignVCenter, s);
            x += sfm.horizontalAdvance(s) + 10;
        }
        for (int i = 0; i < chips.size(); ++i) {
            const qreal cw = cfm.horizontalAdvance(chips[i]) + 14;
            if (x + cw > tx + tw) {
                const QString more = QStringLiteral("+%1").arg(chips.size() - i);
                if (x + cfm.horizontalAdvance(more) <= tx + tw) {
                    p->setFont(cf);
                    p->setPen(theme::textMuted());
                    p->drawText(QRectF(x, y, 40, lh), Qt::AlignLeft | Qt::AlignVCenter, more);
                }
                break;
            }
            const QRectF cr(x, y + 0.5, cw, lh - 1);
            QColor cc = i < chipColors.size() ? chipColors[i].value<QColor>() : QColor();
            if (cc.isValid() && dim)
                cc = theme::blend(cc, theme::textMuted(), 0.45);
            const QPainterPath chip = theme::panelPath(cr.adjusted(0.6, 0.6, -0.6, -0.6),
                                                       theme::mecha() ? 3.0 : cr.height() / 2.7);
            p->fillPath(chip, cc.isValid() ? theme::blend(cc, theme::surface(), 0.14)
                                           : theme::blend(theme::overlay(), theme::surface(), 0.06));
            p->strokePath(chip, QPen(theme::tint(theme::overlay(), theme::titan() ? 0.28 : 0.45), 1.0,
                                     Qt::SolidLine, Qt::FlatCap, joinStyle()));
            p->setFont(cf);
            p->setPen(cc.isValid() ? cc : (dim ? theme::textMuted() : theme::textSecondary()));
            p->drawText(cr, Qt::AlignCenter, chips[i]);
            x += cw + 6;
        }
    }

    if (!selected && !hover) {
        QPen sep(theme::tint(theme::overlay(), theme::titan() ? 0.12 : 0.22), 1.5, Qt::CustomDashLine);
        sep.setDashPattern({3.0, 3.0});
        p->setPen(sep);
        p->drawLine(QPointF(tx, r.bottom() + 0.5), QPointF(card.right() - 12, r.bottom() + 0.5));
    }
    p->restore();
}

RecordListView::RecordListView(QWidget* parent) : QListView(parent)
{
    setObjectName(QStringLiteral("RecordList"));
    m_delegate = new RecordDelegate(this);
    setItemDelegate(m_delegate);
    setFrameShape(QFrame::NoFrame);
    setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    verticalScrollBar()->setSingleStep(24);
    setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    setMouseTracking(true);
    viewport()->setAttribute(Qt::WA_Hover, true);
    viewport()->setAutoFillBackground(false);
    setSelectionBehavior(QAbstractItemView::SelectRows);
    setSelectionMode(QAbstractItemView::SingleSelection);
    setEditTriggers(QAbstractItemView::NoEditTriggers);
    setUniformItemSizes(true);
    setResizeMode(QListView::Adjust);
    setLayoutMode(QListView::SinglePass);
    setFocusPolicy(Qt::StrongFocus);
    setContextMenuPolicy(Qt::CustomContextMenu);

    m_clock = new QTimer(this);
    m_clock->setInterval(30000);
    connect(m_clock, &QTimer::timeout, viewport(), qOverload<>(&QWidget::update));
    m_clock->start();
}

void RecordListView::setStickyHeaders(bool on)
{
    m_sticky = on;
    viewport()->update();
}

void RecordListView::setBottomInset(int px)
{
    px = qMax(0, px);
    if (px == m_bottomInset)
        return;
    m_bottomInset = px;
    setViewportMargins(0, 0, 0, px);
}

void RecordListView::keyboardSearch(const QString& search)
{
    if (selectionMode() == QAbstractItemView::MultiSelection)
        return;
    QListView::keyboardSearch(search);
}

QModelIndex RecordListView::headerFor(const QModelIndex& idx) const
{
    for (QModelIndex i = idx; i.isValid(); i = i.sibling(i.row() - 1, 0)) {
        if (i.data(rec::Header).toBool())
            return i;
        if (i.row() == 0)
            break;
    }
    return {};
}

void RecordListView::paintEvent(QPaintEvent* e)
{
    QListView::paintEvent(e);
    m_stickyRect = QRect();
    m_stickyGroup.clear();
    if (!m_sticky || !model() || model()->rowCount() == 0)
        return;
    const QModelIndex top = indexAt(QPoint(24, 1));
    if (!top.isValid())
        return;
    const QModelIndex hdr = headerFor(top);
    if (!hdr.isValid())
        return;
    const QRect hr = visualRect(hdr);
    if (hr.isValid() && hr.top() >= 0)
        return;

    QRect band(0, 0, viewport()->width(), RecordDelegate::kStickyH);
    for (int row = top.row() + 1; row < model()->rowCount(); ++row) {
        const QModelIndex i = model()->index(row, 0);
        const QRect vr = visualRect(i);
        if (!vr.isValid() || vr.top() > band.bottom() + 2)
            break;
        if (i.data(rec::Header).toBool()) {
            if (vr.top() < band.height())
                band.moveTop(vr.top() - band.height());
            break;
        }
    }
    QPainter p(viewport());
    m_delegate->paintHeader(&p, band, hdr, true);
    m_stickyRect = band;
    m_stickyGroup = hdr.data(rec::Group).toString();
}

void RecordListView::scrollContentsBy(int dx, int dy)
{
    QListView::scrollContentsBy(dx, dy);
    if (m_sticky)
        viewport()->update(); // the pinned header must not be blitted along with the rows
}

void RecordListView::mousePressEvent(QMouseEvent* e)
{
    if (e->button() == Qt::LeftButton) {
        const QPoint pos = e->position().toPoint();
        if (m_stickyRect.isValid() && m_stickyRect.contains(pos) && !m_stickyGroup.isEmpty()) {
            emit headerClicked(m_stickyGroup);
            e->accept();
            return;
        }
        const QModelIndex i = indexAt(pos);
        if (i.isValid() && i.data(rec::Header).toBool()) {
            emit headerClicked(i.data(rec::Group).toString());
            e->accept();
            return;
        }
    }
    QListView::mousePressEvent(e);
}

void RecordListView::mouseDoubleClickEvent(QMouseEvent* e)
{
    const QPoint pos = e->position().toPoint();
    if (m_stickyRect.contains(pos)) {
        e->accept();
        return;
    }
    const QModelIndex i = indexAt(pos);
    if (i.isValid() && i.data(rec::Header).toBool()) {
        e->accept();
        return;
    }
    if (selectionMode() == QAbstractItemView::MultiSelection && e->button() == Qt::LeftButton) {
        QMouseEvent press(QEvent::MouseButtonPress, e->position(), e->scenePosition(), e->globalPosition(),
                          e->button(), e->buttons(), e->modifiers(), e->pointingDevice());
        mousePressEvent(&press);
        e->accept();
        return;
    }
    QListView::mouseDoubleClickEvent(e);
}
