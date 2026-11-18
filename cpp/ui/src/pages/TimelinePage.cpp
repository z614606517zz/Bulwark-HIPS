#include "pages/TablePages.h"
#include "pages/PageKit.h"
#include "dialogs/EventFormat.h"
#include "dialogs/EventViews.h"
#include "design/Banner.h"
#include "design/FilterChip.h"
#include "design/Format.h"
#include "design/GlowCard.h"
#include "design/Identity.h"
#include "design/Inspector.h"
#include "design/ListShell.h"
#include "design/Segmented.h"
#include "ipc/IpcClient.h"
#include "widgets/ElidingLabel.h"
#include "Nav.h"

#include <QCheckBox>
#include <QCompleter>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHash>
#include <QLineEdit>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QSignalBlocker>
#include <QStringListModel>
#include <QTimeZone>
#include <QToolTip>

#include <algorithm>
#include <cmath>
#include <functional>
#include <iterator>
#include <memory>

using evtfmt::u;
using bulwark::ipc::EventLogPayload;

namespace {

enum Seg { SegAll = 0, SegMissed, SegBlock, SegAsk, SegAllow, SegCount };

// 与事件记录页同一口径:判为拦截但处置没有生效(仅告警 / 处置失败)的行单独归「未拦住」,
// 不计入「拦截」。
bool isMissed(const EventLogPayload& p)
{
    return p.action == bulwark::VerdictAction::Block && evtfmt::needsManualAction(p.enforcement);
}

// 「进程」框里填的是不是 PID;不是(返回 0)就按程序名处理。
int pidOf(const QString& text)
{
    bool ok = false;
    const int pid = text.trimmed().toInt(&ok);
    return ok && pid > 0 ? pid : 0;
}

QString actorFile(const EventLogPayload& p)
{
    return QFileInfo(p.event.actorPath).fileName();
}

// 已载入事件里出现过的发起程序名,出现得多的排前面,给「进程」框当候选。
QStringList actorNames(const QList<EventLogPayload>& events)
{
    struct Seen {
        QString name;
        int count = 0;
    };
    QHash<QString, Seen> seen;
    for (const EventLogPayload& e : events) {
        const QString name = actorFile(e);
        if (name.isEmpty())
            continue;
        Seen& s = seen[name.toLower()];
        if (s.count++ == 0)
            s.name = name;
    }
    QList<Seen> order = seen.values();
    std::sort(order.begin(), order.end(), [](const Seen& a, const Seen& b) {
        return a.count != b.count ? a.count > b.count : a.name.compare(b.name, Qt::CaseInsensitive) < 0;
    });
    QStringList names;
    names.reserve(order.size());
    for (const Seen& s : order)
        names << s.name;
    return names;
}

struct RangeOption {
    const char* key;
    const char* label;
    int seconds;
};
const RangeOption kRanges[] = {
    {"15m", "15 分钟", 15 * 60},  {"1h", "1 小时", 3600},       {"6h", "6 小时", 6 * 3600},
    {"24h", "24 小时", 24 * 3600}, {"7d", "7 天", 7 * 24 * 3600}, {"all", "全部", 0},
};
constexpr int kDefaultRange = 3;
constexpr int kQueryLimit = 2000;

QString hourTitle(const QDateTime& local)
{
    const QDate d = local.date();
    const QDate today = QDate::currentDate();
    const QString hh = local.toString(QStringLiteral("HH:00"));
    if (d == today)
        return u("今天 ") + hh;
    if (d == today.addDays(-1))
        return u("昨天 ") + hh;
    if (d.year() == today.year())
        return local.toString(QStringLiteral("MM-dd ")) + hh;
    return local.toString(QStringLiteral("yyyy-MM-dd ")) + hh;
}

class DensityBar : public QWidget
{
public:
    struct Sample {
        qint64 ms;
        int severity;
    };
    std::function<void(const QDateTime& from, const QDateTime& to)> onSelect;
    QColor hue;

    DensityBar()
    {
        setMouseTracking(true);
        setMinimumHeight(66);
        setCursor(Qt::CrossCursor);
        setAccessibleName(u("事件密度,拖动选择时间段"));
    }

    void setData(const QDateTime& from, const QDateTime& to, const QList<Sample>& samples)
    {
        m_from = from.toMSecsSinceEpoch();
        m_to = std::max(to.toMSecsSinceEpoch(), m_from + 60 * 1000);
        m_count.fill(0, kBuckets);
        m_sev.fill(0, kBuckets);
        for (const Sample& s : samples) {
            const int b = bucketOf(s.ms);
            if (b < 0)
                continue;
            ++m_count[b];
            m_sev[b] = std::max(m_sev[b], s.severity);
        }
        m_max = 0;
        for (int c : std::as_const(m_count))
            m_max = std::max(m_max, c);
        m_selA = m_selB = -1;
        update();
    }

    void clearSelection()
    {
        m_selA = m_selB = -1;
        update();
    }

    QSize sizeHint() const override { return {480, 66}; }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const QRectF plot = plotRect();
        const qreal bw = plot.width() / kBuckets;
        if (m_selA >= 0) {
            const int a = std::min(m_selA, m_selB);
            const int b = std::max(m_selA, m_selB);
            const QRectF sel(plot.left() + a * bw, plot.top() - 3, (b - a + 1) * bw, plot.height() + 6);
            if (theme::titan()) {
                // 金刚:选区是能量蓝的框,两端各一根把手。
                const QColor g = theme::pal().glow;
                p.setPen(QPen(g, 1.5));
                p.setBrush(theme::blend(g, theme::surface(), 0.12));
                p.drawRect(sel);
                p.setPen(Qt::NoPen);
                p.setBrush(g);
                p.drawRect(QRectF(sel.left() - 1.5, sel.center().y() - 8.0, 3.0, 16.0));
                p.drawRect(QRectF(sel.right() - 1.5, sel.center().y() - 8.0, 3.0, 16.0));
            } else {
                p.setPen(QPen(theme::blend(theme::accent(), theme::surface(), 0.65), 1.0));
                p.setBrush(theme::blend(theme::accent(), theme::surface(), 0.16));
                p.drawRoundedRect(sel, 4, 4);
            }
        }
        for (int i = 0; i < m_count.size(); ++i) {
            const qreal x = plot.left() + i * bw;
            if (m_count[i] == 0 || m_max == 0) {
                p.setPen(Qt::NoPen);
                p.setBrush(theme::border());
                p.drawRect(QRectF(x + 1, plot.bottom() - 1, std::max(1.0, bw - 2), 1));
                continue;
            }
            const qreal h = std::max(3.0, std::sqrt(qreal(m_count[i]) / m_max) * plot.height());
            QColor c = m_sev[i] >= 2 ? theme::danger()
                       : m_sev[i] == 1 ? theme::warning()
                                       : theme::blend(hue.isValid() ? hue : theme::accent(), theme::surface(), 0.62);
            if (i == m_hover)
                c = c.lighter(130);
            p.setPen(Qt::NoPen);
            p.setBrush(c);
            p.drawRoundedRect(QRectF(x + 1, plot.bottom() - h, std::max(1.0, bw - 2), h), 1.5, 1.5);
        }
        QFont f = font();
        f.setPointSizeF(8.0);
        p.setFont(f);
        p.setPen(theme::textMuted());
        const QRectF axis(plot.left(), plot.bottom() + 3, plot.width(), 14);
        p.drawText(axis, Qt::AlignLeft | Qt::AlignVCenter, label(m_from));
        p.drawText(axis, Qt::AlignHCenter | Qt::AlignVCenter, label(m_from + (m_to - m_from) / 2));
        p.drawText(axis, Qt::AlignRight | Qt::AlignVCenter, label(m_to));
    }

    void mousePressEvent(QMouseEvent* e) override
    {
        if (e->button() != Qt::LeftButton)
            return;
        m_prevA = m_selA;
        m_prevB = m_selB;
        m_selA = m_selB = bucketAtX(e->position().x());
        update();
    }

    void mouseMoveEvent(QMouseEvent* e) override
    {
        const int b = bucketAtX(e->position().x());
        if (e->buttons() & Qt::LeftButton) {
            if (b != m_selB) {
                m_selB = b;
                update();
            }
        }
        if (b != m_hover) {
            m_hover = b;
            update();
        }
        if (b >= 0 && b < m_count.size())
            QToolTip::showText(e->globalPosition().toPoint(), tip(b), this);
    }

    void mouseReleaseEvent(QMouseEvent* e) override
    {
        if (e->button() != Qt::LeftButton || m_selA < 0)
            return;
        int a = std::min(m_selA, m_selB);
        int b = std::max(m_selA, m_selB);
        const int pa = std::min(m_prevA, m_prevB);
        const int pb = std::max(m_prevA, m_prevB);
        if (a == b && a == pa && b == pb)
            a = b = -1;
        m_selA = a;
        m_selB = b;
        update();
        if (onSelect) {
            if (a < 0)
                onSelect(QDateTime(), QDateTime());
            else
                onSelect(QDateTime::fromMSecsSinceEpoch(bucketStart(a), QTimeZone::UTC),
                         QDateTime::fromMSecsSinceEpoch(bucketStart(b + 1), QTimeZone::UTC));
        }
    }

    void leaveEvent(QEvent*) override
    {
        m_hover = -1;
        update();
    }

private:
    static constexpr int kBuckets = 60;

    QRectF plotRect() const { return QRectF(rect()).adjusted(6, 8, -6, -20); }

    qint64 bucketStart(int i) const { return m_from + (m_to - m_from) * i / kBuckets; }

    int bucketOf(qint64 ms) const
    {
        if (ms < m_from || ms > m_to || m_to <= m_from)
            return -1;
        return std::clamp(int((ms - m_from) * kBuckets / (m_to - m_from)), 0, kBuckets - 1);
    }

    int bucketAtX(qreal x) const
    {
        const QRectF plot = plotRect();
        return std::clamp(int((x - plot.left()) / (plot.width() / kBuckets)), 0, kBuckets - 1);
    }

    QString label(qint64 ms) const
    {
        const QDateTime t = QDateTime::fromMSecsSinceEpoch(ms).toLocalTime();
        // 首尾不在同一天就带上日期:选「24 小时」时两头是同一个钟点,只写「时:分」分不清哪头是昨天;
        // 短范围跨过午夜时也一样。
        const bool sameDay = QDateTime::fromMSecsSinceEpoch(m_from).toLocalTime().date()
                             == QDateTime::fromMSecsSinceEpoch(m_to).toLocalTime().date();
        return t.toString(sameDay ? QStringLiteral("HH:mm") : QStringLiteral("MM-dd HH:mm"));
    }

    QString tip(int b) const
    {
        const QString span = u("%1 – %2").arg(label(bucketStart(b)), label(bucketStart(b + 1)));
        if (m_count.value(b) == 0)
            return span + u(" · 没有事件");
        return span + u(" · %1 条").arg(m_count.value(b))
             + (m_sev.value(b) >= 2 ? u(",含拦截") : (m_sev.value(b) == 1 ? u(",含询问") : QString()));
    }

    qint64 m_from = 0;
    qint64 m_to = 1;
    QVector<int> m_count = QVector<int>(kBuckets, 0);
    QVector<int> m_sev = QVector<int>(kBuckets, 0);
    int m_max = 0;
    int m_selA = -1;
    int m_selB = -1;
    int m_prevA = -1;
    int m_prevB = -1;
    int m_hover = -1;
};

}

QWidget* pages::timeline(IpcClient* ipc)
{
    auto* page = new RecordBrowser;
    page->setIdentity(identity::page(nav::Timeline));
    page->setGrouped(true, true, true);
    page->searchBox()->setPlaceholderText(u("过滤结果 · 回车在全部历史里检索"));
    page->searchBox()->setToolTip(u("输入即在已载入的结果里过滤(多个关键词用空格分隔);"
                                    "按回车按关键字(路径 / 目标 / 命令行 / 发布者)在服务端全部历史里查询"));
    page->setNoDataContent(QStringLiteral("clock"), u("这段时间里没有事件"),
                           u("换一个更长的时间范围,或清除进程 / 关键字条件后重新查询。"));
    auto store = std::make_shared<RecordStore<EventLogPayload>>(page->model(), &evtview::recordView);
    const QString trustSource = u("从时间线信任");

    auto* query = new QWidget;
    auto* qh = new QHBoxLayout(query);
    qh->setContentsMargins(0, 0, 0, 0);
    qh->setSpacing(10);
    auto* range = new Segmented;
    range->setCompact(true);
    range->setIdentity(page->identity());
    range->setAccessibleName(u("时间范围"));
    for (const RangeOption& r : kRanges)
        range->addSegment(u(r.label), r.seconds);
    range->setCurrentIndex(kDefaultRange);
    qh->addWidget(ui::label(u("时间范围"), "caption"));
    qh->addWidget(range);
    qh->addSpacing(12);
    qh->addWidget(ui::label(u("进程"), "caption"));
    // 程序名或 PID 都可以填:用户通常只知道程序叫什么,PID 要先去别处查。候选来自已载入的事件。
    auto* pidEdit = new QLineEdit;
    pidEdit->setPlaceholderText(u("程序名或 PID"));
    pidEdit->setClearButtonEnabled(true);
    pidEdit->setFixedWidth(156);
    pidEdit->setAccessibleName(u("只看某个进程(程序名或 PID)"));
    pidEdit->setToolTip(u("只看某个程序的事件:填程序名(可从候选里选)或 PID,回车查询。"
                          "填 PID 时可以连它派生的子进程一起看。"));
    auto* procNames = new QStringListModel(pidEdit);
    auto* procCompleter = new QCompleter(procNames, pidEdit);
    procCompleter->setCaseSensitivity(Qt::CaseInsensitive);
    procCompleter->setFilterMode(Qt::MatchContains);
    pidEdit->setCompleter(procCompleter);
    auto* treeBox = new QCheckBox(u("含子进程"));
    treeBox->setChecked(true);
    treeBox->setToolTip(u("按 PID 查询时,把该进程派生出来的整棵进程树的事件一并纳入;按程序名查询时不起作用。"));
    qh->addWidget(pidEdit);
    qh->addWidget(treeBox);
    auto* summary = ui::elided(QString(), "muted");
    summary->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    qh->addWidget(summary, 1);
    page->addTop(query);

    auto* density = new DensityBar;
    density->hue = page->identity();
    auto* densityCard = new GlowCard;
    densityCard->setObjectName(QStringLiteral("Card"));
    densityCard->setRadius(14);
    densityCard->setGlow(page->identity(), QPointF(0.0, 0.0), 0.6, 0.06);
    auto* dl = new QVBoxLayout(densityCard);
    dl->setContentsMargins(10, 4, 10, 2);
    dl->addWidget(density);
    page->addAboveList(densityCard);

    Segmented* seg = page->segments();
    seg->addSegment(u("全部"));
    seg->addSegment(u("未拦住"));
    seg->addSegment(u("拦截"));
    seg->addSegment(u("询问"));
    seg->addSegment(u("放行"));
    seg->setAccent(SegMissed, theme::warning());
    seg->setAccent(SegBlock, theme::danger());
    seg->setAccent(SegAsk, theme::warning());
    FilterChip* typeChip = page->addChip(u("类型"));
    typeChip->addOption(u("全部"));
    for (int i = 0; i <= int(bulwark::EventType::RemoteShareAccess); ++i)
        typeChip->addOption(evtfmt::typeShort(bulwark::EventType(i)), i);
    FilterChip* riskChip = page->addChip(u("风险"));
    riskChip->addOption(u("全部"), 0);
    riskChip->addOption(u("可疑及以上"), 50);
    riskChip->addOption(u("仅高危"), 80);
    auto* sliceChip = ui::button(QString(), "ghost", QStringLiteral("close"), true);
    sliceChip->setToolTip(u("清除时间段选择"));
    sliceChip->hide();
    page->addFilterWidget(sliceChip);

    auto slice = std::make_shared<QPair<QDateTime, QDateTime>>();
    page->setPredicate([store, seg, typeChip, riskChip, slice](int row) {
        const EventLogPayload* p = store->itemAt(row);
        if (!p)
            return true;
        using V = bulwark::VerdictAction;
        switch (seg->currentIndex()) {
        case SegMissed: if (!isMissed(*p)) return false; break;
        case SegBlock:  if (p->action != V::Block || isMissed(*p)) return false; break;
        case SegAsk:    if (p->action != V::Ask) return false; break;
        case SegAllow:  if (p->action != V::Allow) return false; break;
        default: break;
        }
        if (typeChip->isActive() && int(p->event.type) != typeChip->currentData().toInt())
            return false;
        if (riskChip->isActive() && p->event.riskScore < riskChip->currentData().toInt())
            return false;
        if (slice->first.isValid()
            && (p->event.timestampUtc < slice->first || p->event.timestampUtc >= slice->second))
            return false;
        return true;
    });
    const auto setSlice = [page, slice, sliceChip](const QDateTime& from, const QDateTime& to) {
        *slice = qMakePair(from, to);
        if (from.isValid()) {
            const bool sameDay = from.toLocalTime().date() == to.toLocalTime().date();
            const QString fmtStr = sameDay ? QStringLiteral("HH:mm") : QStringLiteral("MM-dd HH:mm");
            sliceChip->setText(u("%1 – %2").arg(from.toLocalTime().toString(QStringLiteral("MM-dd HH:mm")),
                                                to.toLocalTime().toString(fmtStr)));
        }
        sliceChip->setVisible(from.isValid());
        page->refilter();
    };
    density->onSelect = setSlice;
    QObject::connect(sliceChip, &QPushButton::clicked, page, [density, setSlice] {
        density->clearSelection();
        setSlice(QDateTime(), QDateTime());
    });
    page->setClearFilters([seg, typeChip, riskChip, density, slice, sliceChip] {
        seg->setCurrentIndex(SegAll);
        typeChip->reset();
        riskChip->reset();
        density->clearSelection();
        *slice = {};
        sliceChip->hide();
    });
    const auto updateCounts = [store, seg] {
        int n[SegCount] = {};
        for (const EventLogPayload& p : store->items()) {
            ++n[SegAll];
            if (isMissed(p)) ++n[SegMissed];
            else if (p.action == bulwark::VerdictAction::Block) ++n[SegBlock];
            else if (p.action == bulwark::VerdictAction::Ask) ++n[SegAsk];
            else ++n[SegAllow];
        }
        for (int i = 0; i < SegCount; ++i)
            seg->setCount(i, n[i]);
    };
    QObject::connect(seg, &Segmented::currentChanged, page, [page] { page->refilter(); });
    for (FilterChip* c : {typeChip, riskChip})
        QObject::connect(c, &FilterChip::currentChanged, page, [page] { page->refilter(); });

    page->setInspectorBuilder([store, ipc, trustSource](Inspector* in, int row) {
        if (const EventLogPayload* p = store->itemAt(row))
            evtview::fillInspector(in, *p, ipc, trustSource);
    });
    page->setActivateHandler([page, store, ipc](int row) {
        if (const EventLogPayload* p = store->itemAt(row))
            evtview::openTimeline(page, p->event, ipc, evtview::outcomeOf(*p));
    });
    page->setContextMenuBuilder([page, store, ipc, trustSource](QMenu* m, const QList<int>& rows) {
        if (rows.size() != 1)
            return;
        if (const EventLogPayload* p = store->itemAt(rows.first()))
            evtview::fillContextMenu(m, page, *p, ipc, trustSource);
    });

    auto lastId = std::make_shared<QUuid>();
    auto serverText = std::make_shared<QString>();
    auto window = std::make_shared<QPair<QDateTime, QDateTime>>();
    // 上一次查询时「进程」框里的内容(PID 或程序名),以及其中按程序名查的那一种。
    auto lastProc = std::make_shared<QString>();
    auto procName = std::make_shared<QString>();
    const auto runQuery = [ipc, page, range, pidEdit, treeBox, summary, lastId, serverText, window, lastProc,
                           procName] {
        if (!ipc->isConnected())
            return;
        bulwark::ipc::TimelineRequestPayload req;
        const int secs = range->currentData().toInt();
        const QDateTime now = QDateTime::currentDateTimeUtc();
        if (secs > 0)
            req.fromUtc = now.addSecs(-secs);
        const QString proc = pidEdit->text().trimmed();
        req.pid = pidOf(proc);
        req.includeProcessTree = treeBox->isChecked();
        // 服务端只按 PID 认进程。填的是程序名时,没有别的关键字就把名字当关键字交给服务端先收窄
        // (它还会命中目标、命令行和发布者),结果回来后再按发起程序名筛一遍。
        *procName = req.pid > 0 ? QString() : proc;
        req.text = serverText->isEmpty() ? *procName : *serverText;
        req.limit = kQueryLimit;
        *lastProc = proc;
        *lastId = req.requestId;
        *window = qMakePair(req.fromUtc, now);
        page->setLoading(true);
        summary->setText(u("查询中…"));
        ipc->requestTimeline(req);
    };

    QObject::connect(ipc, &IpcClient::timelineReceived, page,
                     [page, store, density, summary, lastId, serverText, window, updateCounts, slice, sliceChip,
                      lastProc, procName, procNames](const bulwark::ipc::TimelineResponsePayload& p) {
        if (p.requestId != *lastId)
            return;
        // 候选只在没有按进程收窄时刷新:收窄后的结果里只剩那一个程序,拿它当候选就换不了别的了。
        if (lastProc->isEmpty() || procNames->rowCount() == 0)
            procNames->setStringList(actorNames(p.events));
        QList<EventLogPayload> events = p.events;
        if (!procName->isEmpty())
            events.removeIf([&procName](const EventLogPayload& e) {
                return !actorFile(e).contains(*procName, Qt::CaseInsensitive);
            });
        QList<EventLogPayload> items(events.crbegin(), events.crend());
        store->resetGrouped(
            items,
            [](const EventLogPayload& e) {
                return e.event.timestampUtc.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH"));
            },
            [](const QString&, const QList<const EventLogPayload*>& members) {
                RecordView h;
                const QDateTime t = members.isEmpty() ? QDateTime() : members.first()->event.timestampUtc.toLocalTime();
                h.title = hourTitle(t);
                int blocks = 0;
                int asks = 0;
                int maxRisk = 0;
                for (const EventLogPayload* m : members) {
                    if (evtfmt::isRealBlock(m->action, m->enforcement))
                        ++blocks;
                    else if (m->action == bulwark::VerdictAction::Ask)
                        ++asks;
                    maxRisk = std::max(maxRisk, m->event.riskScore);
                }
                QStringList note;
                if (blocks) note << u("拦截 %1").arg(blocks);
                if (asks) note << u("询问 %1").arg(asks);
                if (maxRisk >= 50) note << u("最高风险 %1").arg(maxRisk);
                h.groupNote = note.join(u(" · "));
                h.groupColor = blocks ? theme::danger() : (maxRisk >= 50 ? theme::warning() : QColor());
                return h;
            });
        page->setLoading(false);
        updateCounts();

        // Density over what was actually loaded: when the result was truncated,
        // older events weren't loaded, so the bar must not show that stretch as empty.
        const QDateTime to = window->second.isValid() ? window->second : QDateTime::currentDateTimeUtc();
        QDateTime from = window->first;
        if (!from.isValid() || p.truncated)
            from = p.events.isEmpty() ? (p.earliestUtc.isValid() ? p.earliestUtc : to.addSecs(-3600))
                                      : p.events.first().event.timestampUtc;
        QList<DensityBar::Sample> samples;
        samples.reserve(events.size());
        for (const EventLogPayload& e : events) {
            const int sev = evtfmt::isRealBlock(e.action, e.enforcement) ? 2
                            : e.action == bulwark::VerdictAction::Ask     ? 1
                                                                          : 0;
            samples.append(DensityBar::Sample{e.event.timestampUtc.toMSecsSinceEpoch(), sev});
        }
        density->setData(from, to, samples);
        *slice = {};
        sliceChip->hide();
        page->refilter();

        QStringList parts;
        if (events.isEmpty())
            parts << (p.message.isEmpty() || !p.events.isEmpty() ? u("没有符合条件的事件") : p.message);
        else
            parts << u("载入 %1 条").arg(events.size());
        if (!procName->isEmpty())
            parts << u("程序名含「%1」").arg(*procName);
        if (!serverText->isEmpty())
            parts << u("关键字「%1」").arg(*serverText);
        if (p.earliestUtc.isValid())
            parts << u("历史可回溯至 %1").arg(p.earliestUtc.toLocalTime().toString(QStringLiteral("MM-dd HH:mm")));
        summary->setText(parts.join(u(" · ")));
        if (p.truncated)
            ui::notify(page, ui::Tone::Warning,
                       procName->isEmpty()
                           ? u("命中 %1 条,只载入了最近的 %2 条。缩小时间范围,或按程序名 / PID 查询,才能看到更早的事件。")
                                 .arg(p.matched)
                                 .arg(p.events.size())
                           : u("命中 %1 条,只载入了最近的 %2 条,并从中筛出程序名对得上的。缩小时间范围,才能看到更早的事件。")
                                 .arg(p.matched)
                                 .arg(p.events.size()));
    });

    QObject::connect(range, &Segmented::currentChanged, page, [runQuery] { runQuery(); });
    // 「含子进程」只对 PID 有意义:填的是程序名时置灰,免得以为它在起作用。
    const auto syncTreeBox = [pidEdit, treeBox] {
        const QString proc = pidEdit->text().trimmed();
        treeBox->setEnabled(proc.isEmpty() || pidOf(proc) > 0);
    };
    QObject::connect(pidEdit, &QLineEdit::returnPressed, page, [runQuery] { runQuery(); });
    QObject::connect(pidEdit, &QLineEdit::textChanged, page, [runQuery, lastProc, syncTreeBox](const QString& t) {
        syncTreeBox();
        if (t.trimmed().isEmpty() && !lastProc->isEmpty())
            runQuery();
    });
    // 用鼠标点候选不会触发回车,这里补上查询;用键盘选中再回车时上面已经查过,不重复查。
    // 此刻输入框自己还没来得及换成选中的名字(它的连接建得比这里晚),所以先替它填上。
    QObject::connect(procCompleter, qOverload<const QString&>(&QCompleter::activated), page,
                     [runQuery, pidEdit, lastProc](const QString& name) {
        pidEdit->setText(name);
        if (name.trimmed() != *lastProc)
            runQuery();
    });
    QObject::connect(treeBox, &QCheckBox::toggled, page, [runQuery, pidEdit] {
        if (pidOf(pidEdit->text()) > 0)
            runQuery();
    });
    QObject::connect(page->searchBox(), &QLineEdit::returnPressed, page, [page, serverText, runQuery] {
        *serverText = page->searchBox()->text().trimmed();
        runQuery();
    });
    QObject::connect(page->searchBox(), &QLineEdit::textChanged, page, [serverText, runQuery](const QString& t) {
        if (t.trimmed().isEmpty() && !serverText->isEmpty()) {
            serverText->clear();
            runQuery();
        }
    });

    QHBoxLayout* actions = pagekit::headerActions(page);
    QObject::connect(pagekit::headerButton(actions, QStringLiteral("refresh"), u("重新查询")), &QPushButton::clicked,
                     page, [runQuery] { runQuery(); });

    pagekit::onConnected(page, ipc, page, 1200, runQuery);

    nav::onArrive(page, QString::fromLatin1(nav::Timeline),
                  [page, range, pidEdit, treeBox, serverText, runQuery, syncTreeBox](const QVariantMap& args) {
        {
            const QSignalBlocker b1(range);
            const QSignalBlocker b2(pidEdit);
            const QSignalBlocker b3(treeBox);
            if (args.contains(QStringLiteral("range"))) {
                const QString key = args.value(QStringLiteral("range")).toString();
                for (int i = 0; i < int(std::size(kRanges)); ++i)
                    if (key == QLatin1String(kRanges[i].key))
                        range->setCurrentIndex(i);
            }
            if (args.contains(QStringLiteral("pid"))) {
                const int pid = args.value(QStringLiteral("pid")).toInt();
                pidEdit->setText(pid > 0 ? QString::number(pid) : QString());
                treeBox->setChecked(args.value(QStringLiteral("tree"), true).toBool());
            }
        }
        syncTreeBox();
        if (args.contains(QStringLiteral("text"))) {
            *serverText = args.value(QStringLiteral("text")).toString().trimmed();
            page->searchBox()->setText(*serverText);
        }
        runQuery();
    });
    updateCounts();
    return page;
}
