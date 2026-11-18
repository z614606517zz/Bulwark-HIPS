#include "pages/TablePages.h"
#include "pages/PageKit.h"
#include "dialogs/EventFormat.h"
#include "dialogs/EventViews.h"
#include "design/Banner.h"
#include "design/Confirm.h"
#include "design/FilterChip.h"
#include "design/Identity.h"
#include "design/Inspector.h"
#include "design/ListShell.h"
#include "design/Segmented.h"
#include "ipc/IpcClient.h"
#include "Nav.h"

#include <QMenu>
#include <QPushButton>
#include <QTimer>

#include <algorithm>
#include <memory>

using evtfmt::u;
using bulwark::ipc::EventLogPayload;

namespace {

constexpr int kMaxRows = 1000;
constexpr int kRecentRows = 500;

enum Seg { SegAll = 0, SegMissed, SegBlock, SegAsk, SegAllow, SegCount };
const char* const kSegKeys[SegCount] = {"all", "missed", "block", "ask", "allow"};

// 判为拦截、但处置没有生效的行(仅告警 / 处置失败):动作已经发生,恰恰最需要人来处理。
// 单独归到「未拦住」页签,不混在「拦截」里充数;口径与总览页的「N 次拦截没有真正执行」一致。
bool isMissed(const EventLogPayload& p)
{
    return p.action == bulwark::VerdictAction::Block && evtfmt::needsManualAction(p.enforcement);
}

int retentionVictim(const QList<EventLogPayload>& rows)
{
    if (rows.size() <= kMaxRows)
        return -1;
    const int firstEvictable = std::min(kRecentRows, int(rows.size()));
    const auto oldestWithAction = [&rows, firstEvictable](bulwark::VerdictAction action) {
        for (int i = int(rows.size()) - 1; i >= firstEvictable; --i)
            if (rows[i].action == action)
                return i;
        return -1;
    };
    for (const bulwark::VerdictAction action : {bulwark::VerdictAction::Allow,
                                                 bulwark::VerdictAction::Ask,
                                                 bulwark::VerdictAction::Block}) {
        const int victim = oldestWithAction(action);
        if (victim >= 0)
            return victim;
    }
    return int(rows.size()) - 1;
}

void retainImportant(QList<EventLogPayload>& rows)
{
    while (rows.size() > kMaxRows)
        rows.removeAt(retentionVictim(rows));
}

void retainImportant(RecordStore<EventLogPayload>& store)
{
    while (store.size() > kMaxRows)
        store.removeAt(retentionVictim(store.items()));
}

int segFromKey(const QString& key, int fallback)
{
    for (int i = 0; i < SegCount; ++i)
        if (key == QLatin1String(kSegKeys[i]))
            return i;
    return fallback;
}

QWidget* buildEventsPage(IpcClient* ipc, int defaultSeg)
{
    auto* page = new RecordBrowser;
    page->setIdentity(identity::page(nav::Events));
    page->setLiveTop(true);
    page->searchBox()->setPlaceholderText(u("搜索程序 / 目标 / 命令行…"));
    page->setNoDataContent(QStringLiteral("activity"), u("暂无事件记录"),
                           u("防护运行后,被拦截、询问与放行的安全事件都会实时记在这里。"));
    auto store = std::make_shared<RecordStore<EventLogPayload>>(page->model(), &evtview::recordView);
    const QString trustSource = u("从事件记录信任");

    Segmented* seg = page->segments();
    seg->addSegment(u("全部"));
    seg->addSegment(u("未拦住"));
    seg->addSegment(u("拦截"));
    seg->addSegment(u("询问"));
    seg->addSegment(u("放行"));
    seg->setAccent(SegMissed, theme::warning());
    seg->setAccent(SegBlock, theme::danger());
    seg->setAccent(SegAsk, theme::warning());
    seg->setCurrentIndex(segFromKey(pagekit::remembered(QStringLiteral("events"), QStringLiteral("segment"),
                                                       QString::fromLatin1(kSegKeys[defaultSeg])),
                                    defaultSeg));

    FilterChip* typeChip = page->addChip(u("类型"));
    typeChip->addOption(u("全部"));
    for (int i = 0; i <= int(bulwark::EventType::RemoteShareAccess); ++i)
        typeChip->addOption(evtfmt::typeShort(bulwark::EventType(i)), i);
    FilterChip* riskChip = page->addChip(u("风险"));
    riskChip->addOption(u("全部"), 0);
    riskChip->addOption(u("可疑及以上"), 50);
    riskChip->addOption(u("仅高危"), 80);

    page->setPredicate([store, seg, typeChip, riskChip](int row) {
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
        return true;
    });
    page->setClearFilters([seg, typeChip, riskChip] {
        seg->setCurrentIndex(SegAll);
        typeChip->reset();
        riskChip->reset();
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
    QObject::connect(seg, &Segmented::currentChanged, page, [page](int i) {
        pagekit::remember(QStringLiteral("events"), QStringLiteral("segment"), QString::fromLatin1(kSegKeys[i]));
        page->refilter();
    });
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

    QHBoxLayout* actions = pagekit::headerActions(page);
    auto* pause = pagekit::headerButton(actions, QStringLiteral("pause"), u("暂停实时"));
    pause->setCheckable(true);
    pause->setToolTip(u("暂停后新事件先攒着不插进列表,方便对照查看;继续时一次补上。"));
    QMenu* more = pagekit::headerMenu(actions);
    auto queue = std::make_shared<QList<EventLogPayload>>();
    const auto syncPause = [pause, queue] {
        if (!pause->isChecked()) {
            pause->setText(u("暂停实时"));
            pause->setIcon(AppIcon::icon(QStringLiteral("pause"), theme::textSecondary(), 16));
        } else {
            pause->setText(queue->isEmpty() ? u("继续") : u("继续 · %1 条新事件").arg(queue->size()));
            pause->setIcon(AppIcon::icon(QStringLiteral("play"), theme::accentSoft(), 16));
        }
    };
    QObject::connect(pause, &QPushButton::toggled, page, [store, queue, syncPause, updateCounts](bool paused) {
        if (!paused && !queue->isEmpty()) {
            store->prependMany(*queue);
            retainImportant(*store);
            queue->clear();
            updateCounts();
        }
        syncPause();
    });

    auto clearPending = std::make_shared<bool>(false);
    pagekit::menuAction(more, QStringLiteral("trash"), u("清空事件历史…"), page, [page, ipc, clearPending] {
        if (!ipc->isConnected()) {
            ui::notify(page, ui::Tone::Danger, u("未连接后台服务,无法清空事件历史。"));
            return;
        }
        ui::ConfirmSpec s;
        s.risk = ui::Risk::Danger;
        s.title = u("清空全部事件历史");
        s.summary = u("事件记录与事件时间线读取的是同一份历史:清空后两处都会变空。");
        s.consequences << u("服务端的历史文件一并清空,重启后也不会再回填") << u("此操作不可撤销");
        s.confirmText = u("清空");
        if (!ui::confirm(page, s))
            return;
        *clearPending = true;
        ipc->clearEventHistory();
        QTimer::singleShot(8000, page, [page, clearPending] {
            if (!*clearPending)
                return;
            *clearPending = false;
            ui::notify(page, ui::Tone::Warning, u("没有收到服务的清空确认,列表可能还不是最新状态。"));
        });
    });

    QObject::connect(ipc, &IpcClient::eventLogReceived, page,
                     [store, pause, queue, syncPause, updateCounts](const EventLogPayload& p) {
        if (pause->isChecked()) {
            queue->prepend(p);
            retainImportant(*queue);
            syncPause();
            return;
        }
        store->prepend(p);
        retainImportant(*store);
        updateCounts();
    });
    QObject::connect(ipc, &IpcClient::eventHistoryReceived, page,
                     [page, store, queue, syncPause, updateCounts, clearPending](const QList<EventLogPayload>& events) {
        QList<EventLogPayload> rows(events.crbegin(), events.crend());
        retainImportant(rows);
        queue->clear();
        syncPause();
        store->reset(rows);
        page->setLoading(false);
        updateCounts();
        if (*clearPending) {
            *clearPending = false;
            ui::notify(page, events.isEmpty() ? ui::Tone::Success : ui::Tone::Warning,
                       events.isEmpty() ? u("事件历史已清空。") : u("服务回推的历史仍有 %1 条记录,清空可能没有完成。").arg(events.size()));
        }
    });
    pagekit::onConnected(page, ipc, page, 500, [page, ipc] {
        if (!ipc->isConnected())
            return;
        page->setLoading(true);
        ipc->requestEventHistory();
    });

    nav::onArrive(page, QString::fromLatin1(nav::Events), [page, seg](const QVariantMap& args) {
        if (args.contains(QStringLiteral("segment")))
            seg->setCurrentIndex(segFromKey(args.value(QStringLiteral("segment")).toString(), seg->currentIndex()));
        if (args.contains(QStringLiteral("select")))
            page->selectKey(args.value(QStringLiteral("select")).toString());
    });
    updateCounts();
    return page;
}

}

QWidget* pages::interceptions(IpcClient* ipc) { return buildEventsPage(ipc, SegBlock); }
QWidget* pages::activity(IpcClient* ipc) { return buildEventsPage(ipc, SegAll); }
