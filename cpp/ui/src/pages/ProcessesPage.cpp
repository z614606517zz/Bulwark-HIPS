#include "pages/TablePages.h"
#include "pages/PageKit.h"
#include "dialogs/EventFormat.h"
#include "dialogs/ProcessViews.h"
#include "design/Banner.h"
#include "design/EmptyState.h"
#include "design/Format.h"
#include "design/Icons.h"
#include "design/Identity.h"
#include "design/Inspector.h"
#include "design/ListShell.h"
#include "design/Segmented.h"
#include "design/Skin.h"
#include "design/Theme.h"
#include "design/ToggleSwitch.h"
#include "ipc/IpcClient.h"

#include <QApplication>
#include <QHash>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPainter>
#include <QPointer>
#include <QRegularExpression>
#include <QScrollBar>
#include <QSet>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QStyledItemDelegate>
#include <QTimer>
#include <QTreeView>

#include <functional>
#include <memory>
#include <utility>

using evtfmt::u;
using bulwark::ProcessEntry;
using Kind = bulwark::ipc::ProcessActionKind;

namespace {

enum Col { ColName = 0, ColPid, ColMem, ColSig, ColHint, ColCount };
constexpr int kIndexRole = Qt::UserRole + 1;
constexpr int kSortRole = Qt::UserRole + 2;
constexpr int kSubRole = Qt::UserRole + 3;
constexpr int kToneRole = Qt::UserRole + 4;
constexpr int kDescRole = Qt::UserRole + 5;
constexpr int kGlyphRole = Qt::UserRole + 6;
constexpr int kWatchRole = Qt::UserRole + 7;
constexpr int kRowH = 50;

enum Seg { SegAll = 0, SegWatch, SegUnsigned, SegHosted };

using Entries = QList<ProcessEntry>;

bool needsAttention(const ProcessEntry& e)
{
    return !e.isProtectedSelf && !e.isTrusted && !e.isCritical && (e.riskScore > 0 || e.signatureMismatch);
}

bool hosted(const ProcessEntry& e)
{
    return e.originKind == bulwark::ProcessOriginKind::Service
        || e.originKind == bulwark::ProcessOriginKind::ScheduledTask;
}

QColor toneOf(const ProcessEntry& e)
{
    return procview::tone(e);
}

// What would make the inspector content stale (memory ticks don't).
QString signatureOf(const ProcessEntry& e)
{
    return QStringLiteral("%1|%2|%3|%4|%5|%6")
        .arg(e.pid)
        .arg(e.imagePath)
        .arg(int(e.isTrusted))
        .arg(e.riskScore)
        .arg(e.originLabel())
        .arg(int(e.isSigned));
}

class NameDelegate : public QStyledItemDelegate
{
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter* p, const QStyleOptionViewItem& opt, const QModelIndex& idx) const override
    {
        QStyleOptionViewItem o(opt);
        initStyleOption(&o, idx);
        o.text.clear();
        o.icon = QIcon();
        const QWidget* w = opt.widget;
        QStyle* st = w ? w->style() : QApplication::style();
        st->drawControl(QStyle::CE_ItemViewItem, &o, p, w);

        p->save();
        p->setRenderHint(QPainter::Antialiasing, true);
        const QRect r = opt.rect.adjusted(8, 0, -8, 0);
        const QColor tone = idx.data(kToneRole).value<QColor>();
        const QString glyph = idx.data(kGlyphRole).toString();
        AppIcon::draw(*p, glyph.isEmpty() ? QStringLiteral("target") : glyph,
                      QRectF(r.left(), r.center().y() - 8, 16, 16), tone.isValid() ? tone : theme::textMuted(), 1.5);
        const QRect text = r.adjusted(26, 7, 0, -7);
        const int half = text.height() / 2;

        QFont nf = opt.font;
        nf.setWeight(QFont::DemiBold);
        const QFontMetrics nfm(nf);
        const QString name = nfm.elidedText(idx.data(Qt::DisplayRole).toString(), Qt::ElideRight, text.width());
        p->setFont(nf);
        p->setPen(theme::textPrimary());
        p->drawText(QRect(text.left(), text.top(), text.width(), half), Qt::AlignLeft | Qt::AlignVCenter, name);
        const int used = nfm.horizontalAdvance(name) + 10;
        const QString desc = idx.data(kDescRole).toString();
        QFont sf = opt.font;
        sf.setPointSizeF(std::max(7.5, opt.font.pointSizeF() - 1.0));
        const QFontMetrics sfm(sf);
        p->setFont(sf);
        if (!desc.isEmpty() && used < text.width() - 40) {
            p->setPen(theme::textSecondary());
            p->drawText(QRect(text.left() + used, text.top(), text.width() - used, half), Qt::AlignLeft | Qt::AlignVCenter,
                        sfm.elidedText(desc, Qt::ElideRight, text.width() - used));
        }
        p->setPen(theme::textMuted());
        p->drawText(QRect(text.left(), text.top() + half, text.width(), text.height() - half),
                    Qt::AlignLeft | Qt::AlignVCenter,
                    sfm.elidedText(idx.data(kSubRole).toString(), Qt::ElideMiddle, text.width()));
        p->restore();
    }

    QSize sizeHint(const QStyleOptionViewItem& opt, const QModelIndex& idx) const override
    {
        const QSize s = QStyledItemDelegate::sizeHint(opt, idx);
        return {std::max(s.width(), 240), kRowH};
    }
};

class ProcTree : public QTreeView
{
public:
    ProcTree()
    {
        setObjectName(QStringLiteral("ProcessTree"));
        setUniformRowHeights(true);
        setSortingEnabled(true);
        setSelectionBehavior(QAbstractItemView::SelectRows);
        setSelectionMode(QAbstractItemView::SingleSelection);
        setEditTriggers(QAbstractItemView::NoEditTriggers);
        setAllColumnsShowFocus(true);
        setExpandsOnDoubleClick(false);
        setContextMenuPolicy(Qt::CustomContextMenu);
        setAccessibleName(QString::fromUtf8("进程列表"));
        setIndentation(18);
    }

protected:
    // 金刚:有提示的进程在行首亮一道琥珀条。
    void drawRow(QPainter* p, const QStyleOptionViewItem& opt, const QModelIndex& index) const override
    {
        QTreeView::drawRow(p, opt, index);
        if (theme::titan() && index.siblingAtColumn(0).data(kWatchRole).toBool())
            p->fillRect(QRect(opt.rect.left(), opt.rect.top() + 8, 3, opt.rect.height() - 16), theme::warning());
    }

    void drawBranches(QPainter* p, const QRect& rect, const QModelIndex& index) const override
    {
        if (theme::titan() && index.parent().isValid()) {
            // 金刚:子进程前画「├ / └」连线,接到父进程那一列的展开箭头下面。
            int depth = 0;
            for (QModelIndex up = index.parent(); up.isValid(); up = up.parent())
                ++depth;
            const qreal x = rect.left() + depth * indentation() - 11.5;
            const qreal cy = rect.center().y();
            const bool more = index.sibling(index.row() + 1, 0).isValid();
            const bool hasKids = model() && model()->hasChildren(index);
            p->save();
            p->setPen(QPen(theme::rim(), 1.5));
            p->drawLine(QPointF(x, rect.top()), QPointF(x, more ? rect.bottom() + 1.0 : cy));
            p->drawLine(QPointF(x, cy), QPointF(rect.right() - (hasKids ? 19.0 : 4.0), cy));
            // 上面哪一层后面还有兄弟,那一层的竖线要从这一行穿过去,否则孙进程那一行会把树线截断。
            int level = depth - 1;
            for (QModelIndex up = index.parent(); up.isValid() && level >= 1; up = up.parent(), --level) {
                if (up.sibling(up.row() + 1, 0).isValid()) {
                    const qreal ax = rect.left() + level * indentation() - 11.5;
                    p->drawLine(QPointF(ax, rect.top()), QPointF(ax, rect.bottom() + 1.0));
                }
            }
            p->restore();
        }
        if (!model() || !model()->hasChildren(index))
            return;
        p->save();
        p->setRenderHint(QPainter::Antialiasing, true);
        const QRectF r(rect.right() - 17, rect.center().y() - 6, 12, 12);
        AppIcon::draw(*p, isExpanded(index) ? QStringLiteral("chevron-down") : QStringLiteral("chevron-right"), r,
                      theme::textMuted(), 1.6);
        p->restore();
    }
};

class ProcFilter : public QSortFilterProxyModel
{
public:
    std::shared_ptr<Entries> entries;
    std::function<bool(const ProcessEntry&)> pred;

    void setSearch(const QString& text)
    {
        static const QRegularExpression ws(QStringLiteral("\\s+"));
        m_terms = text.split(ws, Qt::SkipEmptyParts);
        refresh();
    }
    void refresh() { invalidateFilter(); }

    bool matches(const ProcessEntry& e) const
    {
        if (pred && !pred(e))
            return false;
        if (m_terms.isEmpty())
            return true;
        const QString hay = procview::searchText(e);
        for (const QString& t : m_terms)
            if (!hay.contains(t, Qt::CaseInsensitive))
                return false;
        return true;
    }

protected:
    bool filterAcceptsRow(int row, const QModelIndex& parent) const override
    {
        const int i = sourceModel()->index(row, ColName, parent).data(kIndexRole).toInt();
        return entries && i >= 0 && i < entries->size() && matches(entries->at(i));
    }

private:
    QStringList m_terms;
};

}

QWidget* pages::processes(IpcClient* ipc)
{
    auto* shell = new ListShell;
    shell->setIdentity(identity::page(nav::Processes));
    shell->searchBox()->setPlaceholderText(u("进程名 / 路径 / 服务 / 任务 / PID…"));
    auto entries = std::make_shared<Entries>();
    auto loading = std::make_shared<bool>(false);

    auto* model = new QStandardItemModel(shell);
    model->setHorizontalHeaderLabels({u("进程"), QStringLiteral("PID"), u("内存"), u("签名"), u("提示")});
    auto* proxy = new ProcFilter;
    proxy->setParent(shell);
    proxy->entries = entries;
    proxy->setSourceModel(model);
    proxy->setSortRole(kSortRole);
    proxy->setRecursiveFilteringEnabled(true);
    auto* view = new ProcTree;
    view->setModel(proxy);
    view->setItemDelegateForColumn(ColName, new NameDelegate(view));
    QHeaderView* hdr = view->header();
    hdr->setStretchLastSection(false);
    hdr->setSectionResizeMode(ColName, QHeaderView::Stretch);
    const std::pair<int, int> widths[] = {{ColPid, 78}, {ColMem, 96}, {ColSig, 92}, {ColHint, 108}};
    for (const auto& [col, width] : widths) {
        hdr->setSectionResizeMode(col, QHeaderView::Interactive);
        view->setColumnWidth(col, width);
    }
    view->sortByColumn(ColHint, Qt::DescendingOrder);
    shell->setView(view);

    Segmented* seg = shell->segments();
    seg->addSegment(u("全部"));
    seg->addSegment(u("需留意"));
    seg->addSegment(u("无签名"));
    seg->addSegment(u("服务 / 计划任务"));
    seg->setAccent(SegWatch, theme::warning());
    auto* mode = new Segmented;
    mode->setCompact(true);
    mode->setIdentity(shell->identity());
    mode->setAccessibleName(u("视图"));
    mode->addSegment(u("列表"), QStringLiteral("list"));
    mode->addSegment(u("进程树"), QStringLiteral("tree"));
    mode->setCurrentIndex(pagekit::remembered(QStringLiteral("processes"), QStringLiteral("view"),
                                              QStringLiteral("list")) == QLatin1String("tree")
                              ? 1
                              : 0);
    shell->addFilterWidget(mode);
    proxy->pred = [seg](const ProcessEntry& e) {
        switch (seg->currentIndex()) {
        case SegWatch:    return needsAttention(e);
        case SegUnsigned: return !e.isSigned;
        case SegHosted:   return hosted(e);
        default:          return true;
        }
    };

    auto itemByPid = std::make_shared<QHash<int, QStandardItem*>>();
    auto collapsed = std::make_shared<QSet<int>>();
    const auto pidAt = [proxy, model, entries](const QModelIndex& proxyIndex) -> int {
        const QModelIndex src = proxy->mapToSource(proxyIndex.siblingAtColumn(ColName));
        const QStandardItem* it = model->itemFromIndex(src);
        const int i = it ? it->data(kIndexRole).toInt() : -1;
        return (i >= 0 && i < entries->size()) ? entries->at(i).pid : 0;
    };
    const auto entryAt = [proxy, model, entries](const QModelIndex& proxyIndex) -> const ProcessEntry* {
        if (!proxyIndex.isValid())
            return nullptr;
        const QStandardItem* it = model->itemFromIndex(proxy->mapToSource(proxyIndex.siblingAtColumn(ColName)));
        const int i = it ? it->data(kIndexRole).toInt() : -1;
        return (i >= 0 && i < entries->size()) ? &entries->at(i) : nullptr;
    };
    const auto rebuild = [model, entries, itemByPid, view, mode, collapsed, proxy] {
        const bool tree = mode->currentIndex() == 1;
        model->removeRows(0, model->rowCount());
        itemByPid->clear();
        QList<QList<QStandardItem*>> rows;
        rows.reserve(entries->size());
        QHash<int, int> indexOfPid;
        for (int i = 0; i < entries->size(); ++i) {
            const ProcessEntry& e = entries->at(i);
            const procview::Hint h = procview::hint(e);
            auto* name = new QStandardItem(e.name.isEmpty() ? u("(未知)") : e.name);
            name->setData(i, kIndexRole);
            name->setData(e.name.toLower(), kSortRole);
            name->setData(!e.originLabel().isEmpty() ? e.originLabel() : evtfmt::nativePath(e.imagePath), kSubRole);
            name->setData(toneOf(e), kToneRole);
            name->setData(evtfmt::originGlyph(e.originKind), kGlyphRole);
            name->setData(e.fileDescription, kDescRole);
            name->setData(needsAttention(e), kWatchRole);
            name->setToolTip(evtfmt::nativePath(e.imagePath));
            auto* pid = new QStandardItem(QString::number(e.pid));
            pid->setData(e.pid, kSortRole);
            auto* mem = new QStandardItem(e.workingSetBytes > 0 ? fmt::bytes(e.workingSetBytes) : u("—"));
            mem->setData(qlonglong(e.workingSetBytes), kSortRole);
            auto* sig = new QStandardItem(procview::signatureText(e));
            sig->setForeground(procview::signatureColor(e));
            sig->setData(e.signatureMismatch ? 2 : (e.isSigned ? 0 : 1), kSortRole);
            auto* hint = new QStandardItem(h.text);
            hint->setForeground(h.color);
            hint->setData(h.rank, kSortRole);
            if (!e.riskReasons.isEmpty())
                hint->setToolTip(e.riskReasons.join(QLatin1Char('\n')));
            const QList<QStandardItem*> row{name, pid, mem, sig, hint};
            for (QStandardItem* it : row)
                it->setEditable(false);
            rows.append(row);
            itemByPid->insert(e.pid, name);
            indexOfPid.insert(e.pid, i);
        }
        QList<int> parentOf(entries->size(), -1);
        if (tree) {
            for (int i = 0; i < entries->size(); ++i) {
                const ProcessEntry& e = entries->at(i);
                const int p = indexOfPid.value(e.parentPid, -1);
                if (p < 0 || p == i || e.parentPid == 0)
                    continue;
                const ProcessEntry& pe = entries->at(p);
                if (pe.startTimeUtc.isValid() && e.startTimeUtc.isValid() && pe.startTimeUtc > e.startTimeUtc)
                    continue;
                parentOf[i] = p;
            }
            for (int i = 0; i < entries->size(); ++i) {
                int j = parentOf[i];
                for (int depth = 0; j >= 0 && depth < 64; ++depth) {
                    if (j == i) {
                        parentOf[i] = -1;
                        break;
                    }
                    j = parentOf[j];
                }
            }
        }
        for (int i = 0; i < rows.size(); ++i) {
            if (parentOf[i] >= 0)
                rows[parentOf[i]].first()->appendRow(rows[i]);
            else
                model->appendRow(rows[i]);
        }
        view->setRootIsDecorated(tree);
        view->setIndentation(tree ? 18 : 0);
        if (tree) {
            view->expandAll();
            for (int pid : std::as_const(*collapsed))
                if (QStandardItem* it = itemByPid->value(pid, nullptr))
                    view->collapse(proxy->mapFromSource(it->index()));
        }
    };

    const auto reload = [ipc, loading] {
        if (!ipc->isConnected())
            return;
        *loading = true;
        ipc->requestProcesses();
    };
    const auto refreshCounts = [shell, seg, proxy, entries, ipc, loading, reload] {
        int n[4] = {0, 0, 0, 0};
        int shown = 0;
        for (const ProcessEntry& e : std::as_const(*entries)) {
            ++n[SegAll];
            if (needsAttention(e)) ++n[SegWatch];
            if (!e.isSigned) ++n[SegUnsigned];
            if (hosted(e)) ++n[SegHosted];
            if (proxy->matches(e)) ++shown;
        }
        for (int i = 0; i < 4; ++i)
            seg->setCount(i, n[i]);
        shell->setMatch(shown, int(entries->size()));
        EmptyState* es = shell->emptyState();
        if (entries->isEmpty()) {
            if (!ipc->isConnected()) {
                es->setContent(QStringLiteral("server"), theme::textMuted(), u("未连接后台服务"),
                               u("界面还没有与后台服务建立连接,暂时读不到在跑的进程。服务恢复后会自动刷新。"));
                es->setAction(QString(), {});
            } else if (*loading) {
                es->setContent(QStringLiteral("refresh"), shell->identity(), u("正在读取进程快照…"), QString());
                es->setAction(QString(), {});
            } else {
                es->setContent(QStringLiteral("target"), shell->identity(), u("没有读到进程"),
                               u("服务返回了空的进程快照。"));
                es->setAction(u("重新读取"), reload, "primary");
            }
            shell->setEmptyVisible(true);
        } else if (shown == 0) {
            es->setContent(QStringLiteral("search"), theme::textMuted(), u("没有匹配的进程"),
                           u("当前的筛选或搜索条件下没有进程。"));
            es->setAction(u("清除筛选"), [shell, seg] {
                shell->searchBox()->clear();
                seg->setCurrentIndex(SegAll);
            });
            shell->setEmptyVisible(true);
        } else {
            shell->setEmptyVisible(false);
        }
    };

    auto shownSig = std::make_shared<QString>();
    const auto showInspector = [shell, ipc, shownSig](const ProcessEntry& e) {
        Inspector* in = shell->inspector();
        in->setUpdatesEnabled(false);
        in->clear();
        procview::fill(in, e, ipc, true);
        in->setUpdatesEnabled(true);
        *shownSig = signatureOf(e);
        shell->setInspectorOpen(true);
    };
    QObject::connect(view->selectionModel(), &QItemSelectionModel::currentChanged, shell,
                     [shell, entryAt, showInspector](const QModelIndex& cur) {
        if (!shell->isInspectorOpen())
            return;
        if (const ProcessEntry* e = entryAt(cur))
            showInspector(*e);
    });
    QObject::connect(view, &QAbstractItemView::clicked, shell, [shell, entryAt, showInspector](const QModelIndex& i) {
        if (shell->isInspectorOpen())
            return;
        if (const ProcessEntry* e = entryAt(i))
            showInspector(*e);
    });
    QObject::connect(view, &QAbstractItemView::activated, shell, [shell, entryAt, ipc](const QModelIndex& i) {
        if (const ProcessEntry* e = entryAt(i))
            procview::openDetail(shell, *e, ipc);
    });
    QObject::connect(view, &QWidget::customContextMenuRequested, shell, [shell, view, entryAt, ipc](const QPoint& pos) {
        const QModelIndex i = view->indexAt(pos);
        const ProcessEntry* pe = entryAt(i);
        if (!pe)
            return;
        view->selectionModel()->setCurrentIndex(i, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
        const ProcessEntry e = *pe;
        const QString locked = procview::lockReason(e);
        QMenu menu(shell);
        menu.setToolTipsVisible(true);
        QAction* kill = pagekit::menuAction(&menu, QStringLiteral("close"), u("结束进程"), shell,
                                            [shell, ipc, e] { procview::run(shell, ipc, e, Kind::Terminate); });
        QAction* tree = pagekit::menuAction(&menu, QStringLiteral("tree"), u("结束进程树"), shell,
                                            [shell, ipc, e] { procview::run(shell, ipc, e, Kind::TerminateTree); });
        if (!locked.isEmpty())
            for (QAction* a : {kill, tree}) {
                a->setEnabled(false);
                a->setToolTip(locked);
            }
        menu.addSeparator();
        procview::fillMenu(&menu, shell, e, ipc, true);
        menu.exec(view->viewport()->mapToGlobal(pos));
    });
    QObject::connect(view, &QTreeView::collapsed, shell,
                     [collapsed, pidAt](const QModelIndex& i) { collapsed->insert(pidAt(i)); });
    QObject::connect(view, &QTreeView::expanded, shell,
                     [collapsed, pidAt](const QModelIndex& i) { collapsed->remove(pidAt(i)); });

    QObject::connect(shell->searchBox(), &QLineEdit::textChanged, shell, [proxy, refreshCounts](const QString& t) {
        proxy->setSearch(t);
        refreshCounts();
    });
    QObject::connect(seg, &Segmented::currentChanged, shell, [proxy, refreshCounts] {
        proxy->refresh();
        refreshCounts();
    });

    const auto applySnapshot = [shell, view, entries, rebuild, refreshCounts, itemByPid, proxy, entryAt, pidAt, shownSig,
                                showInspector](const Entries& list) {
        const int keepPid = pidAt(view->currentIndex());
        const int scroll = view->verticalScrollBar()->value();
        *entries = list;
        rebuild();
        refreshCounts();
        if (keepPid > 0) {
            if (QStandardItem* it = itemByPid->value(keepPid, nullptr)) {
                const QModelIndex pi = proxy->mapFromSource(it->index());
                if (pi.isValid()) {
                    view->selectionModel()->blockSignals(true);
                    view->selectionModel()->setCurrentIndex(
                        pi, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
                    view->selectionModel()->blockSignals(false);
                    view->viewport()->update();
                    if (shell->isInspectorOpen())
                        if (const ProcessEntry* e = entryAt(pi); e && signatureOf(*e) != *shownSig)
                            showInspector(*e);
                }
            } else if (shell->isInspectorOpen()) {
                shell->setInspectorOpen(false);
                ui::notify(shell, ui::Tone::Info, u("PID %1 已经退出,详情已关闭。").arg(keepPid));
            }
        }
        QTimer::singleShot(0, view, [view, scroll] { view->verticalScrollBar()->setValue(scroll); });
    };
    QObject::connect(ipc, &IpcClient::processListReceived, shell,
                     [loading, applySnapshot](const bulwark::ipc::ProcessListResponsePayload& p) {
        *loading = false;
        applySnapshot(p.processes);
    });
    QObject::connect(mode, &Segmented::currentChanged, shell, [mode, applySnapshot, entries] {
        pagekit::remember(QStringLiteral("processes"), QStringLiteral("view"),
                          mode->currentData().toString());
        const Entries copy = *entries;
        applySnapshot(copy);
    });

    // 处置结果一律给回执:成功要说明做了什么,失败必须说明为什么没做成
    //(关键进程 / 自我保护 / 权限不足 / 进程已退出),绝不让用户以为「点了就生效了」。
    QObject::connect(ipc, &IpcClient::processActionResult, shell,
                     [shell, ipc, reload](const bulwark::ipc::ProcessActionResultPayload& r) {
        if (r.kind == Kind::ComputeHash)
            return;
        ui::notify(shell, r.success ? ui::Tone::Success : ui::Tone::Danger,
                   r.message.isEmpty() ? (r.success ? u("操作已完成。") : u("操作未成功,服务没有给出原因。")) : r.message);
        if (ipc->isConnected())
            reload();
    });

    QHBoxLayout* actions = pagekit::headerActions(shell);
    auto* autoSwitch = new ToggleSwitch(false);
    autoSwitch->setAccessibleName(u("每 5 秒自动刷新"));
    autoSwitch->setToolTip(u("一次快照要枚举几百个进程并验签,默认不自动刷新;需要盯着看时再打开。"));
    actions->addWidget(autoSwitch);
    actions->addWidget(ui::label(u("自动刷新"), "secondary"));
    actions->addSpacing(6);
    QObject::connect(pagekit::headerButton(actions, QStringLiteral("refresh"), u("刷新")), &QPushButton::clicked, shell,
                     [reload, refreshCounts] {
                         reload();
                         refreshCounts();
                     });
    auto* timer = new QTimer(shell);
    timer->setInterval(5000);
    QObject::connect(timer, &QTimer::timeout, shell, reload);
    QObject::connect(autoSwitch, &QAbstractButton::toggled, shell, [timer](bool on) {
        if (on)
            timer->start();
        else
            timer->stop();
    });

    QObject::connect(ipc, &IpcClient::connectionChanged, shell, [shell, reload, refreshCounts](bool c) {
        refreshCounts();
        if (c)
            QTimer::singleShot(1500, shell, [reload, refreshCounts] {
                reload();
                refreshCounts();
            });
    });
    if (ipc->isConnected())
        QTimer::singleShot(1500, shell, [reload, refreshCounts] {
            reload();
            refreshCounts();
        });
    nav::onArrive(shell, QString::fromLatin1(nav::Processes), [shell, reload](const QVariantMap& args) {
        const int pid = args.value(QStringLiteral("pid")).toInt();
        if (pid <= 0)
            return;
        shell->searchBox()->setText(QString::number(pid));
        reload();
    });
    refreshCounts();
    return shell;
}
