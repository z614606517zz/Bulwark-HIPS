#include "pages/TablePages.h"
#include "pages/PageKit.h"
#include "dialogs/EventFormat.h"
#include "design/Banner.h"
#include "design/Confirm.h"
#include "design/Format.h"
#include "design/Identity.h"
#include "design/Inspector.h"
#include "design/ListShell.h"
#include "design/Skin.h"
#include "design/TitanKit.h"
#include "ipc/IpcClient.h"
#include "Nav.h"

#include <QDesktopServices>
#include <QFileInfo>
#include <QHash>
#include <QMenu>
#include <QPainter>
#include <QPushButton>
#include <QTimer>
#include <QUrl>

#include <algorithm>
#include <memory>

using evtfmt::u;
using bulwark::ipc::QuarantineItemPayload;

namespace {

// 金刚:紫色只给「敌方」—— 已经移进隔离区的恶意文件用紫色;原路径仍有文件的照旧用红色,它还可能运行。
QColor sealedColor() { return theme::titan() ? theme::purple() : theme::warning(); }

RecordView itemView(const QuarantineItemPayload& it)
{
    RecordView v;
    v.icon = it.originalRemoved ? QStringLiteral("lock") : QStringLiteral("alert-triangle");
    v.iconColor = it.originalRemoved ? sealedColor() : theme::danger();
    if (theme::titan())
        v.accent = v.iconColor;
    v.title = it.fileName.isEmpty() ? QFileInfo(it.originalPath).fileName() : it.fileName;
    v.subtitle = evtfmt::nativePath(it.originalPath);
    v.subtitleMono = true;
    if (!it.originalRemoved) {
        v.chips << (it.deleteOnRebootScheduled
                        ? u("原路径仍有文件 · 已计划重启删除")
                        : u("原路径仍有文件 · 删除与重启调度均失败"));
    }
    if (!it.reason.isEmpty())
        v.chips << it.reason;
    v.chips << fmt::bytes(it.size);
    v.meta = fmt::bytes(it.size);
    v.time = it.quarantinedUtc;
    v.tooltip = evtfmt::nativePath(it.originalPath);
    v.haystack = QStringList{it.fileName, it.originalPath, it.reason, it.sha256}.join(QLatin1Char(' '));
    v.key = it.id.toString(QUuid::WithoutBraces);
    return v;
}

// 金刚:隔离区顶上的一排静滞舱,一格一个文件。紫 = 已移出原位置;红 = 原路径仍有文件;暗 = 空舱。
class StasisPods final : public QWidget
{
public:
    StasisPods()
    {
        setFixedSize(kPods * (kPodW + kGap) - kGap + 34, 40);
        setAttribute(Qt::WA_TransparentForMouseEvents);
    }

    void setCounts(int sealed, int partial)
    {
        m_sealed = sealed;
        m_partial = partial;
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        const theme::Palette& P = theme::pal();
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setRenderHint(QPainter::TextAntialiasing, true);
        const int total = m_sealed + m_partial;
        for (int i = 0; i < kPods; ++i) {
            const QRectF r(1.0 + i * (kPodW + kGap), 3.0, kPodW, height() - 6.0);
            const bool sealed = i < m_sealed;
            const bool partial = !sealed && i < total;
            const QColor c = sealed ? P.purple : partial ? P.danger : QColor();
            QPainterPath pod;
            pod.addRoundedRect(r, 5.0, 5.0);
            p.fillPath(pod, c.isValid() ? theme::blend(c, P.surface, 0.55) : P.surfaceAlt);
            if (c.isValid()) {
                QPainterPath core;
                core.addRoundedRect(r.adjusted(3.5, 5.0, -3.5, -5.0), 2.5, 2.5);
                p.fillPath(core, c);
                p.fillRect(QRectF(r.left() + 4.5, r.top() + 7.0, 1.5, r.height() * 0.4), QColor(255, 255, 255, 120));
            }
            p.strokePath(pod, QPen(c.isValid() ? P.ink : P.borderStrong, c.isValid() ? 2.0 : 1.5));
        }
        if (total > kPods) {
            p.setFont(titankit::numFont(13, QFont::Bold));
            p.setPen(P.purple);
            p.drawText(QRectF(kPods * (kPodW + kGap), 0.0, 34.0, height()), Qt::AlignCenter,
                       QStringLiteral("+%1").arg(total - kPods));
        }
    }

private:
    static constexpr int kPods = 16;
    static constexpr int kPodW = 15;
    static constexpr int kGap = 5;
    int m_sealed = 0;
    int m_partial = 0;
};

enum class Op { Restore, Delete };

struct Batch {
    Op op = Op::Restore;
    QHash<QUuid, QString> waiting;
    QStringList done;
    QStringList failed;
};

}

QWidget* pages::quarantine(IpcClient* ipc)
{
    auto* page = new RecordBrowser;
    page->setIdentity(identity::page(nav::Quarantine));
    page->setMultiSelect(true);
    page->searchBox()->setPlaceholderText(u("搜索文件名 / 原路径 / 原因 / SHA-256…"));
    page->setNoDataContent(QStringLiteral("lock"), u("隔离区是空的"),
                           u("被判定为恶意并移出原位置的文件会出现在这里,可以还原或永久删除。"));
    auto store = std::make_shared<RecordStore<QuarantineItemPayload>>(page->model(), &itemView);
    auto batch = std::make_shared<Batch>();
    auto batchSeq = std::make_shared<int>(0);

    StasisPods* pods = nullptr;
    QLabel* bayLine = nullptr;
    if (theme::titan()) {
        auto* bay = ui::card();
        bay->setGlow(theme::purple(), QPointF(0.0, 0.5), 0.7, 0.16);
        auto* bh = new QHBoxLayout(bay);
        bh->setContentsMargins(18, 12, 20, 12);
        bh->setSpacing(18);
        pods = new StasisPods;
        bh->addWidget(pods, 0, Qt::AlignVCenter);
        auto* col = new QVBoxLayout;
        col->setSpacing(3);
        bayLine = new QLabel;
        bayLine->setTextFormat(Qt::RichText);
        col->addWidget(bayLine);
        auto* sub = ui::label(u("被判定为恶意并移出原位置的文件会出现在这里,可以还原或永久删除。"), "muted");
        sub->setWordWrap(true);
        col->addWidget(sub);
        bh->addLayout(col, 1);
        bh->addWidget(titankit::labTag(QStringLiteral("STASIS")), 0, Qt::AlignVCenter);
        page->addTop(bay);
    }
    const auto syncBay = [pods, bayLine](const QList<QuarantineItemPayload>& items) {
        if (!pods)
            return;
        int sealed = 0;
        qint64 bytes = 0;
        for (const QuarantineItemPayload& it : items) {
            sealed += it.originalRemoved ? 1 : 0;
            bytes += it.size;
        }
        const int partial = int(items.size()) - sealed;
        pods->setCounts(sealed, partial);
        QString line = items.isEmpty()
            ? u("<span style=\"font-weight:700;\">静滞舱是空的</span>")
            : u("<span style=\"font-size:15pt; font-weight:800; color:%1;\">%2</span>"
                "<span style=\"font-weight:700;\"> 个文件在静滞舱里</span>"
                "<span style=\"color:%3;\"> · 共占用 %4</span>")
                  .arg(theme::purple().name())
                  .arg(items.size())
                  .arg(theme::textMuted().name(), fmt::bytes(bytes));
        if (partial > 0)
            line += u("<span style=\"color:%1;\"> · %2 个原路径仍有文件</span>").arg(theme::danger().name()).arg(partial);
        bayLine->setText(line);
    };
    syncBay({});

    const auto finish = [page, batch] {
        if (batch->done.isEmpty() && batch->failed.isEmpty() && batch->waiting.isEmpty())
            return;
        const QString verb = batch->op == Op::Restore ? u("还原") : u("永久删除");
        QStringList bad = batch->failed;
        for (const QString& name : std::as_const(batch->waiting))
            bad << u("%1:没有收到服务回执").arg(name);
        QString text;
        if (bad.isEmpty())
            text = batch->done.size() == 1 ? u("已%1 %2。").arg(verb, batch->done.first())
                                           : u("已%1 %2 个文件。").arg(verb).arg(batch->done.size());
        else if (batch->done.isEmpty())
            text = u("未能%1:%2").arg(verb, bad.join(u(";")));
        else
            text = u("已%1 %2 个;%3 个未能%1:%4").arg(verb).arg(batch->done.size()).arg(bad.size()).arg(bad.join(u(";")));
        Banner* b = ui::notify(page, bad.isEmpty() ? ui::Tone::Success : ui::Tone::Danger, text);
        if (b && bad.isEmpty() && batch->op == Op::Restore)
            b->setTimeout(6000);
        *batch = Batch{};
    };

    const auto runOp = [page, ipc, store, batch, batchSeq, finish](Op op, const QList<int>& rows) {
        QList<QuarantineItemPayload> items;
        for (int r : rows)
            if (const QuarantineItemPayload* it = store->itemAt(r))
                items << *it;
        if (items.isEmpty())
            return;
        if (!ipc->isConnected()) {
            ui::notify(page, ui::Tone::Danger, u("未连接后台服务,无法操作隔离区。"));
            return;
        }
        QStringList names;
        bool hasPartial = false;
        for (const QuarantineItemPayload& it : items) {
            names << (it.fileName.isEmpty() ? evtfmt::nativePath(it.originalPath) : it.fileName);
            hasPartial = hasPartial || !it.originalRemoved;
        }
        ui::ConfirmSpec c;
        if (op == Op::Restore) {
            c.risk = ui::Risk::Caution;
            c.title = items.size() == 1 ? u("还原文件") : u("还原 %1 个文件").arg(items.size());
            c.summary = hasPartial
                ? u("隔离副本会被还原;原路径已有文件时会改用 .restored 名称,不会覆盖。")
                : u("文件会被放回隔离前的原路径。");
            c.consequences << u("如果它确实是恶意程序,还原后可能再次运行");
            c.confirmText = u("还原");
        } else {
            c.risk = ui::Risk::Danger;
            c.title = items.size() == 1 ? u("永久删除文件") : u("永久删除 %1 个文件").arg(items.size());
            c.summary = u("文件会从隔离区里彻底删除。");
            c.consequences << u("删除后无法还原,也无法再用于取证分析");
            if (hasPartial)
                c.consequences << u("部分条目的原路径仍有文件;本操作只删除金库副本,不会删除原路径文件");
            c.confirmText = u("永久删除");
        }
        c.subjectLabel = items.size() == 1 ? u("文件") : u("文件(%1 个)").arg(items.size());
        c.subject = items.size() == 1 ? evtfmt::nativePath(items.first().originalPath)
                                      : names.mid(0, 8).join(QLatin1Char('\n'))
                                            + (names.size() > 8 ? u("\n… 另有 %1 个").arg(names.size() - 8) : QString());
        if (!ui::confirm(page, c))
            return;
        finish();
        batch->op = op;
        for (int i = 0; i < items.size(); ++i)
            batch->waiting.insert(items[i].id, names[i]);
        const int seq = ++*batchSeq;
        QTimer::singleShot(10000, page, [batchSeq, seq, finish] {
            if (*batchSeq == seq)
                finish();
        });
        for (const QuarantineItemPayload& it : items) {
            if (op == Op::Restore)
                ipc->quarantineRestore(it.id);
            else
                ipc->quarantineDelete(it.id);
        }
        page->setCheckMode(false);
        page->clearSelection();
    };

    QObject::connect(ipc, &IpcClient::quarantineActionResult, page,
                     [batch, finish](const bulwark::ipc::QuarantineActionResultPayload& r) {
        const auto it = batch->waiting.constFind(r.id);
        if (it == batch->waiting.constEnd())
            return;
        const QString name = it.value();
        batch->waiting.remove(r.id);
        if (r.success)
            batch->done << name;
        else
            batch->failed << u("%1:%2").arg(name, r.message.isEmpty() ? u("服务没有给出原因") : r.message);
        if (batch->waiting.isEmpty())
            finish();
    });

    page->batchBar()->addAction(QStringLiteral("undo"), u("还原"), "ghost",
                                [page, runOp] { runOp(Op::Restore, page->selectedSourceRows()); });
    page->batchBar()->addAction(QStringLiteral("trash"), u("永久删除"), "danger",
                                [page, runOp] { runOp(Op::Delete, page->selectedSourceRows()); });

    page->setInspectorBuilder([store, runOp](Inspector* in, int row) {
        const QuarantineItemPayload* it = store->itemAt(row);
        if (!it)
            return;
        if (theme::titan())
            in->setNote(u("如果它确实是恶意程序,还原后可能再次运行。"), theme::warning());
        in->setHeader(it->originalRemoved ? QStringLiteral("lock") : QStringLiteral("alert-triangle"),
                      it->originalRemoved ? sealedColor() : theme::danger(),
                      it->fileName.isEmpty() ? u("隔离文件") : it->fileName,
                      fmt::bytes(it->size) + u(" · 隔离于 ") + fmt::relativeTime(it->quarantinedUtc));
        in->addLead(it->originalRemoved
                        ? u("已从原位置移入隔离区。还原会把它放回原路径;永久删除不可撤销。")
                        : (it->deleteOnRebootScheduled
                               ? u("仅完成金库副本:原路径仍有文件,已计划重启删除。还原时不会覆盖原路径。")
                               : u("仅完成金库副本:原路径仍有文件,且重启删除调度失败。该文件当前仍可能运行。")));
        const Inspector::FieldFlags monoCopy = Inspector::Mono | Inspector::Copy;
        QVBoxLayout* s = in->addSection(u("文件"));
        in->addField(s, u("原始路径"), evtfmt::nativePath(it->originalPath), monoCopy);
        in->addField(s, u("隔离原因"), it->reason);
        in->addField(s, u("大小"), fmt::bytes(it->size));
        in->addField(s, QStringLiteral("SHA-256"), it->sha256, monoCopy);
        in->addField(s, u("隔离时间"), fmt::absoluteTime(it->quarantinedUtc));
        if (it->actorPid > 0)
            in->addField(s, u("当时的进程"), QStringLiteral("PID %1").arg(it->actorPid), Inspector::Mono);

        in->addAction(QStringLiteral("undo"), u("还原"), "ghost", [runOp, row] { runOp(Op::Restore, {row}); });
        in->addAction(QStringLiteral("trash"), u("永久删除"), "danger", [runOp, row] { runOp(Op::Delete, {row}); });
        auto* menu = new QMenu;
        const QString sha = it->sha256;
        const QString path = evtfmt::nativePath(it->originalPath);
        if (!sha.isEmpty()) {
            pagekit::menuAction(menu, QStringLiteral("copy"), u("复制 SHA-256"), in, [sha] {
                if (QClipboard* cb = QGuiApplication::clipboard())
                    cb->setText(sha);
            });
        }
        pagekit::menuAction(menu, QStringLiteral("folder"), u("打开原位置所在文件夹"), in, [path] {
            QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(path).absolutePath()));
        });
        in->addMenu(menu);
    });
    page->setContextMenuBuilder([page, runOp](QMenu* m, const QList<int>& rows) {
        if (rows.isEmpty())
            return;
        const QString n = rows.size() == 1 ? QString() : u(" %1 个文件").arg(rows.size());
        pagekit::menuAction(m, QStringLiteral("undo"), u("还原") + n, page, [runOp, rows] { runOp(Op::Restore, rows); });
        pagekit::menuAction(m, QStringLiteral("trash"), u("永久删除") + n + u("…"), page,
                            [runOp, rows] { runOp(Op::Delete, rows); });
    });

    QHBoxLayout* actions = pagekit::headerActions(page);
    auto* total = ui::label(QString(), "muted");
    actions->addWidget(total);
    auto* pick = pagekit::headerButton(actions, QStringLiteral("check-square"), u("批量选择"));
    pick->setCheckable(true);
    pick->setEnabled(false);
    const auto syncPick = [pick](bool on) {
        pick->setText(on ? u("退出批量") : u("批量选择"));
        pick->setIcon(AppIcon::icon(on ? QStringLiteral("close") : QStringLiteral("check-square"),
                                    on ? theme::accentSoft() : theme::textSecondary(), 16));
        pick->setToolTip(on ? u("退出批量选择,清除已勾选的文件")
                            : u("逐个勾选文件,再一起还原或永久删除(也可以按住 Ctrl / Shift 点选)"));
    };
    syncPick(false);
    QObject::connect(pick, &QPushButton::toggled, page, [page](bool on) { page->setCheckMode(on); });
    QObject::connect(page, &RecordBrowser::checkModeChanged, pick, [pick, syncPick](bool on) {
        const QSignalBlocker quiet(pick);
        pick->setChecked(on);
        syncPick(on);
    });
    QMenu* more = pagekit::headerMenu(actions);
    const auto reload = [page, ipc] {
        if (!ipc->isConnected())
            return;
        page->setLoading(true);
        ipc->requestQuarantine();
    };
    pagekit::menuAction(more, QStringLiteral("refresh"), u("刷新列表"), page, reload);

    QObject::connect(ipc, &IpcClient::quarantineReceived, page,
                     [page, store, total, pick, syncBay](const QList<QuarantineItemPayload>& items) {
        syncBay(items);
        QList<QuarantineItemPayload> list = items;
        std::stable_sort(list.begin(), list.end(), [](const QuarantineItemPayload& a, const QuarantineItemPayload& b) {
            return a.quarantinedUtc > b.quarantinedUtc;
        });
        store->reset(list);
        page->setLoading(false);
        if (list.isEmpty())
            page->setCheckMode(false);
        pick->setEnabled(!list.isEmpty());
        qint64 bytes = 0;
        for (const QuarantineItemPayload& it : items)
            bytes += it.size;
        total->setText(items.isEmpty() ? QString() : u("共占用 %1").arg(fmt::bytes(bytes)));
    });
    pagekit::onConnected(page, ipc, page, 0, reload);
    return page;
}
