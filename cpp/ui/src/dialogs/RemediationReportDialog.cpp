#include "dialogs/RemediationReportDialog.h"
#include "Nav.h"
#include "ipc/IpcClient.h"
#include "design/Banner.h"
#include "design/Components.h"
#include "design/Confirm.h"
#include "design/CountTile.h"
#include "design/CountdownBar.h"
#include "design/FitScroll.h"
#include "design/Icons.h"
#include "design/Theme.h"
#include "widgets/WrapLabel.h"

#include <QClipboard>
#include <QFileInfo>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollBar>
#include <QVBoxLayout>

#include <utility>

using bulwark::ipc::RemediationReportPayload;
using bulwark::ipc::RemediationSkippedItem;

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

constexpr int kCardW = 600;
constexpr int kAutoCloseMs = 30000;

QWidget* pathRow(const QString& path, const QString& note = QString())
{
    auto* w = new QWidget;
    auto* v = new QVBoxLayout(w);
    v->setContentsMargins(18, 0, 0, 0);
    v->setSpacing(1);
    auto* p = new WrapLabel(path);
    p->setProperty("role", "mono");
    v->addWidget(p);
    if (!note.isEmpty()) {
        auto* n = ui::label(note, "muted");
        n->setWordWrap(true);
        v->addWidget(n);
    }
    return w;
}

}

RemediationReportDialog::RemediationReportDialog(const RemediationReportPayload& report,
                                                 IpcClient* ipc, QWidget* parent)
    : Sheet(parent), m_report(report), m_ipc(ipc)
{
    setAttribute(Qt::WA_DeleteOnClose);
    setModal(false); // informational — never blocks the user's work
    setSheetWidth(kCardW);

    const int quarantined = int(report.quarantinedFiles.size());
    const int removed = int(report.removedRegistryValues.size());
    const int failed = int(report.skipped.size());
    const QString when = report.timestampUtc.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    QString actorName = QFileInfo(report.actorPath).fileName();
    if (actorName.isEmpty())
        actorName = report.actorPath.isEmpty() ? u("未知程序") : report.actorPath;

    const QColor tone = failed > 0 ? theme::warning() : theme::success();
    setHeader(QStringLiteral("trash"), tone, u("恶意足迹清理报告"),
              actorName + (report.actorPid > 0 ? u(" · PID %1").arg(report.actorPid) : QString()) + u(" · ") + when);

    QVBoxLayout* body = this->body();
    body->setSpacing(12);

    if (!report.actorPath.isEmpty()) {
        auto* p = new WrapLabel(report.actorPath);
        p->setProperty("role", "mono");
        p->setAccessibleName(u("主体路径"));
        body->addWidget(p);
    }
    if (!report.reason.isEmpty()) {
        auto* r = ui::label(u("判定:") + report.reason, "secondary");
        r->setWordWrap(true);
        r->setTextInteractionFlags(Qt::TextSelectableByMouse);
        body->addWidget(r);
    }

    auto* tiles = new QHBoxLayout;
    tiles->setSpacing(10);
    struct TileSpec { const char* key; QString label; int count; QColor color; };
    const TileSpec specs[] = {
        {"quarantined", u("已隔离"), quarantined, theme::success()},
        {"removed", u("已移除自启动"), removed, theme::info()},
        {"skipped", u("未能清理"), failed, theme::warning()},
    };
    for (const TileSpec& s : specs) {
        auto* t = new CountTile(s.label, s.count, s.color);
        const QString key = QString::fromLatin1(s.key);
        connect(t, &QAbstractButton::clicked, this, [this, key] { scrollToGroup(key); });
        tiles->addWidget(t);
    }
    body->addLayout(tiles);

    m_scroll = new FitScrollArea(Sheet::screenHeightFor(parent, 0.40), kCardW - 48);
    auto* content = new QWidget;
    auto* list = new QVBoxLayout(content);
    list->setContentsMargins(0, 0, 6, 0);
    list->setSpacing(6);
    list->setAlignment(Qt::AlignTop);

    if (quarantined > 0) {
        group(list, QStringLiteral("quarantined"), u("已隔离(可在隔离区还原)"), theme::success(), quarantined);
        if (report.actorQuarantined)
            list->addWidget(pathRow(report.actorPath, u("主体载荷")));
        for (const QString& f : report.quarantinedFiles) {
            if (report.actorQuarantined && f.compare(report.actorPath, Qt::CaseInsensitive) == 0)
                continue;
            list->addWidget(pathRow(f));
        }
    }
    if (removed > 0) {
        group(list, QStringLiteral("removed"), u("已移除自启动 / 注册表项"), theme::info(), removed);
        for (const QString& r : report.removedRegistryValues)
            list->addWidget(pathRow(r));
    }
    if (failed > 0) {
        group(list, QStringLiteral("skipped"), u("未能自动清理"), theme::warning(), failed);
        for (const RemediationSkippedItem& s : report.skipped) {
            auto* rowW = new QWidget;
            auto* h = new QHBoxLayout(rowW);
            h->setContentsMargins(0, 0, 0, 0);
            h->setSpacing(10);
            h->addWidget(pathRow(s.target, s.reason), 1);
            if (s.forceable) {
                auto* force = ui::button(u("强制处理…"), "danger", QStringLiteral("alert"), true);
                force->setToolTip(u("结束占用进程、绕过签名护栏、夺取所有权后强删;需二次确认"));
                connect(force, &QPushButton::clicked, this, [this, force, s] { forceHandle(s, force); });
                h->addWidget(force, 0, Qt::AlignTop);
            }
            if (s.isFile) {
                auto* retry = ui::button(u("重试隔离"), "ghost", QStringLiteral("refresh"), true);
                const QString target = s.target;
                connect(retry, &QPushButton::clicked, this, [this, retry, target] {
                    if (!m_ipc || !m_ipc->isConnected()) {
                        banners()->post(ui::Tone::Danger, u("未连接后台服务,无法重试隔离。"));
                        return;
                    }
                    m_ipc->manualQuarantine(target);
                    retry->setEnabled(false);
                    retry->setText(u("已请求"));
                    setPinned(true);
                });
                h->addWidget(retry, 0, Qt::AlignTop);
                m_retry << qMakePair(target, retry);
            }
            list->addWidget(rowW);
        }
    }

    if (list->count() == 0)
        list->addWidget(ui::label(u("本次没有需要列出的清理项。"), "muted"));

    m_scroll->setContent(content);
    body->addWidget(m_scroll, 1);

    m_autoClose = new CountdownBar;
    m_autoClose->setColor(theme::textMuted());
    m_autoClose->setFormatter([](int s) { return u("%1 秒后自动关闭").arg(s); });
    m_autoClose->setToolTip(u("鼠标停在报告上时暂停"));
    m_autoClose->setHoverPause(card());
    connect(m_autoClose, &CountdownBar::finished, this, &QDialog::accept);
    m_pin = ui::button(QString(), "ghost", QStringLiteral("pin"), true);
    m_pin->setToolTip(u("固定:保持报告打开,不自动关闭"));
    m_pin->setAccessibleName(u("固定报告"));
    m_pin->setAutoDefault(false);
    connect(m_pin, &QPushButton::clicked, this, [this] { setPinned(true); });
    if (failed == 0) {
        addFooterLeft(m_autoClose);
        addFooterLeft(m_pin);
    } else {
        auto* row = new QHBoxLayout;
        row->setSpacing(10);
        row->addWidget(m_autoClose, 1);
        row->addWidget(m_pin, 0, Qt::AlignRight | Qt::AlignVCenter);
        body->addLayout(row);
    }
    m_autoClose->start(kAutoCloseMs);

    auto* copy = ui::button(u("复制报告"), "ghost", QStringLiteral("copy"), true);
    copy->setAutoDefault(false);
    connect(copy, &QPushButton::clicked, this, [this, copy] {
        if (QClipboard* cb = QGuiApplication::clipboard())
            cb->setText(reportText());
        copy->setText(u("已复制"));
    });
    footer()->addWidget(copy);
    auto* openQ = ui::button(u("打开隔离区"), "ghost", QStringLiteral("lock"), true);
    openQ->setAutoDefault(false);
    connect(openQ, &QPushButton::clicked, this, &RemediationReportDialog::openQuarantine);
    footer()->addWidget(openQ);
    if (!m_retry.isEmpty()) {
        auto* all = ui::button(u("全部重试"), "ghost", QStringLiteral("refresh"), true);
        all->setAutoDefault(false);
        connect(all, &QPushButton::clicked, this, &RemediationReportDialog::retryAll);
        footer()->addWidget(all);
    }
    QPushButton* close = addButton(u("关闭"), "primary", [this] { accept(); });
    close->setMinimumWidth(84);

    if (m_ipc)
        connect(m_ipc, &IpcClient::manualQuarantineResult, this,
                [this](const bulwark::ipc::ManualQuarantineResultPayload& r) {
                    const bool forced = m_forcePending.contains(r.requestId);
                    if (forced) {
                        if (QPushButton* b = m_forcePending.take(r.requestId)) {
                            b->setText(r.success ? u("已处理") : u("重新强制处理…"));
                            b->setEnabled(!r.success);
                        }
                    }
                    const QString fallback = r.success ? (forced ? u("已处理") : u("已隔离")) : u("未成功");
                    banners()->post(r.success ? ui::Tone::Success : ui::Tone::Danger,
                                    (forced ? u("强制处理:") : u("重试隔离:"))
                                        + (r.message.isEmpty() ? fallback : r.message));
                    refit();
                });
}

QWidget* RemediationReportDialog::group(QVBoxLayout* into, const QString& key, const QString& title,
                                        const QColor& color, int count)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, into->count() > 0 ? 10 : 0, 0, 2);
    h->setSpacing(8);
    h->addWidget(ui::statusDot(color), 0, Qt::AlignVCenter);
    h->addWidget(ui::coloredText(title, 10, 700, theme::textPrimary()), 0, Qt::AlignVCenter);
    if (count > 0)
        h->addWidget(ui::pill(QString::number(count), color), 0, Qt::AlignVCenter);
    h->addStretch();
    into->addWidget(w);
    m_groups.insert(key, w);
    return w;
}

void RemediationReportDialog::scrollToGroup(const QString& key)
{
    if (QWidget* w = m_groups.value(key))
        m_scroll->ensureWidgetVisible(w, 0, 8);
    if (QWidget* w = m_groups.value(key))
        m_scroll->verticalScrollBar()->setValue(w->y());
}

void RemediationReportDialog::retryAll()
{
    if (!m_ipc || !m_ipc->isConnected()) {
        banners()->post(ui::Tone::Danger, u("未连接后台服务,无法重试隔离。"));
        refit();
        return;
    }
    int n = 0;
    for (const auto& [path, btn] : std::as_const(m_retry)) {
        if (!btn->isEnabled())
            continue;
        m_ipc->manualQuarantine(path);
        btn->setEnabled(false);
        btn->setText(u("已请求"));
        ++n;
    }
    setPinned(true);
    banners()->post(ui::Tone::Info, n > 0 ? u("已请求重试隔离 %1 个文件,结果会逐条显示在这里。").arg(n)
                                          : u("没有待重试的文件。"));
    refit();
}

void RemediationReportDialog::forceHandle(const RemediationSkippedItem& item, QPushButton* button)
{
    if (!m_ipc || !m_ipc->isConnected()) {
        banners()->post(ui::Tone::Danger, u("未连接后台服务,无法强制处理。"));
        refit();
        return;
    }
    setPinned(true); // 用户正在处理它,确认框开着时报告不能自己关掉

    ui::ConfirmSpec s;
    s.risk = ui::Risk::Danger;
    s.subject = item.target;
    if (item.isFile || item.kind == QLatin1String("file")) {
        s.title = u("强制处理文件");
        s.subjectLabel = u("文件");
        s.summary = u("将结束占用该文件的进程,并忽略「带可信签名」「不在落地区」两道保护,把它移入隔离区。");
        s.consequences << u("被结束的进程未保存的数据会丢失(系统关键进程与桌面进程不会被结束)")
                       << u("实在做不出可还原副本时会直接删除,这一步【不可还原】")
                       << u("仍删不掉时会计划在下次重启时删除,并禁止它在重启前再次运行")
                       << u("Windows 系统目录与本产品自身的文件始终不会被处理");
        s.confirmText = u("强制处理");
    } else {
        s.title = u("强制删除持久化项");
        s.subjectLabel = item.kind == QLatin1String("task") ? u("计划任务") : u("注册表项");
        s.summary = u("将夺取该项的所有权并强制删除,随后阻止它被立即重新写回。");
        s.consequences << u("删除后不可还原;若判断有误,对应程序的开机自启 / 服务将失效")
                       << u("只处理 Run / RunOnce / IFEO / 服务 / 非系统计划任务,其它位置会被拒绝");
        s.confirmText = u("强制删除");
    }
    if (!ui::confirm(this, s))
        return;
    if (!m_ipc || !m_ipc->isConnected()) {
        banners()->post(ui::Tone::Danger, u("未连接后台服务,无法强制处理。"));
        refit();
        return;
    }
    const QUuid id = m_ipc->forceHandle(item);
    m_forcePending.insert(id, button);
    if (button) {
        button->setEnabled(false);
        button->setText(u("处理中…"));
    }
}

void RemediationReportDialog::openQuarantine()
{
    if (QWidget* w = parentWidget() ? parentWidget()->window() : nullptr) {
        w->show();
        w->setWindowState((w->windowState() & ~Qt::WindowMinimized) | Qt::WindowActive);
        w->raise();
        w->activateWindow();
    }
    nav::go(nav::Quarantine);
}

QString RemediationReportDialog::reportText() const
{
    const RemediationReportPayload& r = m_report;
    QStringList out;
    out << u("磐垒 · 恶意足迹清理报告");
    out << u("时间:") + r.timestampUtc.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    out << u("主体:") + r.actorPath + (r.actorPid > 0 ? u(" (PID %1)").arg(r.actorPid) : QString());
    if (!r.reason.isEmpty())
        out << u("判定:") + r.reason;
    if (r.actorQuarantined)
        out << u("主体载荷已隔离");
    if (!r.quarantinedFiles.isEmpty())
        out << u("已隔离文件:") << r.quarantinedFiles;
    if (!r.removedRegistryValues.isEmpty())
        out << u("已移除自启动 / 注册表项:") << r.removedRegistryValues;
    if (!r.skipped.isEmpty()) {
        out << u("未能自动清理:");
        for (const RemediationSkippedItem& s : r.skipped)
            out << s.target + u(" —— ") + s.reason;
    }
    return out.join(QLatin1Char('\n'));
}

void RemediationReportDialog::setPinned(bool pinned)
{
    if (pinned == m_pinned)
        return;
    m_pinned = pinned;
    if (!m_autoClose)
        return;
    if (pinned) {
        m_autoClose->stop();
        m_autoClose->hide();
        if (m_pin) {
            m_pin->setEnabled(false);
            m_pin->setText(u("已固定"));
            m_pin->setIcon(QIcon());
        }
    }
}
