#include "pages/TablePages.h"

#include "design/Banner.h"
#include "design/Components.h"
#include "design/Confirm.h"
#include "design/Format.h"
#include "design/IconTile.h"
#include "design/Identity.h"
#include "design/Skin.h"
#include "design/Theme.h"
#include "design/TitanKit.h"
#include "ipc/IpcClient.h"
#include "pages/PageKit.h"
#include "Nav.h"

#include <QDateTime>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHash>
#include <QLabel>
#include <QPainter>
#include <QPointer>
#include <QPushButton>
#include <QScrollArea>
#include <QSet>
#include <QTimer>
#include <QUuid>
#include <QVBoxLayout>

#include <memory>

using bulwark::ipc::HardeningItemPayload;
using bulwark::ipc::HardeningStatusResponsePayload;
using bulwark::ipc::HijackAlertPayload;

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

QColor severityColor(const QString& sev)
{
    if (sev == QLatin1String("danger")) return theme::danger();
    if (sev == QLatin1String("warn")) return theme::warning();
    if (sev == QLatin1String("info")) return theme::info();
    return theme::success();
}

QLabel* wrapped(const QString& text, const char* role)
{
    auto* l = ui::label(text, role);
    l->setWordWrap(true);
    l->setTextInteractionFlags(Qt::TextSelectableByMouse);
    return l;
}

void clearLayout(QLayout* l)
{
    while (QLayoutItem* it = l->takeAt(0)) {
        if (QWidget* w = it->widget())
            w->deleteLater();
        else if (QLayout* child = it->layout())
            clearLayout(child);
        delete it;
    }
}

QString surfaceLabel(const QString& s)
{
    if (s == QLatin1String("proxy")) return u("系统代理");
    if (s == QLatin1String("policy")) return u("浏览器策略");
    if (s == QLatin1String("dns")) return u("网卡 DNS");
    if (s == QLatin1String("shortcut")) return u("浏览器快捷方式");
    return s;
}

struct State {
    HardeningStatusResponsePayload last;
    bool haveData = false;
    QSet<QUuid> inflight;
    QHash<QUuid, QString> inflightWhat;
};

// 金刚:总览里的一排装甲板,一块对应一个加固项 / 基线项。蓝 = 已达标,琥珀 = 可加固,红 = 基线未达标。
class ArmorPlates final : public QWidget
{
public:
    enum class Plate { Ready, Upgrade, Risk };

    ArmorPlates()
    {
        setFixedHeight(32);
        setAttribute(Qt::WA_TransparentForMouseEvents);
    }

    void setPlates(QList<Plate> plates)
    {
        m_plates = std::move(plates);
        setFixedWidth(qMax(1, int(m_plates.size()) * (kW + kGap) - kGap + 2));
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        const theme::Palette& P = theme::pal();
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        for (int i = 0; i < m_plates.size(); ++i) {
            const Plate k = m_plates.at(i);
            const QColor c = k == Plate::Ready ? P.structure : k == Plate::Upgrade ? P.amber : P.danger;
            const QRectF r(1.0 + i * (kW + kGap), 3.0, kW, height() - 6.0);
            const QPainterPath path = theme::panelPath(r, 5.0);
            p.fillPath(path, c);
            p.save();
            p.setClipPath(path);
            p.fillRect(QRectF(r.left(), r.top(), r.width(), 4.0), k == Plate::Ready ? P.structureHi : c.lighter(125));
            p.fillRect(QRectF(r.left(), r.bottom() - 4.0, r.width(), 4.0), c.darker(140));
            p.restore();
            p.strokePath(path, QPen(P.ink, 2.0, Qt::SolidLine, Qt::SquareCap, Qt::MiterJoin));
        }
    }

private:
    static constexpr int kW = 20;
    static constexpr int kGap = 4;
    QList<Plate> m_plates;
};

}

namespace pages {

QWidget* hardening(IpcClient* ipc)
{
    auto* page = new QWidget;
    auto st = std::make_shared<State>();

    auto* outer = new QVBoxLayout(page);
    outer->setContentsMargins(0, 0, 0, 0);
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->viewport()->setAutoFillBackground(false);
    outer->addWidget(scroll);
    auto* content = new QWidget;
    auto* v = new QVBoxLayout(content);
    v->setContentsMargins(theme::metric::pagePad, 16, theme::metric::pagePad, theme::metric::pagePad);
    v->setSpacing(16);
    scroll->setWidget(content);
    content->setAutoFillBackground(false);

    QHBoxLayout* actions = pagekit::headerActions(page);
    QPushButton* refreshBtn = pagekit::headerButton(actions, QStringLiteral("refresh"), u("重新体检"));

    auto* summary = ui::card();
    summary->setGlow(identity::page(QString::fromLatin1(nav::Hardening)), QPointF(0.0, 0.0), 0.7, 0.12);
    auto* sh = new QHBoxLayout(summary);
    sh->setContentsMargins(20, 16, 20, 16);
    sh->setSpacing(16);
    auto* tile = new IconTile(QStringLiteral("shield"), identity::page(QString::fromLatin1(nav::Hardening)), 46, 22);
    sh->addWidget(tile, 0, Qt::AlignTop);
    auto* sv = new QVBoxLayout;
    sv->setSpacing(4);
    auto* headline = ui::label(u("正在读取…"), "h2");
    headline->setWordWrap(true);
    sv->addWidget(headline);
    auto* subline = wrapped(QString(), "secondary");
    sv->addWidget(subline);
    auto* guardLine = wrapped(QString(), "muted");
    sv->addWidget(guardLine);
    sh->addLayout(sv, 1);
    const bool titan = theme::titan();
    ArmorPlates* plates = nullptr;
    QLabel* platesLine = nullptr;
    if (titan) {
        auto* pv = new QVBoxLayout;
        pv->setSpacing(4);
        pv->addStretch();
        plates = new ArmorPlates;
        pv->addWidget(plates, 0, Qt::AlignRight);
        platesLine = ui::label(QString(), "muted");
        platesLine->setAlignment(Qt::AlignRight);
        pv->addWidget(platesLine);
        pv->addStretch();
        sh->addLayout(pv);
    }
    v->addWidget(summary);

    // 金刚:四块面板两行两列,按原型的顺序摆(告警 / 加固 / 在盯什么 / 基线)。
    auto* titanGrid = titan ? new QGridLayout : nullptr;
    QList<titankit::Panel> panels;
    const auto section = [v, titanGrid, &panels](const QString& icon, const QColor& hue, const QString& title,
                                                const QString& note, QLabel** countOut) -> QVBoxLayout* {
        if (titanGrid) {
            static const int kCell[] = {0, 1, 3, 2};
            const int at = kCell[qMin(int(panels.size()), 3)];
            titankit::Panel p = titankit::panel(title, QString(), QString(), hue);
            *countOut = p.head.note;
            if (!note.isEmpty())
                p.body->addWidget(wrapped(note, "muted"));
            auto* body = new QVBoxLayout;
            body->setSpacing(0);
            p.body->addLayout(body);
            p.body->addStretch();
            titanGrid->addWidget(p.card, at / 2, at % 2);
            panels << p;
            return body;
        }
        auto* card = ui::card();
        auto* cv = new QVBoxLayout(card);
        cv->setContentsMargins(20, 16, 20, 14);
        cv->setSpacing(10);
        auto* head = new QHBoxLayout;
        head->setSpacing(10);
        head->addWidget(new IconTile(icon, hue, 30, 15));
        head->addWidget(ui::label(title, "title"));
        *countOut = ui::label(QString(), "muted");
        head->addWidget(*countOut);
        head->addStretch();
        cv->addLayout(head);
        if (!note.isEmpty())
            cv->addWidget(wrapped(note, "muted"));
        auto* body = new QVBoxLayout;
        body->setSpacing(0);
        cv->addLayout(body);
        v->addWidget(card);
        return body;
    };
    QLabel *alertCount = nullptr, *hardenCount = nullptr, *baseCount = nullptr, *monCount = nullptr;
    QVBoxLayout* alertBody = section(QStringLiteral("alert"), theme::warning(), u("劫持告警"),
                                     u("系统代理 / 浏览器策略 / 网卡 DNS / 浏览器快捷方式相对基线被改成了可疑的值。"
                                       "「还原」把它改回基线;「接受」认可这个改动(以后不再就它告警)。"
                                       "这里只说「被改了」,不指认是哪个程序改的 —— 用户态拿不到写入者。"),
                                     &alertCount);
    QWidget* alertCard = alertBody->parentWidget();
    QVBoxLayout* hardenBody = section(QStringLiteral("shield"), theme::accent(), u("可一键加固"),
                                      u("每一项都会先说清代价再让你确认;应用前记下原样,撤销回到的是「你应用之前的样子」。"),
                                      &hardenCount);
    QVBoxLayout* baseBody = section(QStringLiteral("check"), theme::info(), u("基线体检(只读)"),
                                    u("这些设置常是有意为之(兼容旧软件、公司策略、第三方软件接管),所以只如实报告,不替你改。"),
                                    &baseCount);
    QVBoxLayout* monBody = section(QStringLiteral("eye"), theme::periwinkle(), u("劫持防护在盯什么"),
                                   QString(), &monCount);
    if (titanGrid) {
        titanGrid->setHorizontalSpacing(14);
        titanGrid->setVerticalSpacing(14);
        titanGrid->setColumnStretch(0, 1);
        titanGrid->setColumnStretch(1, 1);
        v->addLayout(titanGrid);
        alertCard = panels[0].card;
    }
    v->addStretch();

    QPointer<QWidget> pageGuard(page);

    std::function<void()> refresh;
    const auto act = [ipc, st, page](const QString& action, const QString& id, const QString& what) {
        if (!ipc->isConnected()) {
            ui::notify(page, ui::Tone::Warning, u("未连接后台服务,没法执行。"));
            return;
        }
        const QUuid req = ipc->hardeningAction(action, id);
        st->inflight.insert(req);
        st->inflightWhat.insert(req, what);
        ui::notify(page, ui::Tone::Info, u("正在%1…").arg(what));
    };

    const auto itemRow = [st, act, page](const HardeningItemPayload& it, bool actionsEnabled) -> QWidget* {
        auto* w = new QWidget;
        auto* rv = new QVBoxLayout(w);
        rv->setContentsMargins(0, 10, 0, 10);
        rv->setSpacing(4);
        auto* top = new QHBoxLayout;
        top->setSpacing(10);
        const bool monitor = it.group == QLatin1String("monitor");
        const QString pillText = monitor ? (it.satisfied ? u("在盯") : u("未盯"))
                                 : it.satisfied ? u("已达标")
                                 : it.severity == QLatin1String("danger") ? u("风险")
                                 : it.severity == QLatin1String("warn")   ? u("建议处理")
                                                                          : u("可选");
        top->addWidget(ui::pill(pillText, it.satisfied ? theme::success() : severityColor(it.severity)), 0, Qt::AlignTop);
        auto* title = ui::label(it.title, "title");
        title->setWordWrap(true);
        top->addWidget(title, 1);
        if (it.needsReboot && !monitor)
            top->addWidget(ui::pill(u("需重启"), theme::textMuted()), 0, Qt::AlignTop);
        if (it.group == QLatin1String("harden")) {
            if (it.actionable) {
                auto* b = ui::button(u("应用…"), "primary", QString(), true);
                b->setEnabled(actionsEnabled);
                if (!actionsEnabled)
                    b->setToolTip(u("部署配置不允许在界面上改系统状态(HardeningUiActionsEnabled=false)。"));
                QObject::connect(b, &QPushButton::clicked, page, [it, act, page] {
                    ui::ConfirmSpec s;
                    s.risk = it.id == QLatin1String("RunAsPPL") ? ui::Risk::Danger : ui::Risk::Caution;
                    s.title = u("应用加固:%1").arg(it.title);
                    s.summary = it.recommended;
                    s.consequences << it.cost;
                    if (it.needsReboot)
                        s.consequences << u("需要重启后才生效。");
                    s.consequences << u("可以在本页随时撤销,撤销回到应用之前的样子。");
                    s.subjectLabel = u("现状");
                    s.subject = it.current;
                    s.confirmText = u("应用");
                    if (ui::confirm(page, s))
                        act(QStringLiteral("apply"), it.id, u("应用「%1」").arg(it.title));
                });
                top->addWidget(b, 0, Qt::AlignTop);
            }
            if (it.revertible) {
                auto* b = ui::button(u("撤销…"), "ghost", QString(), true);
                b->setEnabled(actionsEnabled);
                QObject::connect(b, &QPushButton::clicked, page, [it, act, page] {
                    ui::ConfirmSpec s;
                    s.risk = ui::Risk::Info;
                    s.title = u("撤销加固:%1").arg(it.title);
                    s.summary = u("按应用前记下的原样逐项还原。");
                    if (it.needsReboot)
                        s.consequences << u("需要重启后才生效。");
                    s.consequences << u("撤销后这一项回到你应用之前的样子(不一定是 Windows 出厂的样子)。");
                    s.confirmText = u("撤销");
                    if (ui::confirm(page, s))
                        act(QStringLiteral("revert"), it.id, u("撤销「%1」").arg(it.title));
                });
                top->addWidget(b, 0, Qt::AlignTop);
            }
        }
        rv->addLayout(top);
        if (!it.current.isEmpty())
            rv->addWidget(wrapped(u("现状:") + it.current, "secondary"));
        if (!it.satisfied && !it.recommended.isEmpty() && !monitor)
            rv->addWidget(wrapped(u("建议:") + it.recommended, "secondary"));
        if (!it.cost.isEmpty())
            rv->addWidget(wrapped((monitor ? QString() : u("代价:")) + it.cost, "muted"));
        if (!it.note.isEmpty())
            rv->addWidget(wrapped(it.note, "muted"));
        return w;
    };

    const auto alertRow = [act, page](const HijackAlertPayload& a, bool actionsEnabled) -> QWidget* {
        auto* w = new QWidget;
        auto* rv = new QVBoxLayout(w);
        rv->setContentsMargins(0, 10, 0, 10);
        rv->setSpacing(4);
        auto* top = new QHBoxLayout;
        top->setSpacing(10);
        const bool pending = a.state == QLatin1String("pending");
        top->addWidget(ui::pill(pending ? u("待处理") : a.state == QLatin1String("restored") ? u("已还原") : u("已接受"),
                                pending ? theme::warning() : theme::success()),
                       0, Qt::AlignTop);
        top->addWidget(ui::pill(surfaceLabel(a.surface), theme::periwinkle()), 0, Qt::AlignTop);
        auto* title = ui::label(a.title, "title");
        title->setWordWrap(true);
        top->addWidget(title, 1);
        top->addWidget(ui::label(fmt::relativeTime(a.whenUtc), "muted"), 0, Qt::AlignTop);
        if (pending) {
            if (a.restorable) {
                auto* b = ui::button(u("还原…"), "primary", QString(), true);
                b->setEnabled(actionsEnabled);
                if (!actionsEnabled)
                    b->setToolTip(u("部署配置不允许在界面上改系统状态(HardeningUiActionsEnabled=false)。"));
                QObject::connect(b, &QPushButton::clicked, page, [a, act, page] {
                    ui::ConfirmSpec s;
                    s.risk = ui::Risk::Caution;
                    s.title = u("还原:%1").arg(a.title);
                    s.summary = u("把这一处改回基线(被改之前的值)。");
                    s.consequences << u("改回:%1").arg(a.oldValue.isEmpty() ? u("(原本不存在)") : a.oldValue)
                                   << u("如果这个改动其实是你自己(或你装的代理 / VPN / 浏览器)做的,还原会让那个设置失效。")
                                   << u("改它的程序如果还在,可能会再改一次 —— 那时会再次告警,建议同时排查最近装过的软件。");
                    s.subjectLabel = u("位置");
                    s.subject = a.location;
                    s.confirmText = u("还原");
                    if (ui::confirm(page, s))
                        act(QStringLiteral("restore"), a.id, u("还原「%1」").arg(a.title));
                });
                top->addWidget(b, 0, Qt::AlignTop);
            }
            auto* acc = ui::button(u("接受"), "ghost", QString(), true);
            QObject::connect(acc, &QPushButton::clicked, page, [a, act, page] {
                ui::ConfirmSpec s;
                s.risk = ui::Risk::Info;
                s.title = u("接受这个改动");
                s.summary = u("把基线更新为现在的值,以后不再就这一处告警。不会改动系统。");
                s.consequences << u("基线里不再保留旧值:之后想改回去,只能手动改。");
                s.subjectLabel = u("现值");
                s.subject = a.newValue;
                s.confirmText = u("接受");
                if (ui::confirm(page, s))
                    act(QStringLiteral("accept"), a.id, u("接受「%1」").arg(a.title));
            });
            top->addWidget(acc, 0, Qt::AlignTop);
        }
        rv->addLayout(top);
        auto* loc = ui::label(a.location, "mono");
        loc->setWordWrap(true);
        loc->setTextInteractionFlags(Qt::TextSelectableByMouse);
        rv->addWidget(loc);
        if (!a.preexisting)
            rv->addWidget(wrapped(u("原来:") + (a.oldValue.isEmpty() ? u("(不存在)") : a.oldValue), "secondary"));
        rv->addWidget(wrapped(u("现在:") + (a.newValue.isEmpty() ? u("(不存在)") : a.newValue), "secondary"));
        if (!a.detail.isEmpty())
            rv->addWidget(wrapped(a.detail, "muted"));
        if (a.preexisting)
            rv->addWidget(wrapped(u("这是首次建基线时就已存在的状态,没有「改之前的值」可还原;"
                                    "确认是你自己设的就接受,否则请手动排查。"),
                                  "muted"));
        return w;
    };

    const auto addRows = [](QVBoxLayout* body, const QList<QWidget*>& rows) {
        for (int i = 0; i < rows.size(); ++i) {
            if (i > 0) {
                auto* rule = new QFrame;
                rule->setFixedHeight(1);
                rule->setStyleSheet(QStringLiteral("background:%1;").arg(theme::border().name()));
                body->addWidget(rule);
            }
            body->addWidget(rows[i]);
        }
    };

    const auto render = [=]() {
        if (!pageGuard)
            return;
        const HardeningStatusResponsePayload& s = st->last;
        clearLayout(alertBody);
        clearLayout(hardenBody);
        clearLayout(baseBody);
        clearLayout(monBody);

        QList<QWidget*> alerts, harden, base, mon;
        int pending = 0, todo = 0, risky = 0;
        for (const HijackAlertPayload& a : s.alerts) {
            if (a.state == QLatin1String("pending"))
                ++pending;
            if (alerts.size() < 30)
                alerts << alertRow(a, s.actionsEnabled);
        }
        for (const HardeningItemPayload& it : s.items) {
            if (it.group == QLatin1String("harden")) {
                if (!it.satisfied)
                    ++todo;
                harden << itemRow(it, s.actionsEnabled);
            } else if (it.group == QLatin1String("baseline")) {
                if (!it.satisfied)
                    ++risky;
                base << itemRow(it, s.actionsEnabled);
            } else if (it.group == QLatin1String("monitor")) {
                mon << itemRow(it, s.actionsEnabled);
            }
        }
        if (titan) {
            // 金刚的四块面板固定两行两列:没有告警也留着这一块,只说一句。
            if (alerts.isEmpty())
                alertBody->addWidget(wrapped(u("系统代理 / 浏览器策略 / 网卡 DNS / 浏览器快捷方式都没有被改动。"), "muted"));
            QList<ArmorPlates::Plate> list;
            int ready = 0;
            for (const HardeningItemPayload& it : s.items) {
                const bool upgradable = it.group == QLatin1String("harden");
                if (!upgradable && it.group != QLatin1String("baseline"))
                    continue;
                ready += it.satisfied ? 1 : 0;
                list << (it.satisfied ? ArmorPlates::Plate::Ready
                         : upgradable ? ArmorPlates::Plate::Upgrade
                                      : ArmorPlates::Plate::Risk);
            }
            // 就位的装甲排在前面,缺口(可加固、未达标)依次排在后面。
            std::stable_sort(list.begin(), list.end(),
                             [](ArmorPlates::Plate a, ArmorPlates::Plate b) { return int(a) < int(b); });
            plates->setPlates(list);
            platesLine->setText(list.isEmpty() ? QString() : u("%1 / %2 块装甲已就位").arg(ready).arg(list.size()));
        } else {
            alertCard->setVisible(!alerts.isEmpty());
        }
        addRows(alertBody, alerts);
        addRows(hardenBody, harden);
        addRows(baseBody, base);
        addRows(monBody, mon);
        alertCount->setText(pending > 0 ? u("%1 条待处理").arg(pending) : u("没有待处理的"));
        hardenCount->setText(todo > 0 ? u("%1 项可加固").arg(todo) : u("都已达标"));
        baseCount->setText(risky > 0 ? u("%1 项未达标").arg(risky) : u("都已达标"));
        monCount->setText(s.hijackGuardActive ? u("运行中") : u("未运行"));
        if (mon.isEmpty())
            monBody->addWidget(wrapped(u("劫持防护没有在运行,没有可显示的监视面。"), "muted"));

        tile->set(QStringLiteral("shield"), pending > 0 ? theme::warning() : identity::page(QString::fromLatin1(nav::Hardening)));
        if (pending > 0)
            headline->setText(u("发现 %1 处疑似劫持待你处理").arg(pending));
        else if (todo + risky > 0)
            headline->setText(u("%1 项可加固 · %2 项基线未达标").arg(todo).arg(risky));
        else
            headline->setText(u("加固项与基线都已达标"));
        subline->setText(u("体检时间 %1。每一项现状都是刚从系统里读出来的。")
                             .arg(fmt::absoluteTime(s.scannedUtc)));
        QString g = s.hijackGuardActive
                        ? u("劫持防护运行中:约每 4 秒比对一次系统代理 / 浏览器策略 / 网卡 DNS,浏览器快捷方式稍慢。")
                        : u("劫持防护未运行。");
        if (!s.message.isEmpty())
            g += QLatin1Char(' ') + s.message;
        if (!s.actionsEnabled)
            g += u(" 部署配置把本页设为只读(HardeningUiActionsEnabled=false):可以看,不能改。");
        guardLine->setText(g);
        NavHub::instance()->setBadge(QString::fromLatin1(nav::Hardening), pending);
    };

    refresh = [ipc, headline, st]() {
        if (!ipc->isConnected()) {
            if (!st->haveData)
                headline->setText(u("未连接后台服务"));
            return;
        }
        ipc->requestHardeningStatus();
    };

    QObject::connect(ipc, &IpcClient::hardeningStatusReceived, page,
                     [st, render](const HardeningStatusResponsePayload& p) {
                         st->last = p;
                         st->haveData = true;
                         render();
                     });
    QObject::connect(ipc, &IpcClient::hardeningActionResult, page,
                     [st, page, refresh](const bulwark::ipc::HardeningActionResultPayload& r) {
                         if (!st->inflight.remove(r.requestId))
                             return;
                         const QString what = st->inflightWhat.take(r.requestId);
                         if (r.ok)
                             ui::notify(page, ui::Tone::Success,
                                        r.message.isEmpty() ? u("已%1。").arg(what) : r.message,
                                        r.needsReboot ? 9000 : -1);
                         else
                             ui::notify(page, ui::Tone::Danger,
                                        u("没能%1:%2").arg(what, r.message.isEmpty() ? u("服务没有给出原因。") : r.message));
                         refresh();
                     });
    QObject::connect(ipc, &IpcClient::hijackAlertReceived, page,
                     [refresh](const HijackAlertPayload&) { refresh(); });
    QObject::connect(refreshBtn, &QPushButton::clicked, page, [refresh] { refresh(); });

    pagekit::onConnected(page, ipc, nullptr, 900, refresh);
    auto* tick = new QTimer(page);
    tick->setInterval(30000);
    QObject::connect(tick, &QTimer::timeout, page, [page, refresh] {
        if (page->isVisible())
            refresh();
    });
    tick->start();
    nav::onArrive(page, QString::fromLatin1(nav::Hardening), [refresh](const QVariantMap&) { refresh(); });
    return page;
}

}
