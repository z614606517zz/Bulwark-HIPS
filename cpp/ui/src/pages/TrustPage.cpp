#include "pages/TablePages.h"
#include "pages/PageKit.h"
#include "dialogs/EventFormat.h"
#include "dialogs/EventViews.h"
#include "design/Banner.h"
#include "design/Confirm.h"
#include "design/DropZone.h"
#include "design/FilePicker.h"
#include "design/Format.h"
#include "design/Identity.h"
#include "design/Inspector.h"
#include "design/ListShell.h"
#include "design/Reflow.h"
#include "design/Robot.h"
#include "design/Skin.h"
#include "design/Sticker.h"
#include "design/Theme.h"
#include "design/TitanKit.h"
#include "ipc/IpcClient.h"

#include <QAbstractButton>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QFontMetricsF>
#include <QLabel>
#include <QMenu>
#include <QPainter>
#include <QPushButton>
#include <QTimer>
#include <QUrl>
#include <QtMath>

#include <algorithm>
#include <memory>

using evtfmt::u;
using bulwark::DefenseRule;

namespace {

const QString kFolders = QStringLiteral("folders");
const QString kFiles = QStringLiteral("files");

bool isDir(const DefenseRule& r) { return r.actorPath.isEmpty() && !r.actorPattern.isEmpty(); }

QString pathOf(const DefenseRule& r)
{
    if (!isDir(r))
        return evtfmt::nativePath(r.actorPath);
    QString p = evtfmt::nativePath(r.actorPattern);
    if (p.endsWith(QStringLiteral("\\*")))
        p.chop(2);
    return p;
}

QString noteOf(const DefenseRule& r)
{
    QString n = r.note;
    const QString tag = DefenseRule::trustNoteTag();
    if (n.startsWith(tag))
        n = n.mid(tag.size()).trimmed();
    return n;
}

QColor tintOf(const DefenseRule& r)
{
    if (theme::titan())
        return identity::page(nav::Trust);
    return isDir(r) ? theme::warning() : identity::kind(identity::Kind::File);
}

// 添加时间:今天的只写时分,其余写「月-日 时:分」。
QString shortTime(const QDateTime& utc)
{
    const QDateTime t = utc.toLocalTime();
    return t.toString(t.date() == QDate::currentDate() ? QStringLiteral("HH:mm") : QStringLiteral("MM-dd HH:mm"));
}

QString leafName(const QString& path)
{
    const QString n = QFileInfo(path).fileName();
    return n.isEmpty() ? path : n;
}

// 临时信任还剩多久(金刚的信任名单把它挂在最前面)。
QString remainingOf(const DefenseRule& r)
{
    if (r.sessionOnly)
        return u("临时 · 本次会话");
    if (!r.expiresUtc)
        return QString();
    const qint64 secs = QDateTime::currentDateTimeUtc().secsTo(*r.expiresUtc);
    if (secs <= 0)
        return u("临时 · 已到期");
    if (secs < 3600)
        return u("临时 · 剩 %1 分").arg(qMax<qint64>(1, secs / 60));
    if (secs < 2 * 86400)
        return u("临时 · 剩 %1 小时").arg(secs / 3600);
    return u("临时 · 剩 %1 天").arg(secs / 86400);
}

RecordView trustView(const DefenseRule& r)
{
    RecordView v;
    const bool dir = isDir(r);
    const QString path = pathOf(r);
    v.icon = dir ? QStringLiteral("folder") : QStringLiteral("file");
    v.iconColor = tintOf(r);
    v.title = leafName(path);
    v.subtitle = path;
    v.subtitleMono = true;
    if (theme::titan()) {
        // 金刚:整条路径当标题(文件夹带尾部的 \),备注当副标题,右侧是添加时间和「文件夹 / 程序」牌子。
        v.title = dir && !path.endsWith(QLatin1Char('\\')) ? path + QLatin1Char('\\') : path;
        v.subtitle = noteOf(r);
        v.subtitleMono = false;
        v.accent = tintOf(r);
        v.pill = dir ? u("文件夹") : u("程序");
        v.pillColor = tintOf(r);
        v.meta = shortTime(r.createdUtc);
        if (const QString left = remainingOf(r); !left.isEmpty()) {
            v.chips << left;
            v.chipColors << theme::warning();
        }
    } else {
        if (const QString n = noteOf(r); !n.isEmpty())
            v.chips << n;
        v.time = r.createdUtc;
    }
    v.tooltip = path;
    v.haystack = path + QLatin1Char(' ') + r.note;
    v.key = r.id.toString(QUuid::WithoutBraces);
    return v;
}

QFont titanPx(qreal px, int weight)
{
    QFont f = sticker::headFont(9.0, weight);
    f.setPointSizeF(px * 0.75);
    return f;
}

// CSS 的 color-mix(in srgb, a t, b)。
QColor mixed(const QColor& a, qreal t, const QColor& b)
{
    return QColor::fromRgbF(float(a.redF() * t + b.redF() * (1.0 - t)), float(a.greenF() * t + b.greenF() * (1.0 - t)),
                            float(a.blueF() * t + b.blueF() * (1.0 - t)));
}

// 原稿的 .chip:20 高、左右各空 7,底色是色相兑 10% 进底板,描边是色相兑 55% 进墨色。
class HueChip final : public QWidget
{
public:
    HueChip(const QString& text, const QColor& hue) : m_text(text), m_hue(hue)
    {
        setFont(titanPx(11, QFont::DemiBold));
        setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    }

    QSize sizeHint() const override
    {
        return QSize(qCeil(QFontMetricsF(font()).horizontalAdvance(m_text) + 2 * 7.0 + 2 * 1.5), 20);
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setPen(QPen(mixed(m_hue, 0.55, theme::ink()), 1.5));
        p.setBrush(mixed(m_hue, 0.10, theme::surfaceAlt()));
        p.drawRect(QRectF(rect()).adjusted(0.75, 0.75, -0.75, -0.75));
        p.setPen(m_hue);
        p.drawText(rect(), Qt::AlignCenter, m_text);
    }

private:
    QString m_text;
    QColor m_hue;
};

// 拖放区里的 2px 虚线框(色相 65% 不透明,段长 6、间隔 4)。
class DashedFrame final : public QWidget
{
public:
    explicit DashedFrame(const QColor& hue) : m_hue(hue) {}

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        QColor c = m_hue;
        c.setAlphaF(0.65f);
        QPen pen(c, 2.0, Qt::CustomDashLine, Qt::FlatCap, Qt::MiterJoin);
        pen.setDashPattern({3.0, 2.0});
        p.setPen(pen);
        p.drawRect(QRectF(rect()).adjusted(1.0, 1.0, -1.0, -1.0));
    }

private:
    QColor m_hue;
};

// 金刚右栏上半:「拖入信任」。整页都接受拖放,这块只是告诉你可以这么做。
QWidget* titanDropZone(const QColor& hue)
{
    auto* zone = ui::cardAlt();
    auto* outer = new QVBoxLayout(zone);
    outer->setContentsMargins(10, 10, 10, 10);
    auto* frame = new DashedFrame(hue);
    outer->addWidget(frame);

    auto* v = new QVBoxLayout(frame);
    v->setContentsMargins(14, 14, 14, 14);
    v->setSpacing(0);
    v->addStretch(1);
    robot::Look look;
    look.pose = robot::Pose::Wave;
    look.mood = robot::Mood::Happy;
    look.extras = false;
    look.strokePx = 2.0;
    auto* bot = new RobotWidget(104, look);
    bot->setAnimated(true);
    v->addWidget(bot, 0, Qt::AlignHCenter);
    v->addSpacing(6);
    v->addWidget(titankit::lined(u("拖入信任"), titanPx(15, QFont::ExtraBold), theme::pal().text, 15 * 1.3,
                                 Qt::AlignHCenter));
    v->addSpacing(6);
    v->addWidget(titankit::lined(u("把程序或文件夹拖到这里\n松开以加入信任名单"), titanPx(12, QFont::Normal),
                                 theme::textMuted(), 12 * 1.5, Qt::AlignHCenter));
    v->addSpacing(4 + 6);
    v->addWidget(new HueChip(u("整个目录跳过检测"), hue), 0, Qt::AlignHCenter);
    v->addStretch(1);

    // 窗口矮到这块放不下整套内容时,先收起机器人(它只是装饰),文字和标签保持完整。
    ui::onResize(frame, [frame, v, bot] { ui::showIfFits(bot, v, frame->size()); });
    return zone;
}

}

QWidget* pages::trust(IpcClient* ipc)
{
    auto* page = new RecordBrowser;
    page->setIdentity(identity::page(nav::Trust));
    page->setGrouped(true, true);
    page->searchBox()->setPlaceholderText(u("搜索路径 / 备注…"));
    auto store = std::make_shared<RecordStore<DefenseRule>>(page->model(), &trustView);

    const auto addFile = [page, ipc] {
        const QString f = ui::pickExistingFile(page, u("选择要信任的程序"),
                                               u("可执行文件 (*.exe *.com *.scr *.dll);;所有文件 (*.*)"));
        if (!f.isEmpty())
            evtview::trust(page, ipc, f, false, u("用户手动信任"));
    };
    const auto addFolder = [page, ipc] {
        const QString d = ui::pickExistingFolder(page, u("选择要信任的文件夹(其中运行的所有程序将不再检测)"));
        if (!d.isEmpty())
            evtview::trust(page, ipc, d, true, u("用户手动信任文件夹"));
    };
    page->setNoDataContent(QStringLiteral("trust"), u("信任名单是空的"),
                           u("被信任的程序或文件夹会直接放行,并跳过全部检测。只把你确认安全的东西放进来。"),
                           u("信任程序…"), addFile);
    const QColor olive = identity::page(nav::Trust);
    if (theme::titan()) {
        // 金刚:列表右边一栏 —— 上面小垒挥手招呼你把东西拖进来(整页都接受拖放),下面说清信任意味着什么。
        auto* side = new QWidget;
        side->setFixedWidth(300);
        auto* sv = new QVBoxLayout(side);
        sv->setContentsMargins(0, 0, 0, 0);
        sv->setSpacing(12);
        sv->addWidget(titanDropZone(olive), 1);
        titankit::Panel iff = titankit::panel(u("盟友识别"), QString(), QStringLiteral("IFF"), olive);
        iff.body->addWidget(titankit::lined(u("信任 = 发一枚友军徽章:之后它的行为不再经过规则与威胁检测。"
                                              "若只是某个程序被误拦,优先在拦截通知上「撤销拦截 · 信任 1 小时」。"),
                                            titanPx(11.5, QFont::Normal), theme::textMuted(), 11.5 * 1.6));
        sv->addWidget(iff.card);
        page->addSide(side);

        auto* hint = ui::label(u("被信任的程序或文件夹会直接放行,并跳过全部检测。只把你确认安全的东西放进来。"), "muted");
        hint->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        hint->setMinimumWidth(40);
        page->setLeadingBar(280, u("%1 项"), hint);
        // 全局样式表给 role=muted 的字定了 9pt,setFont 压不过它,只能在控件自己的样式表里改。
        page->matchLabel()->setStyleSheet(
            QStringLiteral("color:%1; font-family:'Bahnschrift'; font-size:8.6pt; font-weight:600;")
                .arg(theme::textMuted().name()));
    }

    page->setInspectorBuilder([store, ipc, page](Inspector* in, int row) {
        const DefenseRule* r = store->itemAt(row);
        if (!r)
            return;
        const bool dir = isDir(*r);
        const QString path = pathOf(*r);
        in->setHeader(dir ? QStringLiteral("folder") : QStringLiteral("file"), tintOf(*r), leafName(path),
                      dir ? u("信任的文件夹") : u("信任的程序"));
        in->addLead(dir ? u("这个文件夹及其子目录中运行的所有程序都完全跳过检测,直接放行。")
                        : u("这个程序的所有行为都直接放行,并跳过云查毒与 IP 情报。"));
        QVBoxLayout* s = in->addSection(u("信任项"));
        in->addField(s, dir ? u("文件夹") : u("程序"), path, Inspector::Mono | Inspector::Copy);
        if (dir)
            in->addField(s, u("匹配"), evtfmt::nativePath(r->actorPattern), Inspector::Mono);
        in->addField(s, u("备注"), noteOf(*r));
        in->addField(s, u("添加时间"), fmt::absoluteTime(r->createdUtc));
        in->addField(s, u("规则 ID"), r->id.toString(QUuid::WithoutBraces), Inspector::Mono | Inspector::Copy);
        if (dir)
            in->setNote(u("今后放进这个文件夹的新程序同样不受检测。"), theme::warning());

        const DefenseRule rule = *r;
        in->addAction(QStringLiteral("trash"), u("移除信任"), "danger", [page, ipc, rule, path, dir] {
            if (!ipc->isConnected()) {
                ui::notify(page, ui::Tone::Danger, u("未连接后台服务,无法移除信任项。"));
                return;
            }
            ui::ConfirmSpec c;
            c.title = dir ? u("移除信任的文件夹") : u("移除信任的程序");
            c.summary = u("移除后恢复正常检测:它的行为会重新经过规则与威胁检测。");
            c.subjectLabel = dir ? u("文件夹") : u("程序");
            c.subject = path;
            c.confirmText = u("移除信任");
            if (!ui::confirm(page, c))
                return;
            const QUuid id = rule.id;
            auto* guard = new QObject(page);
            QObject::connect(ipc, &IpcClient::trustReceived, guard,
                             [guard, page, id, path](const QList<DefenseRule>& list) {
                if (std::any_of(list.cbegin(), list.cend(), [id](const DefenseRule& x) { return x.id == id; }))
                    return;
                ui::notify(page, ui::Tone::Success, u("已移除信任:%1").arg(path));
                guard->deleteLater();
            });
            QTimer::singleShot(8000, guard, [guard, page, path] {
                ui::notify(page, ui::Tone::Warning, u("「%1」仍在信任名单里,移除没有生效。").arg(path));
                guard->deleteLater();
            });
            ipc->removeTrust(id);
        });
        in->addAction(QStringLiteral("folder"), u("打开位置"), "ghost", [path, dir] {
            QDesktopServices::openUrl(QUrl::fromLocalFile(dir ? path : QFileInfo(path).absolutePath()));
        });
    });
    page->setContextMenuBuilder([page, store](QMenu* m, const QList<int>& rows) {
        if (rows.size() != 1)
            return;
        const DefenseRule* r = store->itemAt(rows.first());
        if (!r)
            return;
        const QString path = pathOf(*r);
        pagekit::menuAction(m, QStringLiteral("copy"), u("复制路径"), page, [path] {
            if (QClipboard* cb = QGuiApplication::clipboard())
                cb->setText(path);
        });
    });

    const auto reload = [page, ipc] {
        if (!ipc->isConnected())
            return;
        page->setLoading(true);
        ipc->requestTrust();
    };
    QHBoxLayout* actions = pagekit::headerActions(page);
    if (theme::titan()) {
        QAbstractButton* folder = titankit::button(u("信任文件夹…"), nullptr, QStringLiteral("folder"));
        QAbstractButton* file = titankit::button(u("信任程序…"), "primary", QStringLiteral("plus"));
        QAbstractButton* refresh = titankit::button(QString(), nullptr, QStringLiteral("refresh"));
        refresh->setToolTip(u("刷新列表"));
        actions->addWidget(folder);
        actions->addWidget(file);
        actions->addWidget(refresh);
        QObject::connect(folder, &QAbstractButton::clicked, page, addFolder);
        QObject::connect(file, &QAbstractButton::clicked, page, addFile);
        QObject::connect(refresh, &QAbstractButton::clicked, page, reload);
    } else {
        QObject::connect(pagekit::headerButton(actions, QStringLiteral("folder"), u("信任文件夹…")),
                         &QPushButton::clicked, page, addFolder);
        QObject::connect(pagekit::headerButton(actions, QStringLiteral("plus"), u("信任程序…"), "primary"),
                         &QPushButton::clicked, page, addFile);
        QMenu* more = pagekit::headerMenu(actions);
        pagekit::menuAction(more, QStringLiteral("refresh"), u("刷新列表"), page, reload);
    }

    ui::acceptFileDrops(page, u("松开以加入信任名单"), [page, ipc](const QStringList& paths) {
        for (const QString& p : paths)
            evtview::trust(page, ipc, p, QFileInfo(p).isDir(), u("拖入信任"));
    });

    QObject::connect(ipc, &IpcClient::trustReceived, page, [page, store](const QList<DefenseRule>& entries) {
        QList<DefenseRule> list = entries;
        std::stable_sort(list.begin(), list.end(),
                         [](const DefenseRule& a, const DefenseRule& b) { return a.createdUtc > b.createdUtc; });
        store->resetGrouped(
            list, [](const DefenseRule& r) { return isDir(r) ? kFolders : kFiles; },
            [](const QString& g, const QList<const DefenseRule*>&) {
                RecordView h;
                const bool folders = g == kFolders;
                if (theme::titan()) {
                    h.title = folders ? u("信任的文件夹") : u("信任的程序");
                    h.groupNote = folders ? u("文件夹及其子目录中运行的所有程序都完全跳过检测")
                                          : u("这个程序的所有行为都直接放行");
                    h.groupColor = identity::page(nav::Trust);
                    return h;
                }
                h.title = folders ? u("文件夹") : u("程序");
                h.groupNote = folders ? u("整个目录跳过检测") : QString();
                h.groupColor = folders ? theme::warning() : QColor();
                return h;
            },
            {kFolders, kFiles});
        page->setLoading(false);
    });
    pagekit::onConnected(page, ipc, page, 0, reload);
    return page;
}
