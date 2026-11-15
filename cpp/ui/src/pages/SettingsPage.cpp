#include "pages/CardPages.h"
#include "pages/PageKit.h"
#include "Bootstrap.h"
#include "dialogs/EventFormat.h"
#include "bulwark/Version.h"
#include "bulwark/models/RuntimeSettings.h"
#include "design/Banner.h"
#include "design/Components.h"
#include "design/Confirm.h"
#include "design/FilePicker.h"
#include "design/GlowCard.h"
#include "design/IconTile.h"
#include "design/Identity.h"
#include "design/Motion.h"
#include "design/NavButton.h"
#include "design/Reflow.h"
#include "design/Robot.h"
#include "design/StatusStrip.h"
#include "design/Sticker.h"
#include "design/Skin.h"
#include "design/Theme.h"
#include "design/TitanKit.h"
#include "design/ToggleSwitch.h"
#include "ai/McpManager.h"
#include "dialogs/McpServerDialog.h"
#include "ipc/IpcClient.h"
#include "voice/VoiceAnnouncer.h"
#include "widgets/ResidentBot.h"
#include "widgets/TrafficOverlay.h"
#include "Nav.h"

#include <QAbstractButton>
#include <QButtonGroup>
#include <QEnterEvent>
#include <QFontMetricsF>
#include <QMenu>
#include <QPainter>
#include <QPainterPath>
#include <QGridLayout>
#include <QHash>
#include <QLabel>
#include <QLineEdit>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

#include <QtMath>

#include <algorithm>
#include <array>
#include <cmath>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>

using evtfmt::u;
using bulwark::RuntimeSettings;

namespace {

struct ToggleBind {
    ToggleSwitch* sw = nullptr;
    bool RuntimeSettings::*field = nullptr;
};
struct TextBind {
    QLineEdit* edit = nullptr;
    QString RuntimeSettings::*field = nullptr;
};
struct State {
    RuntimeSettings last;
    bool have = false;
    bool loading = false;    // echoing a snapshot into the controls (don't send it back)
    bool connected = false;
    bool pendingSave = false;
    int saveSeq = 0;
    QList<ToggleBind> toggles;
    QList<TextBind> texts;
    QSpinBox* timeout = nullptr;
    QList<QWidget*> controls;
    QLabel* saveState = nullptr;
    StatusStrip* strip = nullptr;
    QLabel* aiState = nullptr;
    std::function<void()> rebuildGuardDirs;
    std::function<void()> applyNow;
};

// 在本页点风格卡会让界面整套重建、再重新打开设置页(UiHost::rebuildFor),这一页也是新建的。
// 风格卡不在页面顶部,所以跨重建记一笔:重建后的那次到达回到风格卡所在的一节,不把人扔回顶部。
bool g_returnToSkinCards = false;

// 金刚的分区卡片标题右边挂一个代号标签。
QString sectionTag(const QString& key)
{
    static const QHash<QString, QString> tags{
        {QStringLiteral("protection"), QStringLiteral("MASTER")}, {QStringLiteral("dims"), QStringLiteral("DIMENSIONS")},
        {QStringLiteral("decision"), QStringLiteral("DECISION")}, {QStringLiteral("ransom"), QStringLiteral("SHIELDED")},
        {QStringLiteral("ai"), QStringLiteral("AI")},             {QStringLiteral("mcp"), QStringLiteral("MCP")},
        {QStringLiteral("appearance"), QStringLiteral("SKIN")},   {QStringLiteral("about"), QStringLiteral("ABOUT")},
    };
    return tags.value(key);
}

// 金刚的设置页按设计稿排:左边一块导航面板,右边两列紧凑的分区面板。面板内容区左右留白,
// 行与行之间的分隔线要顶到面板两边,用负边距把它撑出去。
constexpr int kTitanPadL = 16;
constexpr int kTitanPadR = 14;

void titanRule(QVBoxLayout* box)
{
    auto* line = new QFrame;
    line->setFixedHeight(1);
    line->setStyleSheet(QStringLiteral("background:#080B12;"));
    auto* bleed = new QHBoxLayout;
    bleed->setContentsMargins(-kTitanPadL, 0, -kTitanPadR, 0);
    bleed->addWidget(line);
    box->addLayout(bleed);
}

QLabel* titanText(const QString& text, const char* role, const char* size)
{
    auto* l = ui::label(text, role);
    l->setStyleSheet(QStringLiteral("font-size:%1;").arg(QLatin1String(size)));
    return l;
}

// 把一个控件撑到面板两边(抵消内容区的左右留白):目录列表、MCP 列表的行线要贯通整块面板。
void titanBleed(QVBoxLayout* box, QWidget* w)
{
    auto* bleed = new QHBoxLayout;
    bleed->setContentsMargins(-kTitanPadL, 0, -kTitanPadR, 0);
    bleed->addWidget(w);
    box->addLayout(bleed);
}

// 贯通面板的列表里的一行:顶上一条行线,内容左右留白与面板其余内容对齐。
class TitanListRow final : public QWidget
{
public:
    TitanListRow() { setAttribute(Qt::WA_StyledBackground, false); }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.fillRect(QRect(0, 0, width(), 1), QColor(0x08, 0x0B, 0x12));
    }
};

// 金刚设置页左侧导航面板里的一项:分区色的图标 + 名字;选中时底色亮一档,左边一条分区色的光条。
class TitanNavItem final : public QAbstractButton
{
public:
    TitanNavItem(const QString& icon, const QString& text, const QColor& hue) : m_icon(icon), m_hue(hue)
    {
        setText(text);
        setAccessibleName(text);
        setCursor(Qt::PointingHandCursor);
        setFocusPolicy(Qt::TabFocus);
        setFixedHeight(34);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    }
    QSize sizeHint() const override { return {160, 34}; }

protected:
    void paintEvent(QPaintEvent*) override
    {
        const theme::Palette& P = theme::pal();
        QPainter p(this);
        const bool on = isChecked();
        if (on) {
            p.fillRect(rect(), P.surfaceHi);
            p.fillRect(QRectF(0, 5, 6, height() - 10), theme::tint(m_hue, 0.22));
            p.fillRect(QRectF(0, 6, 3, height() - 12), m_hue);
        } else if (underMouse()) {
            p.fillRect(rect(), QColor(255, 255, 255, 10));
        }
        p.setRenderHint(QPainter::Antialiasing, true);
        AppIcon::draw(p, m_icon, QRectF(11, (height() - 15) / 2.0, 15, 15), m_hue, 1.6);
        QFont f = font();
        f.setPixelSize(13);
        f.setWeight(QFont::Bold);
        p.setFont(f);
        p.setPen(on ? QColor(0xFF, 0xFF, 0xFF) : underMouse() ? P.text : P.textMuted);
        p.drawText(QRectF(34, 0, width() - 38, height()), Qt::AlignLeft | Qt::AlignVCenter, text());
        if (hasFocus()) {
            p.setPen(QPen(P.borderLit, 1.2, Qt::DashLine));
            p.setBrush(Qt::NoBrush);
            p.drawRect(QRectF(rect()).adjusted(1.5, 1.5, -1.5, -1.5));
        }
    }
    void enterEvent(QEnterEvent* e) override
    {
        QAbstractButton::enterEvent(e);
        update();
    }
    void leaveEvent(QEvent* e) override
    {
        QAbstractButton::leaveEvent(e);
        update();
    }

private:
    QString m_icon;
    QColor m_hue;
};

QVBoxLayout* sectionCard(QWidget** cardOut, const QString& icon, const QColor& hue, const QString& title,
                         const QString& lead = QString(), const QString& tag = QString())
{
    if (theme::titan()) {
        titankit::Panel pn = titankit::panel(title, QString(), tag, hue);
        pn.body->setContentsMargins(kTitanPadL, 0, kTitanPadR, 4);
        pn.body->setSpacing(0);
        if (!lead.isEmpty()) {
            auto* l = titanText(lead, "muted", "8.6pt");
            l->setWordWrap(true);
            l->setContentsMargins(0, 0, 0, 9);
            pn.body->addWidget(l);
        }
        *cardOut = pn.card;
        return pn.body;
    }
    GlowCard* c = ui::card();
    c->setGlow(hue, QPointF(0.0, 0.0), 0.45, 0.06);
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(22, 18, 22, 18);
    v->setSpacing(4);
    auto* head = new QHBoxLayout;
    head->setSpacing(10);
    head->addWidget(new IconTile(icon, hue, 30, 15), 0, Qt::AlignVCenter);
    head->addWidget(ui::label(title, "h2"), 1, Qt::AlignVCenter);
    if (theme::titan() && !tag.isEmpty())
        head->addWidget(titankit::labTag(tag), 0, Qt::AlignVCenter);
    v->addLayout(head);
    if (!lead.isEmpty()) {
        auto* l = ui::label(lead, "muted");
        l->setWordWrap(true);
        l->setContentsMargins(40, 0, 0, 0);
        v->addWidget(l);
    }
    v->addSpacing(6);
    *cardOut = c;
    return v;
}

QWidget* settingRow(QVBoxLayout* box, const QString& title, const QString& desc, QWidget* control, bool first = false)
{
    if (theme::titan()) {
        if (!first)
            titanRule(box);
        auto* w = new QWidget;
        auto* h = new QHBoxLayout(w);
        h->setContentsMargins(0, 9, 0, 9);
        h->setSpacing(14);
        auto* col = new QVBoxLayout;
        col->setSpacing(1);
        col->addWidget(titanText(title, "title", "9.75pt"));
        if (!desc.isEmpty()) {
            auto* d = titanText(desc, "muted", "8.6pt");
            d->setWordWrap(true);
            col->addWidget(d);
        }
        h->addLayout(col, 1);
        h->addWidget(control, 0, Qt::AlignVCenter);
        box->addWidget(w);
        return w;
    }
    if (!first)
        box->addWidget(ui::hDivider());
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 10, 0, 10);
    h->setSpacing(16);
    auto* col = new QVBoxLayout;
    col->setSpacing(2);
    col->addWidget(ui::label(title, "title"));
    if (!desc.isEmpty()) {
        auto* d = ui::label(desc, "muted");
        d->setWordWrap(true);
        col->addWidget(d);
    }
    h->addLayout(col, 1);
    h->addWidget(control, 0, Qt::AlignVCenter);
    box->addWidget(w);
    return w;
}

// 会明显削弱防护的几个开关:切换前先问一句,把后果说清楚。返回空 = 这次切换不用确认。
// 实时防护 / 自我保护 / 受保护目录 / 退出界面即停止防护 各有自己的确认框,不在这里。
// 文案要与服务端的实际行为一致:静默模式见 Worker::applySilentMode,超时策略见 promptTimeoutShouldBlock。
std::optional<ui::ConfirmSpec> weakeningConfirm(bool RuntimeSettings::*field, bool on)
{
    ui::ConfirmSpec c;
    c.risk = ui::Risk::Caution;
    if (field == &RuntimeSettings::silentMode) {
        if (!on)
            return std::nullopt;
        c.title = u("开启静默模式");
        c.summary = u("开启后不再弹出询问:原本要问你的可疑行为由软件自行处理 —— "
                      "高置信的高危行为直接拦截,其余一律自动放行。");
        c.consequences << u("那些拿不准、本该由你判断的可疑行为会被直接放行")
                       << u("自动放行的行为仍会记入「事件记录」,可以事后查看")
                       << u("适合演示、全屏游戏这类短时间不想被打扰的场合,用完记得关掉");
        c.confirmText = u("开启静默模式");
        return c;
    }
    // 以下几项都是「关闭」才需要确认。
    if (on)
        return std::nullopt;
    if (field == &RuntimeSettings::promptTimeoutBlockHighRisk) {
        c.title = u("关闭高风险询问超时自动拦截");
        c.summary = u("关闭后,带硬指标且风险分 ≥ 70 的询问在超时无人响应时,也按默认策略处理。");
        c.consequences << u("没有打开「默认拦截未知行为」时,默认策略是放行:人不在电脑前,"
                            "这类高风险行为会在倒计时结束后被自动放行")
                       << u("其余询问的超时处理不受影响");
        c.confirmText = u("关闭");
        return c;
    }
    if (field == &RuntimeSettings::kernelDriverEnabled) {
        c.title = u("关闭内核驱动");
        c.summary = u("关闭后停用内核驱动 Bulwark.sys,本软件不再能在行为发生之前拦截。");
        c.consequences << u("多数危险行为只能在发生之后发现和处置,有些只能记录、拦不下来")
                       << u("受保护目录降级为「发现后处置」:发起进程会被结束,但首批文件可能已被加密")
                       << u("重新打开即恢复");
        c.confirmText = u("关闭内核驱动");
        return c;
    }
    struct Dim {
        bool RuntimeSettings::*field;
        const char* name;
        const char* covers;
    };
    static const Dim dims[] = {
        {&RuntimeSettings::processProtection, "进程防护", "进程创建、远程线程注入"},
        {&RuntimeSettings::fileProtection, "文件防护", "敏感文件写入、删除"},
        {&RuntimeSettings::registryProtection, "注册表防护", "启动项、敏感键值写入"},
        {&RuntimeSettings::networkProtection, "网络防护", "可疑外联、C2 通信"},
        {&RuntimeSettings::memoryProtectionEnabled, "内存防护", "注入类内存操作"},
    };
    for (const Dim& d : dims) {
        if (field != d.field)
            continue;
        c.title = u("关闭%1").arg(u(d.name));
        c.summary = u("关闭后,「%1」这一类行为不再被监控和拦截;其它维度不受影响。").arg(u(d.covers));
        c.consequences << u("若是因为某个程序被误拦,更好的做法是把那个程序加入「信任名单」,而不是关掉整维防护")
                       << u("重新打开即恢复");
        c.confirmText = u("关闭%1").arg(u(d.name));
        return c;
    }
    return std::nullopt;
}

// 「界面风格」里的一张风格卡:左边按那套皮肤画一个挥手的小垒,右边是名字、说明和色板。
class SkinCard : public QAbstractButton
{
public:
    explicit SkinCard(theme::Skin skin) : m_skin(skin)
    {
        setCursor(Qt::PointingHandCursor);
        setFocusPolicy(Qt::StrongFocus);
        setMinimumHeight(theme::titan() ? 180 : 188);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        const bool on = theme::skin() == skin;
        setAccessibleName(theme::skinName(skin) + (on ? u("(使用中)") : QString()));
        setToolTip(on ? u("当前使用的界面风格") : u("切换到「%1」风格").arg(theme::skinName(skin)));
        // 鼠标停上来时卡片里的小垒挥起手来。
        m_wave = new motion::Ticker(this, [this](qint64) {
            update(stageRect().toAlignedRect().adjusted(-3, -3, 3, 3));
        }, 40);
    }
    QSize sizeHint() const override { return theme::titan() ? QSize(140, 180) : QSize(320, 188); }

protected:
    // 金刚:三张竖排的小卡并排在半宽的面板里 —— 上面一块暗底舞台站着那套皮肤的小垒,下面是名字、色条和一句说明。
    void paintTitan(QPainter& p)
    {
        const theme::Palette& P = theme::pal();
        const bool on = theme::skin() == m_skin;
        QString desc;
        std::array<QColor, 4> sw;
        switch (m_skin) {
        case theme::Skin::Mecha:
            desc = u("炭黑 + 装甲白 + 赛车橙。切角硬朗,你是指挥官。");
            sw = {QColor(0x18, 0x17, 0x14), QColor(0xF7, 0xF6, 0xF3), QColor(0xFF, 0x6A, 0x13), QColor(0xFF, 0xCF, 0x33)};
            break;
        case theme::Skin::Kawaii:
            desc = u("可可棕描边 + 粉彩。大圆角,小垒是小伙伴。");
            sw = {QColor(0x5B, 0x40, 0x36), QColor(0xFF, 0xB8, 0xCB), QColor(0xB9, 0xA6, 0xFF), QColor(0x7F, 0xE3, 0xC6)};
            break;
        case theme::Skin::Titan:
            desc = u("装甲红 + 钴蓝 + 铬银,暗色屏。平时是卡车,有事变形。");
            sw = {QColor(0xD3, 0x23, 0x2B), QColor(0x24, 0x59, 0xD8), QColor(0xC6, 0xCF, 0xDA), QColor(0x35, 0xD4, 0xFF)};
            break;
        }
        const QRectF r = QRectF(rect()).adjusted(1, 1, -1, -1);
        const QPainterPath body = theme::panelPath(r, 9.0);
        p.fillPath(body, underMouse() && !on ? P.surface : P.surfaceAlt);
        p.strokePath(body, QPen(on ? P.glow : P.ink, 2.0, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));
        if (hasFocus())
            p.strokePath(theme::panelPath(r.adjusted(4, 4, -4, -4), 6.0), QPen(P.borderLit, 1.2, Qt::DashLine));

        const QRectF stage = stageRect();
        p.fillRect(stage, QColor(0x0B, 0x10, 0x18));
        p.setPen(QPen(P.ink, 2.0, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));
        p.setBrush(Qt::NoBrush);
        p.drawRect(stage);
        robot::Look look;
        look.mood = robot::Mood::Happy;
        look.pose = robot::Pose::Wave;
        look.shadow = false;
        if (m_wave->isActive()) {
            const qreal t = qreal(motion::clockMs()) / 1000.0;
            look.phase = std::fmod(t / 1.6, 1.0);
            look.pulse = 0.5 + 0.5 * std::sin(t * 2.0 * M_PI / 1.2);
        }
        robot::paintAs(p, stage.adjusted(10, 5, -10, -3), look, m_skin);

        const qreal left = r.left() + 8;
        const qreal textW = r.width() - 16;
        qreal y = stage.bottom() + 6;
        QFont nf = font();
        nf.setPixelSize(13);
        nf.setWeight(QFont::ExtraBold);
        p.setFont(nf);
        p.setPen(P.text);
        const QString name = theme::skinName(m_skin);
        p.drawText(QRectF(left, y, textW, 18), Qt::AlignLeft | Qt::AlignVCenter, name);
        if (on) {
            QFont pf = font();
            pf.setPixelSize(11);
            pf.setWeight(QFont::ExtraBold);
            const QString tag = u("使用中");
            const qreal pw = QFontMetricsF(pf).horizontalAdvance(tag) + 16;
            const QRectF pill(left + QFontMetricsF(nf).horizontalAdvance(name) + 8, y + 0.5, pw, 17);
            QPainterPath pp;
            pp.moveTo(pill.left() + 4, pill.top());
            pp.lineTo(pill.right(), pill.top());
            pp.lineTo(pill.right() - 4, pill.bottom());
            pp.lineTo(pill.left(), pill.bottom());
            pp.closeSubpath();
            p.fillPath(pp, P.glow);
            p.setFont(pf);
            p.setPen(P.ink);
            p.drawText(pill, Qt::AlignCenter, tag);
        }
        y += 18 + 6;
        p.setRenderHint(QPainter::Antialiasing, false);
        qreal x = left;
        for (const QColor& c : sw) {
            p.fillRect(QRectF(x, y, 18, 8), P.ink);
            p.fillRect(QRectF(x + 1.5, y + 1.5, 15, 5), c);
            x += 16.5;
        }
        p.setRenderHint(QPainter::Antialiasing, true);
        y += 8 + 6;
        QFont df = font();
        df.setPixelSize(11);
        p.setFont(df);
        p.setPen(P.textMuted);
        p.drawText(QRectF(left, y, textW, r.bottom() - y - 4), Qt::TextWordWrap, desc);
    }

    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        if (theme::titan()) {
            paintTitan(p);
            return;
        }
        const bool on = theme::skin() == m_skin;
        // 每套风格自己的舞台底色、一句话说明和五块色板(按那套风格画,与当前风格无关)。
        QColor stageColor;
        QString desc;
        std::array<QColor, 5> sw;
        switch (m_skin) {
        case theme::Skin::Mecha:
            stageColor = QColor(0xE6, 0xE4, 0xDF);
            desc = u("炭黑 + 装甲白 + 赛车橙。切角硬朗,你是指挥官,通知是战报。");
            sw = {QColor(0xEF, 0xED, 0xE8), QColor(0x33, 0x32, 0x2F), QColor(0xFF, 0x6A, 0x13),
                  QColor(0xFF, 0xA2, 0x3A), QColor(0xFF, 0xCF, 0x33)};
            break;
        case theme::Skin::Kawaii:
            stageColor = QColor(0xFF, 0xF1, 0xF5);
            desc = u("可可棕描边 + 粉彩糖果色。大圆角,小垒是你的小伙伴。");
            sw = {QColor(0xFF, 0xFD, 0xF9), QColor(0xFF, 0xB8, 0xCB), QColor(0x7F, 0xE3, 0xC6),
                  QColor(0xFF, 0xD9, 0x6B), QColor(0x4E, 0x41, 0x66)};
            break;
        case theme::Skin::Titan:
            stageColor = QColor(0x0B, 0x14, 0x24);
            desc = u("装甲红 + 钴蓝 + 铬银,暗色屏。平时是一辆小卡车,有事变形出击。");
            sw = {QColor(0xD3, 0x23, 0x2B), QColor(0x24, 0x59, 0xD8), QColor(0xC6, 0xCF, 0xDA),
                  QColor(0xFF, 0xC1, 0x2E), QColor(0x35, 0xD4, 0xFF)};
            break;
        }
        const QColor fill = on ? theme::blend(theme::accent(), theme::surface(), theme::mecha() ? 0.14 : 0.22)
                               : (underMouse() ? theme::surfaceAlt() : theme::surface());
        const QRectF body = sticker::panel(p, QRectF(rect()), fill, 14.0, true);
        if (hasFocus())
            p.strokePath(theme::panelPath(body.adjusted(4, 4, -4, -4), 11.0),
                         QPen(theme::accentDeep(), 1.6, Qt::DashLine));

        const QRectF stage = stageRect();
        const QPainterPath sp = theme::panelPath(stage, 10.0);
        p.fillPath(sp, stageColor);
        p.strokePath(sp, QPen(theme::ink(), 2.0));
        robot::Look look;
        look.mood = robot::Mood::Happy;
        look.pose = robot::Pose::Wave;
        look.shadow = false;
        if (m_wave->isActive()) {
            const qreal t = qreal(motion::clockMs()) / 1000.0;
            look.phase = std::fmod(t / 1.6, 1.0);
            look.pulse = 0.5 + 0.5 * std::sin(t * 2.0 * M_PI / 1.2);
        }
        robot::paintAs(p, stage.adjusted(12, 10, -12, -6), look, m_skin);

        // 三张卡并排时卡片较窄:说明留三行,色板跟着可用宽度缩。
        const qreal tx = stage.right() + 16;
        const qreal textW = body.right() - tx - 14;
        sticker::stickerText(p, QPointF(tx - 4, body.top() + 10), theme::skinName(m_skin), 24.0);
        QFont f = font();
        f.setPointSizeF(9.0);
        f.setWeight(QFont::DemiBold);
        p.setFont(f);
        p.setPen(theme::textSecondary());
        p.drawText(QRectF(tx, body.top() + 52, textW, 56), Qt::TextWordWrap, desc);
        const qreal chipW = qBound<qreal>(14.0, (textW - 4 * 6) / 5.0, 26.0);
        qreal x = tx;
        for (const QColor& c : sw) {
            const QRectF chip(x, body.top() + 112, chipW, 18);
            p.setPen(QPen(theme::ink(), 2.0));
            p.setBrush(c);
            if (theme::mecha())
                p.drawRect(chip);
            else
                p.drawRoundedRect(chip, 6, 6);
            x += chipW + 6;
        }
        if (on)
            sticker::stamp(p, QPointF(body.right() - 52, body.bottom() - 24), u("使用中"), theme::accentDeep(), -8.0, 13.0);
        else if (underMouse())
            sticker::stamp(p, QPointF(body.right() - 56, body.bottom() - 24), u("点我换装"), theme::textSecondary(), -6.0, 12.0);
    }
    void enterEvent(QEnterEvent* e) override
    {
        QAbstractButton::enterEvent(e);
        m_wave->setActive(true);
        update();
    }
    void leaveEvent(QEvent* e) override
    {
        QAbstractButton::leaveEvent(e);
        m_wave->setActive(false);
        update();
    }
    void hideEvent(QHideEvent* e) override
    {
        QAbstractButton::hideEvent(e);
        m_wave->setActive(false);
    }

private:
    QRectF stageRect() const
    {
        if (theme::titan())
            return QRectF(9, 9, width() - 18, 78);
        const QRectF body = sticker::bodyRect(QRectF(rect()), true);
        return QRectF(body.left() + 14, body.top() + 14, qBound<qreal>(92.0, body.width() * 0.36, 124.0),
                      body.height() - 28);
    }

    theme::Skin m_skin;
    motion::Ticker* m_wave = nullptr;
};

void replaceServer(McpManager* mcp, const McpServerConfig& c)
{
    QList<McpServerConfig> all = mcp->servers();
    for (McpServerConfig& s : all)
        if (s.id == c.id)
            s = c;
    mcp->setServers(all);
}

struct McpList {
    bool modal = false;
    bool dirty = false;
    std::function<void()> rebuild;
    QWidget* page = nullptr;

    void request()
    {
        if (modal) {
            dirty = true;
            return;
        }
        rebuild();
    }
    template <typename Fn>
    void withModal(Fn fn)
    {
        modal = true;
        fn();
        modal = false;
        if (dirty) {
            dirty = false;
            QTimer::singleShot(0, page, rebuild);
        }
    }
};

QWidget* mcpRow(McpManager* mcp, const McpServerConfig& c, QWidget* page, const std::shared_ptr<McpList>& ml)
{
    if (theme::titan()) {
        // 金刚:紧凑的一行。名字 + 状态 + 「自动批准」,下面一行等宽的命令 / 地址;
        // 编辑、测试连接、删除收进「更多」菜单,右边只留启用开关。
        const McpManager::Status st = mcp->status(c.id);
        QString pillText = u("未连接");
        QColor pillColor = theme::textMuted();
        if (!c.enabled) {
            pillText = u("已停用");
        } else {
            switch (st.kind) {
            case McpManager::Status::Kind::Busy:  pillText = u("连接中"); pillColor = theme::accent(); break;
            case McpManager::Status::Kind::Ok:    pillText = u("正常"); pillColor = theme::success(); break;
            case McpManager::Status::Kind::Error: pillText = u("连接失败"); pillColor = theme::danger(); break;
            case McpManager::Status::Kind::Unknown: break;
            }
        }
        auto* row = new TitanListRow;
        auto* rv = new QVBoxLayout(row);
        rv->setContentsMargins(kTitanPadL, 8, kTitanPadR - 3, 7);
        rv->setSpacing(4);
        auto* top = new QHBoxLayout;
        top->setSpacing(8);
        auto* tc = new QVBoxLayout;
        tc->setSpacing(2);
        auto* head = new QHBoxLayout;
        head->setSpacing(7);
        auto* name = ui::elided(c.name, "title");
        name->setStyleSheet(QStringLiteral("font-size:9.75pt;"));
        head->addWidget(name);
        head->addWidget(ui::pill(pillText, pillColor));
        if (c.autoApprove)
            head->addWidget(ui::pill(u("自动批准"), theme::warning()));
        head->addStretch(1);
        tc->addLayout(head);
        auto* summary = ui::elided((c.isStdio() ? u("stdio · ") : u("HTTP · ")) + c.summary(), "mono");
        summary->setStyleSheet(QStringLiteral("font-size:8.25pt; color:%1;").arg(theme::pal().textMuted.name()));
        summary->setToolTip(c.summary());
        tc->addWidget(summary);
        top->addLayout(tc, 1);

        auto* menu = new QMenu(row);
        // 菜单项排队执行:测试连接会立刻触发列表重建,不能在菜单自己的事件处理里把这一行连同菜单一起拆掉。
        const auto item = [menu, page](const QString& text, std::function<void()> fn) {
            QAction* a = menu->addAction(text);
            QObject::connect(a, &QAction::triggered, page, std::move(fn), Qt::QueuedConnection);
            return a;
        };
        item(u("编辑"), [mcp, c, page, ml] {
            ml->withModal([&] {
                if (const auto edited = mcpui::editServer(page, mcp, c, false))
                    replaceServer(mcp, *edited);
            });
        });
        QAction* test = item(u("测试连接"), [mcp, c] { mcp->test(c, {}); });
        test->setEnabled(st.kind != McpManager::Status::Kind::Busy);
        menu->addSeparator();
        item(u("删除"), [mcp, c, page, ml] {
            ml->withModal([&] {
                ui::ConfirmSpec spec;
                spec.risk = ui::Risk::Caution;
                spec.title = u("删除 MCP 服务器");
                spec.summary = u("删除后 AI 不再能调用这台服务器的工具;正在运行的连接会立即断开。");
                spec.subjectLabel = u("服务器");
                spec.subject = c.name + u("\n") + c.summary();
                spec.confirmText = u("删除");
                if (!ui::confirm(page, spec))
                    return;
                QList<McpServerConfig> all = mcp->servers();
                all.erase(std::remove_if(all.begin(), all.end(),
                                         [&c](const McpServerConfig& s) { return s.id == c.id; }),
                          all.end());
                mcp->setServers(all);
            });
        });
        auto* more = ui::moreButton(menu, u("更多操作 ") + c.name);
        top->addWidget(more, 0, Qt::AlignVCenter);
        auto* sw = new ToggleSwitch(c.enabled);
        sw->setAccessibleName(u("启用 MCP 服务器 ") + c.name);
        top->addWidget(sw, 0, Qt::AlignVCenter);
        rv->addLayout(top);

        if (st.kind != McpManager::Status::Kind::Unknown && !st.text.isEmpty()) {
            auto* line = ui::label(st.text, "secondary");
            line->setWordWrap(true);
            line->setTextInteractionFlags(Qt::TextSelectableByMouse);
            line->setStyleSheet(st.kind == McpManager::Status::Kind::Error
                                    ? QStringLiteral("font-size:8.6pt; color:%1;").arg(theme::danger().name())
                                    : QStringLiteral("font-size:8.6pt;"));
            rv->addWidget(line);
        }

        const QString id = c.id;
        QObject::connect(sw, &QAbstractButton::toggled, page, [mcp, id](bool on) {
            for (McpServerConfig s : mcp->servers())
                if (s.id == id) {
                    s.enabled = on;
                    replaceServer(mcp, s);
                    return;
                }
        });
        return row;
    }

    const QColor hue = theme::purple();
    auto* card = ui::cardAlt();
    auto* cv = new QVBoxLayout(card);
    cv->setContentsMargins(14, 10, 14, 10);
    cv->setSpacing(6);
    auto* top = new QHBoxLayout;
    top->setSpacing(12);
    top->addWidget(new IconTile(c.isStdio() ? QStringLiteral("terminal") : QStringLiteral("globe"), hue, 30, 15), 0,
                   Qt::AlignVCenter);
    auto* tc = new QVBoxLayout;
    tc->setSpacing(1);
    tc->addWidget(ui::label(c.name, "title"));
    auto* summary = ui::elided((c.isStdio() ? u("stdio · ") : u("HTTP · ")) + c.summary(), "muted");
    summary->setToolTip(c.summary());
    tc->addWidget(summary);
    top->addLayout(tc, 1);

    const McpManager::Status st = mcp->status(c.id);
    QString pillText = u("未连接");
    QColor pillColor = theme::textMuted();
    if (!c.enabled) {
        pillText = u("已停用");
    } else {
        switch (st.kind) {
        case McpManager::Status::Kind::Busy:  pillText = u("连接中"); pillColor = theme::accent(); break;
        case McpManager::Status::Kind::Ok:    pillText = u("正常"); pillColor = theme::success(); break;
        case McpManager::Status::Kind::Error: pillText = u("连接失败"); pillColor = theme::danger(); break;
        case McpManager::Status::Kind::Unknown: break;
        }
    }
    top->addWidget(ui::pill(pillText, pillColor), 0, Qt::AlignVCenter);
    if (c.autoApprove)
        top->addWidget(ui::pill(u("自动批准"), theme::warning()), 0, Qt::AlignVCenter);
    auto* sw = new ToggleSwitch(c.enabled);
    sw->setAccessibleName(u("启用 MCP 服务器 ") + c.name);
    top->addWidget(sw, 0, Qt::AlignVCenter);
    cv->addLayout(top);

    if (st.kind != McpManager::Status::Kind::Unknown && !st.text.isEmpty()) {
        auto* line = ui::label(st.text, "secondary");
        line->setWordWrap(true);
        line->setContentsMargins(42, 0, 0, 0);
        line->setTextInteractionFlags(Qt::TextSelectableByMouse);
        if (st.kind == McpManager::Status::Kind::Error)
            line->setStyleSheet(QStringLiteral("color:%1;").arg(theme::danger().name()));
        cv->addWidget(line);
    }

    auto* btns = new QHBoxLayout;
    btns->setContentsMargins(42, 0, 0, 0);
    btns->setSpacing(8);
    auto* edit = ui::button(u("编辑"), "ghost", QString(), true);
    auto* test = ui::button(u("测试连接"), "ghost", QString(), true);
    auto* del = ui::button(u("删除"), "ghost", QStringLiteral("trash"), true);
    edit->setAccessibleName(u("编辑 ") + c.name);
    test->setAccessibleName(u("测试连接 ") + c.name);
    del->setAccessibleName(u("删除 ") + c.name);
    test->setEnabled(st.kind != McpManager::Status::Kind::Busy);
    btns->addWidget(edit);
    btns->addWidget(test);
    btns->addWidget(del);
    btns->addStretch();
    cv->addLayout(btns);

    const QString id = c.id;
    QObject::connect(sw, &QAbstractButton::toggled, page, [mcp, id](bool on) {
        for (McpServerConfig s : mcp->servers())
            if (s.id == id) {
                s.enabled = on;
                replaceServer(mcp, s);
                return;
            }
    });
    QObject::connect(edit, &QPushButton::clicked, page, [mcp, c, page, ml] {
        ml->withModal([&] {
            if (const auto edited = mcpui::editServer(page, mcp, c, false))
                replaceServer(mcp, *edited);
        });
    });
    QObject::connect(test, &QPushButton::clicked, page, [mcp, c] { mcp->test(c, {}); });
    QObject::connect(del, &QPushButton::clicked, page, [mcp, c, page, ml] {
        ml->withModal([&] {
            ui::ConfirmSpec spec;
            spec.risk = ui::Risk::Caution;
            spec.title = u("删除 MCP 服务器");
            spec.summary = u("删除后 AI 不再能调用这台服务器的工具;正在运行的连接会立即断开。");
            spec.subjectLabel = u("服务器");
            spec.subject = c.name + u("\n") + c.summary();
            spec.confirmText = u("删除");
            if (!ui::confirm(page, spec))
                return;
            QList<McpServerConfig> all = mcp->servers();
            all.erase(std::remove_if(all.begin(), all.end(),
                                     [&c](const McpServerConfig& s) { return s.id == c.id; }),
                      all.end());
            mcp->setServers(all);
        });
    });
    return card;
}

}

QWidget* pages::settings(IpcClient* ipc)
{
    auto st = std::make_shared<State>();
    auto* page = new QWidget;
    auto* outer = new QVBoxLayout(page);
    outer->setContentsMargins(theme::metric::pagePad, 12, theme::metric::pagePad, 0);
    outer->setSpacing(12);

    st->strip = new StatusStrip;
    outer->addWidget(st->strip);

    // 金刚按设计稿排版:左边一块导航面板,右边的分区面板分两列(防护类在左,维度 / 目录 / MCP / 外观在右)。
    // 另外两套皮肤仍是单列大卡片。
    const bool titan = theme::titan();
    if (titan)
        outer->setContentsMargins(theme::metric::pagePad, 10, theme::metric::pagePad, 16);

    auto* cols = new QHBoxLayout;
    cols->setSpacing(titan ? 14 : 18);
    outer->addLayout(cols, 1);

    QWidget* navHost = titan ? static_cast<QWidget*>(ui::card()) : new QWidget;
    navHost->setFixedWidth(titan ? 176 : 196);
    auto* navCol = new QVBoxLayout(navHost);
    if (titan)
        navCol->setContentsMargins(7, 10, 7, 9);
    else
        navCol->setContentsMargins(0, 2, 0, 0);
    navCol->setSpacing(2);
    auto* group = new QButtonGroup(page);
    group->setExclusive(true);
    cols->addWidget(navHost, 0);

    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->viewport()->setAutoFillBackground(false);
    auto* content = new QWidget;
    auto* v = new QVBoxLayout(content);
    QVBoxLayout* colA = nullptr;
    QVBoxLayout* colB = nullptr;
    if (titan) {
        v->setContentsMargins(0, 0, 6, 2);
        v->setSpacing(0);
        auto* mason = new QHBoxLayout;
        mason->setSpacing(12);
        for (QVBoxLayout** col : {&colA, &colB}) {
            auto* host = new QWidget;
            host->setMinimumWidth(0);
            host->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
            *col = new QVBoxLayout(host);
            (*col)->setContentsMargins(0, 0, 0, 0);
            (*col)->setSpacing(12);
            mason->addWidget(host, 1);
        }
        v->addLayout(mason);

        // 两列的宿主不向外报最小宽度(否则撑出横向溢出),窗口一窄卡片就被挤坏。
        // 所以自己量:两列并排放不下时改成一列往下排。
        QWidget* port = scroll->viewport();
        const auto reflow = [mason, v, port, colA, colB] {
            const QMargins m = v->contentsMargins();
            // 两列等宽,所以按较宽那列的最小宽度算两份。
            const int need =
                2 * qMax(colA->minimumSize().width(), colB->minimumSize().width()) + mason->spacing();
            const bool stack = port->width() - m.left() - m.right() < need;
            const QBoxLayout::Direction dir = stack ? QBoxLayout::TopToBottom : QBoxLayout::LeftToRight;
            if (mason->direction() == dir)
                return;
            mason->setDirection(dir);
            mason->setStretch(0, stack ? 0 : 1);
            mason->setStretch(1, stack ? 0 : 1);
        };
        // 视口变宽窄时判断一次;卡片的最小宽度要等样式生效后才准,所以内容重新排版时也判断一次。
        ui::onResize(port, reflow);
        ui::onResize(content, reflow);
    } else {
        v->setContentsMargins(0, 0, 8, theme::metric::pagePad);
        v->setSpacing(16);
    }
    cols->addWidget(scroll, 1);

    struct Sec {
        QString key;
        QWidget* card;
        QAbstractButton* nav;
    };
    auto sections = std::make_shared<QList<Sec>>();
    const auto addSection = [&](const QString& key, const QString& icon, const QString& title, const QString& lead) {
        QColor hue = identity::settingsSection(key);
        if (titan) {
            // 金刚的分区色按设计稿:总控用屏幕发光色,目录青、AI 琥珀、外观粉,其余与另两套皮肤一致。
            const theme::Palette& P = theme::pal();
            if (key == QLatin1String("protection"))
                hue = P.glow;
            else if (key == QLatin1String("ransom"))
                hue = P.cyan;
            else if (key == QLatin1String("ai"))
                hue = P.amber;
            else if (key == QLatin1String("appearance"))
                hue = P.pink;
        }
        QWidget* card = nullptr;
        QVBoxLayout* box = sectionCard(&card, icon, hue, title, lead, sectionTag(key));
        QAbstractButton* nb = nullptr;
        if (titan) {
            static const QStringList left{QStringLiteral("protection"), QStringLiteral("decision"),
                                          QStringLiteral("ai"), QStringLiteral("about")};
            (left.contains(key) ? colA : colB)->addWidget(card);
            static const QHash<QString, QString> navIcons{{QStringLiteral("dims"), QStringLiteral("sliders")},
                                                          {QStringLiteral("decision"), QStringLiteral("target")},
                                                          {QStringLiteral("ransom"), QStringLiteral("folder")},
                                                          {QStringLiteral("mcp"), QStringLiteral("link")}};
            nb = new TitanNavItem(navIcons.value(key, icon), key == QLatin1String("ransom") ? u("受保护目录") : title, hue);
        } else {
            v->addWidget(card);
            auto* b = new NavButton(icon, title);
            b->setIdentity(hue);
            nb = b;
        }
        nb->setCheckable(true);
        group->addButton(nb);
        navCol->addWidget(nb);
        sections->append({key, card, nb});
        return box;
    };
    const auto toggle = [st](bool on, bool RuntimeSettings::*field) {
        auto* sw = new ToggleSwitch(on);
        st->toggles.append({sw, field});
        st->controls << sw;
        return sw;
    };

    // 分组顺序:防护类在前,只影响长相和提醒方式的「外观与通知」放在后面(「关于」之前)。
    QVBoxLayout* s = addSection(QStringLiteral("protection"), QStringLiteral("shield"), u("防护总控"), QString());
    ToggleSwitch* protection = toggle(true, &RuntimeSettings::protectionEnabled);
    settingRow(s, u("实时防护"), u("监控并拦截敏感系统行为。关闭后系统不受本软件保护。"),
               protection, true);
    ToggleSwitch* followsUi = toggle(false, &RuntimeSettings::protectionFollowsUi);
    followsUi->setCaution(true);
    settingRow(s, u("退出界面即停止防护"),
               u("开启后防护只在本程序运行时生效:退出界面即停止事件监控与处置,并卸载内核驱动;"
                 "再打开界面即恢复。最小化到托盘算运行中。"
                 "代价是界面没在跑的时段(开机到登录、注销后、界面被结束后)主机不受本软件保护"),
               followsUi);
    settingRow(s, u("默认拦截未知行为"), u("灰区行为无匹配规则时默认拦截(更严格)"),
               toggle(false, &RuntimeSettings::defaultBlock));
    settingRow(s, u("软件安装管控"),
               u("检测到软件安装程序(安装包 / Setup / MSI)运行时,在右下角弹窗询问是否允许安装,"
                 "可勾选「记住」。默认关闭;开启后对带正规签名的安装包同样会先询问一次"),
               toggle(false, &RuntimeSettings::installControlEnabled));
    st->timeout = new QSpinBox;
    st->timeout->setRange(5, 300);
    st->timeout->setValue(30);
    st->timeout->setSuffix(u(" 秒"));
    if (titan) {
        // 金刚:设计稿里是一个窄窄的数值框,不带上下箭头(仍可直接输入,或用方向键 / 滚轮调整)。
        st->timeout->setButtonSymbols(QAbstractSpinBox::NoButtons);
        st->timeout->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        st->timeout->setStyleSheet(QStringLiteral("QSpinBox { padding: 3px 8px; font-weight: 700; }"));
        st->timeout->setFixedWidth(76);
        st->timeout->setToolTip(u("5 – 300 秒,可直接输入或用方向键调整"));
    } else {
        st->timeout->setFixedWidth(116);
    }
    st->timeout->setAccessibleName(u("弹窗超时"));
    st->controls << st->timeout;
    // 到时的动作见服务端 Worker::resolvePromptByDefault / promptTimeoutShouldBlock,文案要与之一致。
    settingRow(s, u("弹窗超时"),
               u("询问弹窗等你处理的时间。到时没人响应就自动处置:一般是放行;开着上面的「默认拦截未知行为」时一律拦截,"
                 "带硬指标且风险分 ≥ 70 的按下面一项处理。弹窗上的倒计时会写明这一次到时是放行还是拦截"),
               st->timeout);
    settingRow(s, u("高风险询问超时自动拦截"),
               u("带硬指标且风险分 ≥ 70 的询问弹窗,超时无人响应时自动拦截(其余询问仍按上面的默认策略)。"
                 "不会写入内核持久名单;拦截时有明显通知,可在通知上撤销(需再确认一次)。关闭后超时一律按默认策略"),
               toggle(true, &RuntimeSettings::promptTimeoutBlockHighRisk));
    ToggleSwitch* silent = toggle(false, &RuntimeSettings::silentMode);
    silent->setCaution(true);
    settingRow(s, u("静默模式"), u("不弹窗打扰,询问类自动放行,仅拦确定性高危"), silent);

    s = addSection(QStringLiteral("dims"), QStringLiteral("layers"), u("防护维度"),
                   u("每个维度独立开关;关闭某一维度,只停这一类行为的监控与拦截。"));
    {
        struct Dim {
            const char* icon;
            const char* name;
            const char* desc;
            bool RuntimeSettings::*field;
            identity::Kind kind;
        };
        using K = identity::Kind;
        const Dim dims[] = {
            {"activity", "进程防护", "进程创建 / 远程线程注入", &RuntimeSettings::processProtection, K::Injection},
            {"file", "文件防护", "敏感文件写入 / 删除", &RuntimeSettings::fileProtection, K::File},
            {"sliders", "注册表防护", "启动项 / 敏感键值写入", &RuntimeSettings::registryProtection, K::Registry},
            {"shield", "自我保护", "防止防护组件被结束 / 卸载", &RuntimeSettings::selfProtection, K::Protection},
            {"globe", "网络防护", "可疑外联 / C2 通信", &RuntimeSettings::networkProtection, K::Network},
            {"cpu", "内存防护", "反注入内存保护", &RuntimeSettings::memoryProtectionEnabled, K::Module},
        };
        auto* grid = new QGridLayout;
        if (titan) {
            // 金刚:3×2 的小格,一格一个维度(图标块 + 短名 + 开关),顺序按设计稿;完整名称和说明收进悬停提示。
            struct Cell {
                int dim;
                const char* name;
            };
            static const Cell cells[] = {{0, "进程"}, {1, "文件"}, {2, "注册表"}, {4, "网络"}, {3, "自保"}, {5, "内存"}};
            grid->setContentsMargins(0, 0, 0, 8);
            grid->setHorizontalSpacing(6);
            grid->setVerticalSpacing(6);
            int n = 0;
            for (const Cell& c : cells) {
                const Dim& d = dims[c.dim];
                const QColor hue = c.dim == 0 ? theme::pal().fin : c.dim == 3 ? theme::pal().glow : identity::kind(d.kind);
                const QString tip = u("%1:%2").arg(u(d.name), u(d.desc));
                GlowCard* cell = ui::cardAlt();
                cell->setFixedHeight(40);
                cell->setToolTip(tip);
                auto* ch = new QHBoxLayout(cell);
                ch->setContentsMargins(8, 0, 5, 0);
                ch->setSpacing(7);
                ch->addWidget(new IconTile(QString::fromLatin1(d.icon), hue, 26, 14));
                ch->addWidget(titanText(u(c.name), "title", "9.4pt"));
                ch->addStretch(1);
                ToggleSwitch* sw = toggle(true, d.field);
                sw->setAccessibleName(u(d.name));
                sw->setAccessibleDescription(u(d.desc));
                sw->setToolTip(tip);
                ch->addWidget(sw);
                grid->addWidget(cell, n / 3, n % 3);
                grid->setColumnStretch(n % 3, 1);
                ++n;
            }
        } else {
            grid->setHorizontalSpacing(12);
            grid->setVerticalSpacing(12);
            int i = 0;
            for (const Dim& d : dims) {
                const QColor hue = identity::kind(d.kind);
                GlowCard* tile = ui::cardAlt();
                tile->setGlow(hue, QPointF(0.0, 0.0), 0.8, 0.05);
                auto* th = new QHBoxLayout(tile);
                th->setContentsMargins(14, 12, 14, 12);
                th->setSpacing(12);
                th->addWidget(new IconTile(QString::fromLatin1(d.icon), hue, 34, 17), 0, Qt::AlignTop);
                auto* tc = new QVBoxLayout;
                tc->setSpacing(2);
                tc->addWidget(ui::label(u(d.name), "title"));
                auto* dd = ui::label(u(d.desc), "muted");
                dd->setWordWrap(true);
                tc->addWidget(dd);
                th->addLayout(tc, 1);
                ToggleSwitch* sw = toggle(true, d.field);
                sw->setAccessibleName(u(d.name));
                th->addWidget(sw, 0, Qt::AlignTop);
                grid->addWidget(tile, i / 2, i % 2);
                ++i;
            }
        }
        s->addLayout(grid);
    }
    ToggleSwitch* selfProtection = nullptr;
    for (const ToggleBind& b : st->toggles)
        if (b.field == &RuntimeSettings::selfProtection)
            selfProtection = b.sw;

    s = addSection(QStringLiteral("decision"), QStringLiteral("sliders"), u("决策与监控"), QString());
    settingRow(s, u("信任已签名程序"), u("有效签名的程序默认放行、不弹询问(仅拦确定性恶意)"),
               toggle(true, &RuntimeSettings::trustSignedActors), true);
    settingRow(s, u("行为基线"), u("学习程序的正常行为,偏离时记为弱信号"), toggle(true, &RuntimeSettings::behaviorBaselineEnabled));
    settingRow(s, u("勒索诱饵"), u("布放诱饵文件侦测勒索加密"), toggle(true, &RuntimeSettings::ransomwareCanaryEnabled));
    settingRow(s, u("用户态行为监控"), u("无驱动时的持久化 / 勒索监控"),
               toggle(true, &RuntimeSettings::userModeBehaviorMonitor));
    settingRow(s, u("内核驱动"), u("加载 Bulwark.sys 实现事前拦截"), toggle(false, &RuntimeSettings::kernelDriverEnabled));
    {
        auto* startBtn = titan ? ui::button(u("启动服务"), nullptr, QStringLiteral("power"), true)
                               : ui::button(u("启动服务"), "ghost", QStringLiteral("play"), true);
        // 不进 st->controls:服务停了才用得上,连接断开时必须保持可点。
        settingRow(s, u("后台服务"),
                   u("事件汇总、裁决与处置都在这个 Windows 服务里。服务停止后系统不再受保护;"
                     "点这里重新注册并启动服务(需要管理员权限)。已在运行时点它不会打断现有防护。"),
                   startBtn);
        auto* startNote = ui::label(QString(), "secondary");
        startNote->setWordWrap(true);
        startNote->setContentsMargins(titan ? 0 : 42, 2, 0, 6);
        startNote->hide();
        s->addWidget(startNote);

        auto starting = std::make_shared<bool>(false);
        QObject::connect(startBtn, &QPushButton::clicked, page,
                         [startBtn, startNote, starting, page] {
            if (*starting)
                return;
            *starting = true;
            startBtn->setEnabled(false);
            startNote->setStyleSheet(QString());
            startNote->setText(u("正在启动后台服务…(可能会弹出管理员授权提示)"));
            startNote->show();
            using Outcome = bulwark::ui::bootstrap::BackendStartOutcome;
            bulwark::ui::bootstrap::startBackendAsync(
                page, [startBtn, startNote, starting](Outcome outcome, const QString& detail) {
                    *starting = false;
                    startBtn->setEnabled(true);
                    QString text;
                    QString color;
                    switch (outcome) {
                    case Outcome::AlreadyRunning:
                        text = u("后台服务已在运行。");
                        break;
                    case Outcome::Started:
                        text = u("后台服务已启动,防护已恢复运行。");
                        break;
                    case Outcome::Missing:
                        text = u("找不到 bulwark_service.exe,它需要与界面在同一目录。");
                        color = theme::warning().name();
                        break;
                    case Outcome::Refused:
                        text = u("已取消:需要管理员权限才能启动防护服务。");
                        color = theme::warning().name();
                        break;
                    case Outcome::Failed:
                        text = detail.isEmpty()
                                   ? u("后台服务未能启动,详见 %ProgramData%\\Bulwark\\service.log。")
                                   : detail;
                        color = theme::warning().name();
                        break;
                    }
                    startNote->setText(text);
                    startNote->setStyleSheet(color.isEmpty()
                                                 ? QString()
                                                 : QStringLiteral("color:%1;").arg(color));
                    startNote->show();
                });
        });
    }

    ToggleSwitch* guardSw = nullptr;
    s = addSection(QStringLiteral("ransom"), QStringLiteral("lock"), u("受保护目录(反勒索)"),
                   u("名单里的目录只允许【可信写入者】改:Windows 自身、装在 Program Files 下的程序、"
                     "你信任的程序,以及本软件。其余程序对这些目录的写入、新建、删除、重命名会被内核在"
                     "「打开文件」那一步直接拒绝 —— 勒索软件连第一个字节都写不进去。只读不受影响,"
                     "备份软件照常能读。"));
    {
        guardSw = toggle(true, &RuntimeSettings::ransomGuardEnabled);
        settingRow(s, u("受保护目录防护"),
                   u("需要内核驱动。无驱动时降级为「发现后处置」:改写能被看见并结束发起进程,"
                     "但首批文件可能已被加密"),
                   guardSw, true);

        auto* note = ui::label(
            u("默认自动保护:本机用户的 Documents、Pictures,以及 OneDrive/OneDrive-* 下"
              "对应目录(桌面默认不在内,需要可手动添加)。这些目录使用写前拒绝,不依赖事后检测速度；从 AppData 或便携目录运行的正规"
              "软件若被误拦,先把该程序加入信任名单。\n"
              "另有系统基线:注册表配置单元(System32\\config)、引导文件与 BCD、恢复环境(WinRE)、"
              "代码完整性策略、事件日志、卷影副本目录(System Volume Information)—— 这些是勒索与"
              "擦除器一定会动、而正常装软件几乎不会写的地方。\n"
              "刻意【没有】收进 Program Files 与整个 System32:那是安装程序的正当去处,而安装程序多半"
              "从下载目录或临时目录运行,按身份属于「不可信写入者」,收进来会把装软件这件事拦死。\n"
              "下面可以加上你自己要保护的目录(例如资料盘)。某个程序被误拦时,把它加入「信任名单」即可 —— "
              "信任名单里的程序自动成为可信写入者,不需要在这里再配一次。"),
            "muted");
        note->setWordWrap(true);
        if (titan) {
            titanRule(s);
            note->setStyleSheet(QStringLiteral("font-size:8.6pt;"));
            note->setContentsMargins(0, 8, 0, 8);
        } else {
            note->setContentsMargins(0, 4, 0, 0);
        }
        s->addWidget(note);

        static constexpr int kUserDirMax = 48;
        auto* listHost = new QWidget;
        auto* list = new QVBoxLayout(listHost);
        if (titan) {
            // 金刚:一行一个目录的紧凑列表,行线贯通整块面板。
            list->setContentsMargins(0, 0, 0, 0);
            list->setSpacing(0);
            titanBleed(s, listHost);
            titanRule(s);
        } else {
            list->setContentsMargins(0, 8, 0, 4);
            list->setSpacing(6);
            s->addWidget(listHost);
        }

        auto* actions = new QHBoxLayout;
        if (titan)
            actions->setContentsMargins(0, 9, 0, 8);
        else
            actions->setContentsMargins(0, 4, 0, 0);
        actions->setSpacing(titan ? 10 : 8);
        auto* addDir = ui::button(u("添加目录…"), titan ? nullptr : "primary", QStringLiteral("plus"), true);
        actions->addWidget(addDir);
        QLabel* dirCount = nullptr;
        if (titan) {
            dirCount = titanText(QString(), "muted", "8.6pt");
            actions->addWidget(dirCount);
        }
        actions->addStretch();
        s->addLayout(actions);
        st->controls << addDir;

        st->rebuildGuardDirs = [st, list, page, addDir, dirCount, titan] {
            while (QLayoutItem* item = list->takeAt(0)) {
                if (QWidget* w = item->widget())
                    w->deleteLater();
                delete item;
            }
            const QStringList dirs = st->last.ransomGuardDirs;
            if (dirCount)
                dirCount->setText(u("自定义 %1 / %2 个").arg(dirs.size()).arg(kUserDirMax));
            if (dirs.isEmpty()) {
                auto* empty = ui::label(u("还没有添加自定义目录(自动发现的用户数据目录与内置系统目录仍在保护中)。"), "muted");
                empty->setWordWrap(true);
                if (titan) {
                    empty->setStyleSheet(QStringLiteral("font-size:8.6pt;"));
                    empty->setContentsMargins(kTitanPadL, 0, kTitanPadR, 9);
                }
                list->addWidget(empty);
                return;
            }
            for (const QString& dir : dirs) {
                QWidget* row = titan ? static_cast<QWidget*>(new TitanListRow) : new QWidget;
                auto* h = new QHBoxLayout(row);
                QPushButton* del = nullptr;
                if (titan) {
                    row->setFixedHeight(33);
                    h->setContentsMargins(kTitanPadL, 1, kTitanPadR - 4, 0);
                    h->setSpacing(8);
                    auto* ico = new AppIcon(QStringLiteral("folder"));
                    ico->setPx(14);
                    ico->setColor(theme::pal().textMuted);
                    h->addWidget(ico, 0, Qt::AlignVCenter);
                    auto* path = ui::elided(dir, "mono");
                    path->setElideMode(Qt::ElideMiddle);
                    h->addWidget(path, 1);
                    del = ui::button(u("移除"), "ghost", QString(), true);
                    del->setAccessibleName(u("移除 ") + dir);
                } else {
                    h->setContentsMargins(0, 0, 0, 0);
                    h->setSpacing(10);
                    auto* path = ui::label(dir, "mono");
                    path->setWordWrap(true);
                    h->addWidget(path, 1);
                    del = ui::button(u("移除"), "ghost", QStringLiteral("trash"), true);
                }
                del->setEnabled(addDir->isEnabled());
                h->addWidget(del, 0, Qt::AlignVCenter);
                list->addWidget(row);
                QObject::connect(del, &QPushButton::clicked, page, [st, dir, page] {
                    ui::ConfirmSpec c;
                    c.risk = ui::Risk::Caution;
                    c.title = u("不再保护这个目录");
                    c.summary = u("移除后,任何程序都可以写入、删除、重命名这个目录里的文件 —— "
                                 "包括勒索软件。");
                    c.subjectLabel = u("目录");
                    c.subject = dir;
                    c.confirmText = u("移除");
                    if (!ui::confirm(page, c))
                        return;
                    QStringList next = st->last.ransomGuardDirs;
                    next.removeAll(dir);
                    st->last.ransomGuardDirs = next;
                    if (st->rebuildGuardDirs)
                        st->rebuildGuardDirs();
                    if (st->applyNow)
                        st->applyNow();
                });
            }
        };

        QObject::connect(addDir, &QPushButton::clicked, page, [st, page] {
            const QString dir = ui::pickExistingFolder(page, u("选择要保护的目录(只允许可信程序改写)"));
            if (dir.isEmpty())
                return;
            QStringList next = st->last.ransomGuardDirs;
            if (next.contains(dir, Qt::CaseInsensitive)) {
                ui::notify(page, ui::Tone::Info, u("这个目录已经在保护名单里了。"));
                return;
            }
            if (next.size() >= kUserDirMax) {
                ui::notify(page, ui::Tone::Warning,
                           u("自定义目录最多 %1 个(内核名单容量所限)。请先移除不需要的,"
                             "或改用更靠上的父目录合并。").arg(kUserDirMax));
                return;
            }
            next << dir;
            st->last.ransomGuardDirs = next;
            if (st->rebuildGuardDirs)
                st->rebuildGuardDirs();
            if (st->applyNow)
                st->applyNow();
        });
    }

    s = addSection(QStringLiteral("ai"), QStringLiteral("sparkles"), u("AI 辅助"), QString());
    {
        auto* aiHead = new QHBoxLayout;
        aiHead->setContentsMargins(0, 10, 0, 2);
        aiHead->addWidget(titan ? titanText(u("大模型接入"), "title", "9.75pt") : ui::label(u("大模型接入"), "title"));
        aiHead->addStretch();
        st->aiState = ui::pill(u("未配置"), theme::textMuted());
        aiHead->addWidget(st->aiState);
        s->addLayout(aiHead);
        auto* note = ui::label(u("AI 生成规则,以及行为询问、拦截通知与流量的「AI 解读」使用这里的接口。"
                                 "API Key 保存在本机服务端。发给模型的内容包括程序路径、命令行(最多 1500 字)、"
                                 "进程链和证据摘要,其中只掩码了用户名。放行和拦截只由本地引擎和你决定。"), "muted");
        note->setWordWrap(true);
        if (titan)
            note->setStyleSheet(QStringLiteral("font-size:8.6pt;"));
        s->addWidget(note);
        auto* form = new QGridLayout;
        if (titan)
            form->setContentsMargins(0, 8, 0, 10);
        else
            form->setContentsMargins(0, 6, 0, 4);
        form->setHorizontalSpacing(12);
        form->setVerticalSpacing(8);
        const struct {
            const char* label;
            const char* placeholder;
            QString RuntimeSettings::*field;
            bool secret;
        } fields[] = {
            {"接口地址", "https://api.example.com/v1", &RuntimeSettings::aiBaseUrl, false},
            {"API Key", "sk-…", &RuntimeSettings::aiApiKey, true},
            {"模型", "留空 = 服务端默认模型", &RuntimeSettings::aiModel, false},
        };
        int r = 0;
        QLineEdit* edits[3] = {};
        for (const auto& f : fields) {
            form->addWidget(ui::label(u(f.label), "caption"), r, 0);
            auto* e = new QLineEdit;
            e->setPlaceholderText(u(f.placeholder));
            e->setAccessibleName(u(f.label));
            if (f.secret)
                e->setEchoMode(QLineEdit::Password);
            form->addWidget(e, r, 1);
            st->texts.append({e, f.field});
            st->controls << e;
            edits[r] = e;
            ++r;
        }
        auto* test = ui::button(u("测试连接"), titan ? nullptr : "ghost", QString(), true);
        test->setAccessibleName(u("测试大模型连接"));
        auto* result = ui::label(QString(), "muted");
        result->setWordWrap(true);
        result->setTextInteractionFlags(Qt::TextSelectableByMouse);
        auto* testRow = new QHBoxLayout;
        testRow->setSpacing(10);
        testRow->addWidget(test, 0, Qt::AlignVCenter);
        testRow->addWidget(result, 1, Qt::AlignVCenter);
        form->addLayout(testRow, r, 1);
        form->setColumnStretch(1, 1);
        s->addLayout(form);

        AiScanner* ai = ipc->aiScanner();
        QLineEdit* baseEdit = edits[0];
        QLineEdit* keyEdit = edits[1];
        QLineEdit* modelEdit = edits[2];
        QObject::connect(test, &QPushButton::clicked, result, [ai, test, result, baseEdit, keyEdit, modelEdit] {
            test->setEnabled(false);
            result->setStyleSheet(QStringLiteral("color:%1;").arg(theme::textMuted().name()));
            result->setText(u("测试中…"));
            ai->testConnection(baseEdit->text(), keyEdit->text(), modelEdit->text(), result,
                               [test, result](bool ok, const QString& msg) {
                test->setEnabled(true);
                result->setStyleSheet(
                    QStringLiteral("color:%1;").arg((ok ? theme::success() : theme::danger()).name()));
                result->setText(msg);
            });
        });
    }
    {
        AiScanner* ai = ipc->aiScanner();
        auto* explainSw = new ToggleSwitch(ai->promptExplainEnabled());
        explainSw->setAccessibleName(u("行为询问 AI 解读"));
        settingRow(s, u("行为询问 AI 解读"),
                   u("弹出行为询问时,由上面的大模型用一两句话解读这次行为并给出建议,仅供参考:不参与裁决,"
                     "不改变倒计时与默认处置。会把该事件的程序路径、命令行、父进程、目标与检测理由发给大模型接口"
                     "(路径里的本机用户名先替换掉)。解读结果保存在本机一周以便复用,同一行为期间只问一次、"
                     "界面重启后依然有效,到期自动清理。未配置大模型时不生效,只对当前 Windows 用户生效"),
                   explainSw);
        QObject::connect(explainSw, &QAbstractButton::toggled, ai,
                         [ai](bool on) { ai->setPromptExplainEnabled(on); });

        auto* blockSw = new ToggleSwitch(ai->blockExplainEnabled());
        blockSw->setAccessibleName(u("拦截通知 AI 解读"));
        settingRow(s, u("拦截通知 AI 解读"),
                   u("弹出拦截通知时,同样由上面的大模型用一两句话解读被拦下的程序在做什么、为什么危险,并说明"
                     "这次拦截站不站得住(拦得对 / 疑似误拦)。若只做到「仅告警·未拦截」,解读会如实说未拦下,"
                     "并判断这次行为危不危险(确属危险 / 多半无害)。仅供参考:不改变已经做出的处置。发送的内容与上一项相同"
                     "(路径里的本机用户名先替换掉);同一行为一周内只问一次,拦截通知每分钟最多解读 3 条,"
                     "给行为询问留出余量。未配置大模型时不生效,只对当前 Windows 用户生效"),
                   blockSw);
        QObject::connect(blockSw, &QAbstractButton::toggled, ai,
                         [ai](bool on) { ai->setBlockExplainEnabled(on); });
    }

    s = addSection(QStringLiteral("mcp"), QStringLiteral("server"), u("MCP 服务器"),
                   u("接入外部 MCP(Model Context Protocol)服务器。生成 AI 规则建议时,大模型可以调用"
                     "它们的工具,例如查询威胁情报、读取文档。行为询问与拦截通知的「AI 解读」不使用这些工具。"));
    {
        McpManager* mcp = ipc->aiScanner()->mcp();
        auto* note = ui::label(
            u("调用哪个工具、传什么参数由大模型决定:参数发给对应的 MCP 服务器,工具返回的内容发给上面的大模型接口;"
              "默认每次调用前都先问你。本地(stdio)服务器以当前 Windows 用户的身份运行这里填写的命令,只添加你信任的"
              "服务器。服务器在用到时才启动,空闲 5 分钟后断开。配置只保存在当前 Windows 用户的注册表里;"
              "环境变量与请求头中的令牌使用当前用户 DPAPI 加密,不会写成明文。"),
            "muted");
        note->setWordWrap(true);
        if (titan) {
            note->setStyleSheet(QStringLiteral("font-size:8.6pt;"));
            note->setContentsMargins(0, 0, 0, 9);
        }
        s->addWidget(note);
        auto* listHost = new QWidget;
        auto* list = new QVBoxLayout(listHost);
        auto* actions = new QHBoxLayout;
        if (titan) {
            list->setContentsMargins(0, 0, 0, 0);
            list->setSpacing(0);
            titanBleed(s, listHost);
            titanRule(s);
            actions->setContentsMargins(0, 9, 0, 8);
        } else {
            list->setContentsMargins(0, 8, 0, 4);
            list->setSpacing(8);
            s->addWidget(listHost);
            actions->setContentsMargins(0, 4, 0, 0);
        }
        actions->setSpacing(8);
        auto* add = ui::button(u("添加服务器"), titan ? nullptr : "primary", QStringLiteral("plus"), true);
        auto* import = titan ? ui::button(u("从 JSON 导入"), nullptr, QStringLiteral("download"), true)
                             : ui::button(u("从 JSON 导入"), "ghost", QString(), true);
        actions->addWidget(add);
        actions->addWidget(import);
        actions->addStretch();
        s->addLayout(actions);

        auto ml = std::make_shared<McpList>();
        ml->page = page;
        ml->rebuild = [mcp, list, page, weak = std::weak_ptr<McpList>(ml)] {
            const std::shared_ptr<McpList> self = weak.lock();
            if (!self)
                return;
            while (QLayoutItem* item = list->takeAt(0)) {
                if (QWidget* w = item->widget())
                    w->deleteLater();
                delete item;
            }
            const QList<McpServerConfig> servers = mcp->servers();
            if (servers.isEmpty()) {
                auto* empty = ui::label(u("还没有添加 MCP 服务器。"), "muted");
                if (theme::titan()) {
                    empty->setStyleSheet(QStringLiteral("font-size:8.6pt;"));
                    empty->setContentsMargins(kTitanPadL, 0, kTitanPadR, 9);
                }
                list->addWidget(empty);
            }
            for (const McpServerConfig& c : servers)
                list->addWidget(mcpRow(mcp, c, page, self));
        };
        ml->rebuild();
        QObject::connect(mcp, &McpManager::serversChanged, page, [ml] { ml->request(); });
        QObject::connect(mcp, &McpManager::statusChanged, page, [ml] { ml->request(); });
        QObject::connect(add, &QPushButton::clicked, page, [mcp, page, ml] {
            ml->withModal([&] {
                if (const auto c = mcpui::editServer(page, mcp, McpServerConfig{}, true))
                    mcp->setServers(mcp->servers() + QList<McpServerConfig>{*c});
            });
        });
        QObject::connect(import, &QPushButton::clicked, page, [mcp, page, ml] {
            ml->withModal([&] {
                QString note2;
                const QList<McpServerConfig> imported = mcpui::importServers(page, &note2);
                if (imported.isEmpty())
                    return;
                mcp->setServers(mcp->servers() + imported);
                ui::notify(page, note2.isEmpty() ? ui::Tone::Success : ui::Tone::Warning,
                           u("已导入 %1 台 MCP 服务器。").arg(imported.size()) + note2);
            });
        });
    }

    {
        QVBoxLayout* a = addSection(QStringLiteral("appearance"), QStringLiteral("sparkles"), u("外观与通知"),
                                    u("这一组只影响界面长相和提醒方式,不改变防护策略。"
                                      "整个界面就是机器人小垒:窗口是它的机身,弹窗、通知、悬浮窗是它的器件。"
                                      "三套涂装随时切换;切换时界面会重新装配一次,后台防护不中断。"));
        auto* row = new QHBoxLayout;
        row->setSpacing(titan ? 10 : 14);
        if (titan)
            row->setContentsMargins(0, 0, 0, 4);
        for (const theme::Skin sk : {theme::Skin::Mecha, theme::Skin::Kawaii, theme::Skin::Titan}) {
            auto* card = new SkinCard(sk);
            QObject::connect(card, &QAbstractButton::clicked, card, [sk] {
                if (sk != theme::skin())
                    g_returnToSkinCards = true;
                theme::requestSkin(sk);
            });
            row->addWidget(card, 1);
        }
        a->addLayout(row);
        a->addSpacing(6);
        if (ResidentBot* bot = ResidentBot::instance()) {
            auto* sw = new ToggleSwitch(bot->residentEnabled());
            sw->setAccessibleName(u("常驻机器人小垒"));
            settingRow(a, u("常驻机器人小垒"),
                       u("小垒站在任务栏上方值班:拦截、询问时冒气泡,鼠标停在它身上递出指挥终端,"
                         "双击切换雷达流量表,右键有快捷菜单。只对当前 Windows 用户生效"),
                       sw);
            QObject::connect(sw, &QAbstractButton::toggled, bot, [bot](bool on) { bot->setResidentEnabled(on); });
            QObject::connect(bot, &ResidentBot::enabledChanged, sw, [sw](bool on) {
                const QSignalBlocker block(sw);
                sw->setChecked(on);
            });
        }
        {
            VoiceAnnouncer* voice = VoiceAnnouncer::instance();
            auto* voiceSw = new ToggleSwitch(voice->isEnabled());
            voiceSw->setAccessibleName(u("语音播报拦截结果"));
            settingRow(a, u("语音播报拦截结果"),
                       u("拦截通知弹出时念出处置结果(已拦截 / 未能拦截),询问、放行等其它通知不播报。"
                         "不受静默模式影响,只对当前 Windows 用户生效"),
                       voiceSw);
            // 开关开着但念不出来时要给出提示,否则表现为「设置不生效」。
            auto* voiceNote = ui::label(QString(), "secondary");
            voiceNote->setWordWrap(true);
            voiceNote->setStyleSheet(QStringLiteral("color:%1;").arg(theme::warning().name()));
            voiceNote->hide();
            a->addWidget(voiceNote);
            const auto syncVoice = [voice, voiceNote] {
                QString text;
                switch (voice->status()) {
                case VoiceAnnouncer::Status::NoChineseVoice:
                    text = u("本机没有中文语音,播报可能没有声音或念不出中文。可在 Windows「设置 > 时间和语言 > 语音」"
                             "中添加中文(简体)语音。");
                    break;
                case VoiceAnnouncer::Status::Unavailable:
                    text = u("Windows 语音服务(SAPI)无法初始化,暂时无法播报。");
                    break;
                case VoiceAnnouncer::Status::Idle:
                case VoiceAnnouncer::Status::Ready:
                    break;
                }
                voiceNote->setText(text);
                voiceNote->setVisible(!text.isEmpty());
            };
            QObject::connect(voiceSw, &QAbstractButton::toggled, voice, [voice](bool on) { voice->setEnabled(on); });
            QObject::connect(voice, &VoiceAnnouncer::statusChanged, voiceNote, syncVoice);
            syncVoice();
        }
        if (TrafficOverlay* overlay = TrafficOverlay::instance()) {
            auto* trafficSw = new ToggleSwitch(overlay->overlayEnabled());
            trafficSw->setAccessibleName(u("桌面实时流量悬浮窗"));
            settingRow(a, u("桌面实时流量悬浮窗"),
                       u("在桌面右上角显示实时网速和正在联网的软件:双击一行定位文件,右键可结束进程或让 AI 分析。"
                         "只在显示时才让后台服务统计流量,关闭后后台不再采样。只对当前 Windows 用户生效"),
                       trafficSw);
            QObject::connect(trafficSw, &QAbstractButton::toggled, overlay,
                             [overlay](bool on) { overlay->setOverlayEnabled(on); });
            QObject::connect(overlay, &TrafficOverlay::overlayEnabledChanged, trafficSw, [trafficSw](bool on) {
                const QSignalBlocker block(trafficSw);
                trafficSw->setChecked(on);
            });
        }
    }

    s = addSection(QStringLiteral("about"), QStringLiteral("info"), u("关于"), QString());
    {
        settingRow(s, u("当前版本"), QString(), ui::label(bulwark::version::displayString(), "secondary"), true);
    }
    if (titan) {
        colA->addStretch(1);
        colB->addStretch(1);
    }
    v->addStretch(1);
    navCol->addStretch(1);
    if (titan) {
        auto* foot = titanText(u("磐垒主动防御 %1\n界面风格 · %2").arg(bulwark::version::current(),
                                                                    theme::skinName(theme::skin())),
                               "muted", "7.9pt");
        foot->setTextFormat(Qt::PlainText);
        foot->setContentsMargins(5, 0, 0, 0);
        navCol->addWidget(foot);
    }
    scroll->setWidget(content);
    content->setAutoFillBackground(false);

    // 分区面板在滚动内容里的纵向位置。金刚的面板装在两个列容器里,不能直接用 y()。
    const auto cardTop = [content](const QWidget* card) { return card->mapTo(content, QPoint(0, 0)).y(); };
    auto spyLock = std::make_shared<bool>(false);
    const auto scrollTo = [scroll, spyLock, cardTop](QWidget* card) {
        QScrollBar* sb = scroll->verticalScrollBar();
        const int target = std::min(sb->maximum(), std::max(0, cardTop(card) - 4));
        *spyLock = true;
        if (const int ms = motion::duration(220); ms > 0) {
            auto* a = new QPropertyAnimation(sb, "value", sb);
            a->setDuration(ms);
            a->setEasingCurve(QEasingCurve::OutCubic);
            a->setStartValue(sb->value());
            a->setEndValue(target);
            QObject::connect(a, &QPropertyAnimation::finished, sb, [spyLock] { *spyLock = false; });
            a->start(QAbstractAnimation::DeleteWhenStopped);
        } else {
            sb->setValue(target);
            *spyLock = false;
        }
    };
    for (const Sec& sec : std::as_const(*sections))
        QObject::connect(sec.nav, &QAbstractButton::clicked, page,
                         [scrollTo, card = sec.card] { scrollTo(card); });
    QObject::connect(scroll->verticalScrollBar(), &QScrollBar::valueChanged, page,
                     [sections, spyLock, scroll, cardTop, titan](int value) {
        if (*spyLock || sections->isEmpty())
            return;
        const Sec* current = &sections->first();
        if (titan) {
            // 两列并排时分区的先后顺序不等于上下顺序:取已经滚到顶部附近的面板里最靠下的一块,同高时取靠前的。
            int best = -1;
            for (const Sec& sec : std::as_const(*sections)) {
                const int top = cardTop(sec.card);
                if (top <= value + 48 && top > best) {
                    best = top;
                    current = &sec;
                }
            }
        } else {
            for (const Sec& sec : std::as_const(*sections))
                if (cardTop(sec.card) <= value + 48)
                    current = &sec;
        }
        if (value >= scroll->verticalScrollBar()->maximum() - 2)
            current = &sections->last(); // the last card may never reach the top
        current->nav->setChecked(true);
    });
    sections->first().nav->setChecked(true);

    QHBoxLayout* actions = pagekit::headerActions(page);
    st->saveState = ui::label(QString(), "secondary");
    actions->addWidget(st->saveState);

    const auto syncEnabled = [st] {
        const bool usable = st->have && st->connected;
        for (QWidget* w : std::as_const(st->controls))
            w->setEnabled(usable);
        if (!st->connected)
            st->strip->setState(QStringLiteral("server"), theme::textMuted(), u("未连接后台服务"),
                                st->have ? u("下面显示的是上次读到的设置,连接恢复前不能修改。")
                                         : u("连接后台服务后才能读取和修改设置。"));
        else if (!st->have)
            st->strip->setState(QStringLiteral("refresh"), theme::accent(), u("正在读取服务端设置…"),
                                u("读到之前控件保持禁用,免得改动一份看不见的配置。"));
        st->strip->setVisible(!usable);
    };
    const auto load = [st, syncEnabled](const RuntimeSettings& s2) {
        st->loading = true;
        st->last = s2;
        st->have = true;
        for (const ToggleBind& b : std::as_const(st->toggles))
            b.sw->setChecked(s2.*(b.field));
        for (const TextBind& b : std::as_const(st->texts))
            if (!b.edit->hasFocus()) // don't yank text out from under the cursor
                b.edit->setText(s2.*(b.field));
        {
            const QSignalBlocker block(st->timeout);
            st->timeout->setValue(s2.promptTimeoutSeconds);
        }
        ui::stylePill(st->aiState, s2.aiConfigured() ? u("已配置") : u("未配置"),
                      s2.aiConfigured() ? theme::success() : theme::textMuted());
        if (st->rebuildGuardDirs)
            st->rebuildGuardDirs();
        st->loading = false;
        syncEnabled();
    };

    const auto collect = [st]() -> RuntimeSettings {
        RuntimeSettings s2 = st->last;
        for (const ToggleBind& b : std::as_const(st->toggles))
            s2.*(b.field) = b.sw->isChecked();
        for (const TextBind& b : std::as_const(st->texts))
            s2.*(b.field) = b.edit->text().trimmed();
        s2.promptTimeoutSeconds = st->timeout->value();
        return s2;
    };
    const auto apply = [st, ipc, collect, page] {
        if (st->loading || !st->have)
            return;
        if (!ipc->isConnected()) {
            ui::notify(page, ui::Tone::Danger, u("未连接后台服务,改动没有保存。"));
            return;
        }
        const RuntimeSettings s2 = collect();
        st->last = s2;
        st->pendingSave = true;
        const int seq = ++st->saveSeq;
        st->saveState->setStyleSheet(QString());
        st->saveState->setText(u("正在保存…"));
        ipc->updateSettings(s2);
        QTimer::singleShot(6000, st->saveState, [st, seq] {
            if (!st->pendingSave || st->saveSeq != seq)
                return;
            st->pendingSave = false;
            st->saveState->setStyleSheet(QStringLiteral("color:%1;").arg(theme::warning().name()));
            st->saveState->setText(u("没有收到服务确认"));
        });
    };
    st->applyNow = apply;

    for (const ToggleBind& b : std::as_const(st->toggles)) {
        ToggleSwitch* sw = b.sw;
        const bool guarded = sw == protection || sw == selfProtection || sw == guardSw;
        const bool guardedOnEnable = sw == followsUi;
        QObject::connect(sw, &QAbstractButton::toggled, page,
                         [st, sw, field = b.field, guarded, guardedOnEnable, protection, guardSw, page,
                          apply](bool on) {
            if (st->loading)
                return;
            if (guardedOnEnable && on) {
                ui::ConfirmSpec c;
                c.risk = ui::Risk::Caution;
                c.title = u("退出界面即停止防护");
                c.summary = u("开启后,防护只在本程序运行时生效 —— 界面一退出就彻底停止,包括卸载内核驱动。");
                c.consequences
                    << u("界面没在跑的时段主机不受本软件保护:开机到登录之间、注销之后、界面被结束之后")
                    << u("于是「结束 bulwark_ui.exe」这一下就等于关掉整套防护")
                    << u("已隔离的文件和已施加的拦截不会被放回,只是不再做新的处置")
                    << u("最小化到托盘不算退出,防护照常生效");
                c.confirmText = u("开启");
                if (!ui::confirm(page, c)) {
                    st->loading = true;
                    sw->setChecked(false);
                    st->loading = false;
                    return;
                }
            }
            if (guarded && !on) {
                ui::ConfirmSpec c;
                if (sw == protection) {
                    c.risk = ui::Risk::Danger;
                    c.title = u("关闭实时防护");
                    c.summary = u("关闭后,本软件不再监控和拦截任何行为,系统此刻不受保护。");
                    c.consequences << u("规则、信任名单与隔离区会保留,重新打开即恢复")
                                   << u("此前写入文件 DACL 的跨重启拒绝执行 ACE 不会自动移除;需在卸载前加白对应文件或手工清理")
                                   << u("只是想少被打扰,可以改用「静默模式」");
                    c.confirmText = u("关闭实时防护");
                } else if (sw == guardSw) {
                    c.risk = ui::Risk::Caution;
                    c.title = u("关闭受保护目录防护");
                    c.summary = u("关闭后,注册表配置单元、引导文件、恢复环境、事件日志、卷影副本目录"
                                 "以及你自己添加的目录,都不再限制谁能写入。");
                    c.consequences
                        << u("勒索软件对这些目录的加密与删除不再被拦下 —— 这一维拦的正是「打开文件、"
                             "从头覆写密文、同名保存」那条最常见的加密路径,其它防护拦不住它")
                        << u("你添加的目录列表会保留,重新打开即恢复")
                        << u("若是因为某个程序被误拦,更好的做法是把那个程序加入「信任名单」,"
                             "而不是关掉整维防护");
                    c.confirmText = u("关闭");
                } else {
                    c.risk = ui::Risk::Caution;
                    c.title = u("关闭自我保护");
                    c.summary = u("关闭后,防护组件可以被其它程序结束或卸载 —— 恶意程序常先做这一步。");
                    c.consequences << u("需要卸载或排查本软件时再关,完成后记得打开");
                    c.confirmText = u("关闭自我保护");
                }
                if (!ui::confirm(page, c)) {
                    st->loading = true;
                    sw->setChecked(true);
                    st->loading = false;
                    return;
                }
            }
            if (const std::optional<ui::ConfirmSpec> c = weakeningConfirm(field, on); c && !ui::confirm(page, *c)) {
                st->loading = true;
                sw->setChecked(!on);
                st->loading = false;
                return;
            }
            apply();
        });
    }
    auto* timeoutDebounce = new QTimer(page);
    timeoutDebounce->setSingleShot(true);
    timeoutDebounce->setInterval(450);
    QObject::connect(timeoutDebounce, &QTimer::timeout, page, [apply] { apply(); });
    QObject::connect(st->timeout, &QSpinBox::valueChanged, page, [timeoutDebounce] { timeoutDebounce->start(); });

    for (const TextBind& b : std::as_const(st->texts))
        QObject::connect(b.edit, &QLineEdit::editingFinished, page, [st, apply, edit = b.edit, field = b.field] {
            if (st->have && st->last.*field == edit->text().trimmed())
                return;
            apply();
        });

    QObject::connect(ipc, &IpcClient::settingsReceived, page, [st, load](const RuntimeSettings& s2) {
        load(s2);
        if (st->pendingSave) {
            st->pendingSave = false;
            st->saveState->setStyleSheet(QStringLiteral("color:%1;").arg(theme::success().name()));
            st->saveState->setText(u("已保存 ✓"));
            const int seq = st->saveSeq;
            QTimer::singleShot(2500, st->saveState, [st, seq] {
                if (st->saveSeq == seq && !st->pendingSave)
                    st->saveState->clear();
            });
        }
    });
    QObject::connect(ipc, &IpcClient::connectionChanged, page, [st, ipc, syncEnabled](bool c) {
        st->connected = c;
        syncEnabled();
        if (c)
            ipc->requestSettings();
    });
    st->connected = ipc->isConnected();
    syncEnabled();
    if (st->connected)
        ipc->requestSettings();

    nav::onArrive(page, QString::fromLatin1(nav::Settings), [sections, scrollTo](const QVariantMap& args) {
        QString key = args.value(QStringLiteral("section")).toString();
        if (key.isEmpty() && g_returnToSkinCards)
            key = QStringLiteral("appearance");
        g_returnToSkinCards = false;
        for (const Sec& sec : std::as_const(*sections))
            if (sec.key == key) {
                sec.nav->setChecked(true);
                QTimer::singleShot(0, sec.card, [scrollTo, card = sec.card] { scrollTo(card); });
            }
    });
    return page;
}
