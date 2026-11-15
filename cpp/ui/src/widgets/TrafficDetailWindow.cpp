#include "widgets/TrafficDetailWindow.h"

#include "bulwark/models/SecurityEvent.h"
#include "design/Backdrop.h"
#include "design/Components.h"
#include "design/Format.h"
#include "design/Theme.h"
#include "dialogs/EventFormat.h"
#include "ipc/IpcClient.h"
#include "widgets/ElidingLabel.h"
#include "widgets/FileIconSafe.h"
#include "widgets/TrafficOverlay.h"

#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMenu>
#include <QPushButton>
#include <QSet>
#include <QTimer>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>

using evtfmt::u;
using bulwark::ipc::NetTrafficConnPayload;
using bulwark::ipc::NetTrafficRowPayload;
using bulwark::ipc::NetTrafficSnapshotPayload;

namespace {

constexpr int kHistoryMinutes = 30;

constexpr int kSortRole = Qt::UserRole + 1;

class SortItem : public QTreeWidgetItem
{
public:
    using QTreeWidgetItem::QTreeWidgetItem;
    bool operator<(const QTreeWidgetItem& other) const override
    {
        const int col = treeWidget() ? treeWidget()->sortColumn() : 0;
        const QVariant a = data(col, kSortRole), b = other.data(col, kSortRole);
        if (a.isValid() && b.isValid())
            return a.toLongLong() < b.toLongLong();
        return text(col).compare(other.text(col), Qt::CaseInsensitive) < 0;
    }
};

enum ConnCol { CProto, CRemote, CDomain, CScope, CDown, CUp, CDownTot, CUpTot, CAge, CState, CConnCount };
enum FileCol { FTime, FPath, FKind, FVerdict, FFileCount };
enum EvCol { ETime, EType, ETarget, EVerdict, EEvCount };

QString rateText(qint64 bps)
{
    if (bps <= 0)
        return QStringLiteral("—");
    static const char* const units[] = {"B/s", "KB/s", "MB/s", "GB/s"};
    double v = double(bps);
    int i = 0;
    while (v >= 1024.0 && i < 3) {
        v /= 1024.0;
        ++i;
    }
    const QString num = (i == 0 || v >= 100.0) ? QString::number(qRound(v))
                        : v >= 10.0            ? QString::number(v, 'f', 1)
                                               : QString::number(v, 'f', 2);
    return num + QLatin1Char(' ') + QString::fromLatin1(units[i]);
}

QString durationText(qint64 secs)
{
    if (secs < 60)
        return u("%1 秒").arg(std::max<qint64>(0, secs));
    if (secs < 3600)
        return u("%1 分钟").arg(secs / 60);
    return u("%1 小时 %2 分").arg(secs / 3600).arg((secs % 3600) / 60);
}

QString endpoint(const NetTrafficConnPayload& c)
{
    return c.remoteIp.contains(QLatin1Char(':')) ? QStringLiteral("[%1]:%2").arg(c.remoteIp).arg(c.remotePort)
                                                 : QStringLiteral("%1:%2").arg(c.remoteIp).arg(c.remotePort);
}

QString portHint(const NetTrafficConnPayload& c)
{
    const bool udp = c.proto == QLatin1String("UDP");
    switch (c.remotePort) {
    case 443: return udp ? u("HTTPS(QUIC)") : u("HTTPS");
    case 80:  return u("HTTP");
    case 53:  return u("DNS");
    case 853: return u("DNS over TLS");
    case 123: return udp ? u("时间同步(NTP)") : QString();
    case 22:  return u("SSH");
    case 3389: return u("远程桌面");
    case 445: return u("文件共享(SMB)");
    case 25: case 465: case 587: return u("发邮件(SMTP)");
    case 993: case 143: return u("收邮件(IMAP)");
    case 1900: return udp ? u("局域网设备发现(SSDP)") : QString();
    case 5353: return udp ? u("局域网设备发现(mDNS)") : QString();
    default: break;
    }
    return QString();
}

QString fileKind(const QString& path, QColor* color)
{
    const QString ext = QFileInfo(path).suffix().toLower();
    static const QSet<QString> exe = {QStringLiteral("exe"), QStringLiteral("dll"), QStringLiteral("sys"),
                                      QStringLiteral("scr"), QStringLiteral("msi"), QStringLiteral("com"),
                                      QStringLiteral("cpl"), QStringLiteral("ocx")};
    static const QSet<QString> script = {QStringLiteral("ps1"), QStringLiteral("bat"), QStringLiteral("cmd"),
                                         QStringLiteral("vbs"), QStringLiteral("js"), QStringLiteral("jse"),
                                         QStringLiteral("wsf"), QStringLiteral("hta"), QStringLiteral("lnk")};
    static const QSet<QString> archive = {QStringLiteral("zip"), QStringLiteral("rar"), QStringLiteral("7z"),
                                          QStringLiteral("cab"), QStringLiteral("iso"), QStringLiteral("img"),
                                          QStringLiteral("tar"), QStringLiteral("gz")};
    if (exe.contains(ext)) {
        *color = theme::danger();
        return u("可执行文件");
    }
    if (script.contains(ext)) {
        *color = theme::warning();
        return u("脚本 / 快捷方式");
    }
    if (archive.contains(ext)) {
        *color = theme::warning();
        return u("压缩包 / 镜像");
    }
    *color = theme::textSecondary();
    return ext.isEmpty() ? u("文件") : ext.toUpper();
}

QTreeWidget* makeTree(const QStringList& headers)
{
    auto* t = new QTreeWidget;
    t->setObjectName(QStringLiteral("ProcessTree"));
    t->setStyleSheet(QStringLiteral("QTreeView#ProcessTree::item { min-height: 26px; padding: 0px 6px; }"));
    t->setColumnCount(headers.size());
    t->setHeaderLabels(headers);
    t->setRootIsDecorated(false);
    t->setUniformRowHeights(true);
    t->setAlternatingRowColors(true);
    t->setSelectionMode(QAbstractItemView::SingleSelection);
    t->setTextElideMode(Qt::ElideMiddle);
    t->header()->setStretchLastSection(false);
    t->header()->setSectionsMovable(false);
    return t;
}

QWidget* statBlock(const QString& caption, QLabel** value, QLabel** captionOut = nullptr)
{
    auto* w = new QWidget;
    auto* v = new QVBoxLayout(w);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(2);
    QLabel* c = ui::label(caption, "caption");
    v->addWidget(c);
    *value = ui::label(QStringLiteral("—"), "title");
    (*value)->setTextInteractionFlags(Qt::TextSelectableByMouse);
    v->addWidget(*value);
    if (captionOut)
        *captionOut = c;
    return w;
}

}

TrafficDetailWindow::TrafficDetailWindow(IpcClient* ipc, const NetTrafficRowPayload& row, QWidget* parent)
    : QDialog(parent), m_ipc(ipc), m_pid(row.pid), m_row(row)
{
    setWindowTitle(u("连接详情 · %1").arg(row.name));
    setAccessibleName(windowTitle());
    setWindowFlag(Qt::WindowContextHelpButtonHint, false);
    setWindowFlag(Qt::WindowMinMaxButtonsHint, true);
    Backdrop::install(this);
    resize(1080, 760);
    setMinimumSize(760, 520);
    setSizeGripEnabled(true);

    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(20, 16, 20, 16);
    outer->setSpacing(12);

    {
        auto* head = new QHBoxLayout;
        head->setSpacing(12);
        auto* icon = new QLabel;
        if (!row.path.isEmpty() && QFileInfo::exists(row.path)) {
            const QPixmap pm = fileicon::pixmapForPath(row.path, 32, devicePixelRatioF());
            if (!pm.isNull())
                icon->setPixmap(pm);
        }
        icon->setFixedSize(36, 36);
        icon->setAlignment(Qt::AlignCenter);
        head->addWidget(icon, 0, Qt::AlignTop);
        auto* hc = new QVBoxLayout;
        hc->setSpacing(2);
        hc->addWidget(ui::label(row.name, "h2"));
        auto* sub = ui::elided(u("PID %1 · %2").arg(row.pid).arg(row.path.isEmpty() ? u("(取不到映像路径)")
                                                                                     : QDir::toNativeSeparators(row.path)),
                               "secondary");
        sub->setToolTip(QDir::toNativeSeparators(row.path));
        hc->addWidget(sub);
        head->addLayout(hc, 1);
        auto* locate = ui::button(u("定位文件"), "ghost", QStringLiteral("folder"), true);
        locate->setEnabled(!row.path.isEmpty());
        connect(locate, &QPushButton::clicked, this, [this] {
            if (!TrafficOverlay::locateFile(m_row.path))
                setStatus(u("无法定位:文件已不存在,或资源管理器没能打开。"));
        });
        head->addWidget(locate, 0, Qt::AlignTop);
        outer->addLayout(head);
    }

    {
        auto* card = ui::card();
        auto* g = new QHBoxLayout(card);
        g->setContentsMargins(18, 12, 18, 12);
        g->setSpacing(28);
        g->addWidget(statBlock(u("出网速率 ↓ / ↑"), &m_rateValue));
        g->addWidget(statBlock(u("自开始监控累计 ↓ / ↑"), &m_totalValue));
        g->addWidget(statBlock(u("已建立的 TCP 连接"), &m_connValue));
        g->addWidget(statBlock(u("经本机代理"), &m_proxyValue, &m_proxyCaption));
        g->addStretch();
        outer->addWidget(card);
        m_status = ui::elided(QString(), "muted");
        m_status->setVisible(false);
        outer->addWidget(m_status);
    }

    {
        auto* card = ui::card();
        auto* v = new QVBoxLayout(card);
        v->setContentsMargins(14, 12, 14, 12);
        v->setSpacing(6);
        auto* h = new QHBoxLayout;
        h->addWidget(ui::label(u("连接"), "title"));
        h->addStretch();
        m_connNote = ui::label(u("正在获取连接明细…"), "muted");
        h->addWidget(m_connNote);
        v->addLayout(h);
        m_conns = makeTree({u("协议"), u("对端"), u("域名 / 用途"), u("类型"), u("↓ 速率"), u("↑ 速率"),
                            u("↓ 累计"), u("↑ 累计"), u("持续"), u("状态")});
        m_conns->setSortingEnabled(true);
        m_conns->sortByColumn(CDownTot, Qt::DescendingOrder);
        const int widths[] = {74, 176, 240, 74, 84, 84, 84, 84, 74, 124};
        for (int i = 0; i < CConnCount; ++i)
            m_conns->setColumnWidth(i, widths[i]);
        m_conns->header()->setSectionResizeMode(CDomain, QHeaderView::Stretch);
        m_conns->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(m_conns, &QWidget::customContextMenuRequested, this, &TrafficDetailWindow::connMenu);
        v->addWidget(m_conns, 1);
        outer->addWidget(card, 3);
    }

    {
        auto* row2 = new QHBoxLayout;
        row2->setSpacing(12);

        auto* fileCard = ui::card();
        auto* fv = new QVBoxLayout(fileCard);
        fv->setContentsMargins(14, 12, 14, 12);
        fv->setSpacing(6);
        auto* fh = new QHBoxLayout;
        fh->addWidget(ui::label(u("近 %1 分钟写入的文件").arg(kHistoryMinutes), "title"));
        fh->addStretch();
        m_histNote = ui::label(QString(), "muted");
        fh->addWidget(m_histNote);
        m_refresh = ui::button(u("刷新"), "ghost", QStringLiteral("refresh"), true);
        connect(m_refresh, &QPushButton::clicked, this, &TrafficDetailWindow::requestHistory);
        fh->addWidget(m_refresh);
        fv->addLayout(fh);
        m_files = makeTree({u("时间"), u("文件"), u("类型"), u("处置")});
        m_files->setColumnWidth(FTime, 70);
        m_files->setColumnWidth(FKind, 104);
        m_files->setColumnWidth(FVerdict, 80);
        m_files->header()->setSectionResizeMode(FPath, QHeaderView::Stretch);
        m_files->setToolTip(u("双击定位文件"));
        connect(m_files, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* it, int) {
            const QString path = it ? it->data(FPath, Qt::UserRole).toString() : QString();
            if (!path.isEmpty() && !TrafficOverlay::locateFile(path))
                setStatus(u("无法定位:%1 已不存在(可能是临时文件,已被删除或改名)。")
                                      .arg(QDir::toNativeSeparators(path)));
        });
        fv->addWidget(m_files, 1);
        row2->addWidget(fileCard, 3);

        auto* evCard = ui::card();
        auto* ev = new QVBoxLayout(evCard);
        ev->setContentsMargins(14, 12, 14, 12);
        ev->setSpacing(6);
        ev->addWidget(ui::label(u("近 %1 分钟的其它记录").arg(kHistoryMinutes), "title"));
        m_events = makeTree({u("时间"), u("行为"), u("目标"), u("处置")});
        m_events->setColumnWidth(ETime, 70);
        m_events->setColumnWidth(EType, 96);
        m_events->setColumnWidth(EVerdict, 96);
        m_events->header()->setSectionResizeMode(ETarget, QHeaderView::Stretch);
        ev->addWidget(m_events, 1);
        row2->addWidget(evCard, 2);

        outer->addLayout(row2, 2);
    }

    {
        auto* foot = new QHBoxLayout;
        auto* note = ui::label(
            u("这里能看到的是【元数据】:跟谁连、用什么协议、传了多少字节,以及这个进程写下了哪些文件。"
              "传输的内容看不到 —— 绝大多数流量是 HTTPS 加密的,要解开只能往系统里装根证书做中间人解密,"
              "那会削弱整台电脑的安全,本软件不这么做。域名来自本机的 DNS 应答;经本机代理的连接,"
              "真实目的地址只有代理知道,这里只能看到「连到了代理」。"),
            "muted");
        note->setWordWrap(true);
        foot->addWidget(note, 1);
        auto* close = ui::button(u("关闭"), "primary", QString(), true);
        connect(close, &QPushButton::clicked, this, &QDialog::close);
        foot->addWidget(close, 0, Qt::AlignBottom);
        outer->addLayout(foot);
    }

    updateHeader(&m_row, true);
    if (m_ipc) {
        connect(m_ipc, &IpcClient::netTrafficReceived, this, &TrafficDetailWindow::onSnapshot);
        connect(m_ipc, &IpcClient::timelineReceived, this, &TrafficDetailWindow::onTimeline);
    }
    requestHistory();
}

TrafficDetailWindow::~TrafficDetailWindow() = default;

void TrafficDetailWindow::setStatus(const QString& text)
{
    m_status->setText(text);
    m_status->setVisible(!text.isEmpty());
}

void TrafficDetailWindow::onSnapshot(const NetTrafficSnapshotPayload& snap)
{
    const NetTrafficRowPayload* row = nullptr;
    for (const NetTrafficRowPayload& r : snap.rows) {
        if (r.pid == m_pid) {
            row = &r;
            break;
        }
    }
    if (row)
        m_row = *row;
    updateHeader(row, snap.perProcessAvailable);
    if (snap.connections.contains(m_pid)) {
        m_gotConnections = true;
        updateConnections(snap.connections.value(m_pid));
    } else if (!m_gotConnections) {
        m_connNote->setText(u("正在获取连接明细…(需要后台服务是本版本)"));
    }
}

void TrafficDetailWindow::updateHeader(const NetTrafficRowPayload* row, bool perProcess)
{
    if (!row) {
        setStatus(u("这个进程此刻不在联网列表里:可能已经退出,或者连接都已断开。下面保留最后看到的连接。"));
        m_rateValue->setText(QStringLiteral("—"));
        return;
    }
    if (!perProcess) {
        setStatus(u("逐进程速率不可用(流量 ETW 会话没有运行),只能显示连接。"));
        m_rateValue->setText(QStringLiteral("—"));
    } else {
        setStatus(QString());
        m_rateValue->setText(u("%1  /  %2").arg(rateText(row->downBps), rateText(row->upBps)));
    }
    m_totalValue->setText(u("%1  /  %2").arg(fmt::bytes(row->downTotal), fmt::bytes(row->upTotal)));
    m_connValue->setText(QString::number(row->tcpConns));
    if (row->proxyName.isEmpty()) {
        m_proxyCaption->setText(u("经本机代理"));
        m_proxyValue->setText(u("否"));
        m_proxyValue->setToolTip(QString());
    } else {
        m_proxyCaption->setText(u("经本机代理 %1").arg(row->proxyName));
        m_proxyValue->setText(perProcess ? u("%1 连接 · %2 / %3")
                                               .arg(row->proxyConns)
                                               .arg(rateText(row->proxyDownBps), rateText(row->proxyUpBps))
                                         : u("%1 连接").arg(row->proxyConns));
        m_proxyValue->setToolTip(u("这个程序先连到本机的 %1,再由它往外连。这一段走本机环回、不经过网卡,"
                                   "所以不计入上面的出网速率;真实的出网流量记在 %1 自己那一行。")
                                     .arg(row->proxyName));
    }
}

void TrafficDetailWindow::updateConnections(const QList<NetTrafficConnPayload>& conns)
{
    m_conns->setSortingEnabled(false);
    QSet<QString> seen;
    int active = 0, proxied = 0;
    for (const NetTrafficConnPayload& c : conns) {
        const QString key = c.proto + QLatin1Char('|') + c.remoteIp + QLatin1Char('|') + QString::number(c.remotePort)
                            + QLatin1Char('|') + QString::number(c.localPort);
        seen.insert(key);
        QTreeWidgetItem* it = m_connItems.value(key);
        if (!it) {
            it = new SortItem;
            m_conns->addTopLevelItem(it);
            m_connItems.insert(key, it);
        }
        const bool proxy = c.scope == QLatin1String("proxy");
        if (proxy)
            ++proxied;
        if (c.upBps + c.downBps > 0)
            ++active;

        it->setText(CProto, c.proto);
        it->setText(CRemote, endpoint(c));
        it->setToolTip(CRemote, u("本机端口 %1").arg(c.localPort));
        QString domain;
        if (proxy) {
            domain = u("经本机代理 %1(真实目的只有代理知道)").arg(c.proxyName);
        } else {
            const QString hint = portHint(c);
            domain = c.domain.isEmpty() ? (hint.isEmpty() ? QStringLiteral("—") : hint)
                                        : (hint.isEmpty() ? c.domain : u("%1 · %2").arg(c.domain, hint));
        }
        it->setText(CDomain, domain);
        it->setToolTip(CDomain, c.domain.isEmpty() && !proxy
                                    ? u("本机没有对应的 DNS 应答:程序可能直接连了 IP、走了自己的加密 DNS,或在开始监控前就解析过了。")
                                    : domain);
        const QString scope = proxy ? u("经代理") : c.scope == QLatin1String("lan") ? u("局域网") : u("公网");
        it->setText(CScope, scope);
        it->setForeground(CScope, proxy ? theme::periwinkle() : c.scope == QLatin1String("lan") ? theme::textSecondary()
                                                                                                : theme::textPrimary());
        it->setText(CDown, rateText(c.downBps));
        it->setData(CDown, kSortRole, c.downBps);
        it->setForeground(CDown, c.downBps > 0 ? theme::accent() : theme::textDisabled());
        it->setText(CUp, rateText(c.upBps));
        it->setData(CUp, kSortRole, c.upBps);
        it->setForeground(CUp, c.upBps > 0 ? theme::amber() : theme::textDisabled());
        it->setText(CDownTot, fmt::bytes(c.downTotal));
        it->setData(CDownTot, kSortRole, c.downTotal);
        it->setText(CUpTot, fmt::bytes(c.upTotal));
        it->setData(CUpTot, kSortRole, c.upTotal);
        it->setText(CAge, durationText(c.ageSecs));
        it->setData(CAge, kSortRole, c.ageSecs);
        QString state;
        if (c.proto == QLatin1String("TCP"))
            state = c.established ? (c.idleSecs < 0 ? u("已建立 · 无数据") : u("已建立")) : u("已断开");
        else
            state = c.idleSecs >= 0 && c.idleSecs <= 5 ? u("活跃")
                    : c.idleSecs > 5                   ? u("空闲 %1").arg(durationText(c.idleSecs))
                                                       : u("—");
        it->setText(CState, state);
        it->setForeground(CState, c.established || (c.idleSecs >= 0 && c.idleSecs <= 5) ? theme::textSecondary()
                                                                                        : theme::textDisabled());
    }
    for (auto it = m_connItems.begin(); it != m_connItems.end();) {
        if (!seen.contains(it.key())) {
            delete it.value();
            it = m_connItems.erase(it);
        } else {
            ++it;
        }
    }
    m_conns->setSortingEnabled(true);
    if (conns.isEmpty())
        m_connNote->setText(u("没有连接(进程已退出,或这一分钟内没有联网)"));
    else
        m_connNote->setText(u("%1 条 · 其中 %2 条此刻有流量%3 · 每秒刷新")
                                .arg(conns.size())
                                .arg(active)
                                .arg(proxied > 0 ? u(" · %1 条经本机代理").arg(proxied) : QString()));
}

void TrafficDetailWindow::connMenu(const QPoint& pos)
{
    QTreeWidgetItem* it = m_conns->itemAt(pos);
    if (!it)
        return;
    QMenu menu(this);
    const QString remote = it->text(CRemote);
    const QString domain = it->text(CDomain);
    menu.addAction(u("复制对端地址"), this, [remote] { QGuiApplication::clipboard()->setText(remote); });
    QAction* d = menu.addAction(u("复制域名 / 用途"), this, [domain] { QGuiApplication::clipboard()->setText(domain); });
    d->setEnabled(domain != QStringLiteral("—"));
    menu.addAction(u("复制整行"), this, [it] {
        QStringList cols;
        for (int i = 0; i < CConnCount; ++i)
            cols << it->text(i);
        QGuiApplication::clipboard()->setText(cols.join(QLatin1Char('\t')));
    });
    menu.exec(m_conns->viewport()->mapToGlobal(pos));
}

void TrafficDetailWindow::requestHistory()
{
    if (!m_ipc || !m_ipc->isConnected()) {
        m_histNote->setText(u("未连接后台服务"));
        return;
    }
    bulwark::ipc::TimelineRequestPayload p;
    p.fromUtc = QDateTime::currentDateTimeUtc().addSecs(-kHistoryMinutes * 60);
    p.pid = m_pid;
    p.includeProcessTree = false;
    p.limit = 1000;
    m_timelineReq = p.requestId;
    m_histNote->setText(u("正在读取…"));
    m_refresh->setEnabled(false);
    m_ipc->requestTimeline(p);
    const QUuid req = m_timelineReq;
    QTimer::singleShot(15000, this, [this, req] {
        if (m_timelineReq == req) {
            m_timelineReq = QUuid();
            m_histNote->setText(u("读取超时"));
            m_refresh->setEnabled(true);
        }
    });
}

void TrafficDetailWindow::onTimeline(const bulwark::ipc::TimelineResponsePayload& p)
{
    if (m_timelineReq.isNull() || p.requestId != m_timelineReq)
        return;
    m_timelineReq = QUuid();
    m_refresh->setEnabled(true);
    m_files->clear();
    m_events->clear();

    const QString myPath = QDir::toNativeSeparators(m_row.path);
    QSet<QString> filesSeen;
    int files = 0, others = 0;
    for (auto it = p.events.crbegin(); it != p.events.crend(); ++it) {
        const bulwark::SecurityEvent& e = it->event;
        if (!myPath.isEmpty() && !e.actorPath.isEmpty()
            && QDir::toNativeSeparators(e.actorPath).compare(myPath, Qt::CaseInsensitive) != 0)
            continue;
        const QString when = e.timestampUtc.toLocalTime().toString(QStringLiteral("HH:mm:ss"));
        const evtfmt::Badge disp = evtfmt::disposition(it->action, it->enforcement);
        if (e.type == bulwark::EventType::FileWrite) {
            const QString path = QDir::toNativeSeparators(e.target.trimmed());
            if (path.isEmpty() || filesSeen.contains(path.toLower()))
                continue;
            filesSeen.insert(path.toLower());
            auto* item = new SortItem(m_files);
            QColor kc;
            const QString kind = fileKind(path, &kc);
            item->setText(FTime, when);
            item->setText(FPath, path);
            item->setData(FPath, Qt::UserRole, path);
            item->setToolTip(FPath, path + u("\n双击定位"));
            item->setText(FKind, kind);
            item->setForeground(FKind, kc);
            item->setText(FVerdict, disp.text);
            item->setForeground(FVerdict, disp.color);
            ++files;
        } else {
            if (others >= 200)
                continue;
            auto* item = new SortItem(m_events);
            item->setText(ETime, when);
            item->setText(EType, evtfmt::typeLabel(e));
            item->setForeground(EType, evtfmt::typeColor(e.type));
            item->setText(ETarget, e.target.trimmed().isEmpty() ? QStringLiteral("—") : e.target.trimmed());
            item->setToolTip(ETarget, evtfmt::sentence(e, false));
            item->setText(EVerdict, disp.text);
            item->setForeground(EVerdict, disp.color);
            ++others;
        }
    }
    if (files == 0) {
        auto* item = new QTreeWidgetItem(m_files);
        item->setText(FPath, u("没有记录(本软件只记录它关注的写入;同类零风险的写入可能被合并)"));
        item->setForeground(FPath, theme::textMuted());
        item->setFlags(Qt::ItemIsEnabled);
    }
    if (others == 0) {
        auto* item = new QTreeWidgetItem(m_events);
        item->setText(ETarget, u("没有记录"));
        item->setForeground(ETarget, theme::textMuted());
        item->setFlags(Qt::ItemIsEnabled);
    }
    m_histNote->setText(p.truncated ? u("%1 个文件 · 记录较多,只取了最近 %2 条").arg(files).arg(p.events.size())
                                    : u("%1 个文件 · %2 条其它记录").arg(files).arg(others));
}
