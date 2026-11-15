#include "dialogs/AiInsightPanel.h"
#include "design/Components.h"
#include "design/FlowLayout.h"
#include "design/IconTile.h"
#include "design/Theme.h"
#include "widgets/WrapLabel.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

QString cachedAgeText(qint64 ms)
{
    const qint64 mins = ms / 60000;
    if (mins < 2)
        return u("刚才");
    if (mins < 60)
        return u(" %1 分钟前").arg(mins);
    const qint64 hours = mins / 60;
    if (hours < 24)
        return u(" %1 小时前").arg(hours);
    return u(" %1 天前").arg(qMax<qint64>(1, hours / 24));
}

void setPlainText(QLabel* l, const QString& s)
{
    if (auto* w = dynamic_cast<WrapLabel*>(l))
        w->setText(s);
    else
        l->setText(s);
}

}

AiInsightPanel::AiInsightPanel(AiExplainContext context, bool compact, QWidget* parent)
    : QFrame(parent), m_context(context), m_compact(compact), m_color(theme::accentAlt())
{
    setAttribute(Qt::WA_StyledBackground, false);
    auto* h = new QHBoxLayout(this);
    h->setContentsMargins(compact ? 12 : 16, compact ? 8 : 10, compact ? 10 : 12, compact ? 8 : 10);
    h->setSpacing(compact ? 8 : 10);
    m_tile = compact ? new IconTile(QStringLiteral("sparkles"), m_color, 22, 12)
                     : new IconTile(QStringLiteral("sparkles"), m_color, 26, 14);
    h->addWidget(m_tile, 0, Qt::AlignTop);

    auto* col = new QVBoxLayout;
    col->setContentsMargins(0, 0, 0, 0);
    col->setSpacing(compact ? 4 : 5);
    auto* head = new QHBoxLayout;
    head->setContentsMargins(0, 0, 0, 0);
    head->setSpacing(compact ? 6 : 8);
    m_caption = ui::coloredText(u("AI 解读"), 9, 600, m_color);
    head->addWidget(m_caption, 0, Qt::AlignVCenter);
    m_advice = ui::pill(QString(), theme::textMuted());
    m_advice->hide();
    head->addWidget(m_advice, 0, Qt::AlignVCenter);
    m_confidence = ui::pill(QString(), m_color);
    m_confidence->hide();
    head->addWidget(m_confidence, 0, Qt::AlignVCenter);
    head->addStretch(1);
    m_meta = ui::label(QString(), "muted");
    if (!compact)
        head->addWidget(m_meta, 0, Qt::AlignVCenter);
    col->addLayout(head);

    m_text = bodyLabel(theme::textSecondary());
    m_text->hide();
    col->addWidget(m_text);
    m_note = bodyLabel(theme::warning());
    m_note->hide();
    col->addWidget(m_note);
    if (compact) {
        m_meta->hide();
        col->addWidget(m_meta);
    }

    m_fixRow = new QWidget(this);
    auto* fix = new QVBoxLayout(m_fixRow);
    fix->setContentsMargins(0, 2, 0, 0);
    fix->setSpacing(4);
    m_fixCap = ui::label(compact ? u("确认误伤可临时放行") : u("若确认误伤(规则误伤纠正)"), "muted");
    fix->addWidget(m_fixCap);
    // 拦截通知只有 412 宽,一排放不下这几个按钮:放不下就折到下一行,不能把按钮挤扁。
    auto* rowHost = new QWidget(m_fixRow);
    auto* row = new FlowLayout(rowHost, 6, 6);
    row->setContentsMargins(0, 0, 0, 0);
    m_trust1h = ui::button(compact ? u("信任 1h") : u("信任 1 小时"), "ghost", QString(), true);
    m_trust1d = ui::button(compact ? u("信任 1d") : u("信任 1 天"), "ghost", QString(), true);
    m_trustSession = ui::button(compact ? u("本次会话") : u("仅本次会话"), "ghost", QString(), true);
    m_delRule = ui::button(compact ? u("删规则") : u("删除命中规则"), "ghost", QString(), true);
    row->addWidget(m_trust1h);
    row->addWidget(m_trust1d);
    row->addWidget(m_trustSession);
    row->addWidget(m_delRule);
    fix->addWidget(rowHost);
    m_fixRow->hide();
    col->addWidget(m_fixRow);

    connect(m_trust1h, &QPushButton::clicked, this,
            [this] { emit trustRequested(bulwark::RememberScope::OneHour); });
    connect(m_trust1d, &QPushButton::clicked, this,
            [this] { emit trustRequested(bulwark::RememberScope::OneDay); });
    connect(m_trustSession, &QPushButton::clicked, this,
            [this] { emit trustRequested(bulwark::RememberScope::Session); });
    connect(m_delRule, &QPushButton::clicked, this, [this] { emit deleteRuleRequested(); });
    m_undoTrust = ui::button(u("撤销自动信任"), "ghost", QString(), true);
    m_undoTrust->hide();
    row->addWidget(m_undoTrust);
    connect(m_undoTrust, &QPushButton::clicked, this, [this] {
        // id 为空也发:外壳会按路径回查信任条目(addTrust 与列表回包之间可能有竞态)。
        emit autoTrustUndoRequested(m_autoTrustRuleId);
    });

    h->addLayout(col, 1);

    m_ticker = new QTimer(this);
    m_ticker->setInterval(1000);
    connect(m_ticker, &QTimer::timeout, this, [this] {
        setMeta(u("正在解读… %1 秒").arg(m_since.elapsed() / 1000));
    });

    setAccessibleName(u("AI 解读"));
    setToolTip(m_context != AiExplainContext::Prompt
                   ? u("由「设置 → AI 辅助」里配置的大模型生成,仅供参考:不参与裁决,"
                       "也不改变已经做出的处置。可在同一处关闭。")
                   : u("由「设置 → AI 辅助」里配置的大模型生成,仅供参考:不参与裁决,"
                       "不改变倒计时与默认处置。可在同一处关闭。"));
}

void AiInsightPanel::setLoading()
{
    m_since.start();
    setMeta(u("正在解读…"));
    m_ticker->start();
    showCorrectionRow(false);
}

void AiInsightPanel::setCorrectionContext(const QString& actorPath, const QString& matchedRuleNote)
{
    m_actorPath = actorPath;
    m_matchedRuleNote = matchedRuleNote;
}

void AiInsightPanel::showCorrectionRow(bool show)
{
    if (!m_fixRow)
        return;
    if (show) {
        m_delRule->setVisible(!m_matchedRuleNote.trimmed().isEmpty());
        m_trust1h->show();
        m_trust1d->show();
        m_trustSession->show();
        m_undoTrust->hide();
        if (m_fixCap)
            m_fixCap->setText(m_compact ? u("确认误伤可临时放行") : u("若确认误伤(规则误伤纠正)"));
        m_fixRow->show();
    } else {
        m_fixRow->hide();
    }
}

void AiInsightPanel::showAutoTrustApplied(bulwark::RememberScope scope, const QUuid& ruleId)
{
    if (!m_fixRow)
        return;
    m_autoTrustRuleId = ruleId;
    QString scopeText;
    switch (scope) {
    case bulwark::RememberScope::Session:   scopeText = u("本次会话"); break;
    case bulwark::RememberScope::OneHour:   scopeText = u("1 小时"); break;
    case bulwark::RememberScope::OneDay:    scopeText = u("1 天"); break;
    case bulwark::RememberScope::Permanent: scopeText = u("永久"); break;
    }
    if (m_fixCap)
        m_fixCap->setText(u("高置信·无硬指标,已自动信任 %1(可撤销)").arg(scopeText));
    m_trust1h->hide();
    m_trust1d->hide();
    m_trustSession->hide();
    m_delRule->hide();
    m_undoTrust->show();
    m_fixRow->show();
    setAccessibleDescription(accessibleDescription() + u(" 已自动信任%1。").arg(scopeText));
}

void AiInsightPanel::setResult(const AiExplanation& r, bool hardIndicator)
{
    m_ticker->stop();
    showCorrectionRow(false);
    if (!r.ok) {
        setTone(theme::textMuted());
        setMeta(QString());
        setPlainText(m_text, u("暂不可用:") + r.error);
        m_text->setStyleSheet(QStringLiteral("color:%1; font-size:9pt;").arg(theme::textMuted().name()));
        m_text->show();
        setAccessibleDescription(m_text->text());
        return;
    }

    const bool blockToast = m_context != AiExplainContext::Prompt;
    const bool wasBlocked = m_context == AiExplainContext::Blocked;
    const bool conflict = hardIndicator && r.advice == AiExplanation::Advice::Allow;
    switch (r.advice) {
    case AiExplanation::Advice::Block:
        ui::stylePill(m_advice,
                      !blockToast     ? u("建议拦截")
                      : wasBlocked    ? u("拦得对")
                                      : u("确属危险"),
                      theme::danger());
        break;
    case AiExplanation::Advice::Allow:
        if (wasBlocked)
            ui::stylePill(m_advice, u("疑似误拦"), theme::warning());
        else if (blockToast)
            ui::stylePill(m_advice, u("多半无害"), theme::warning());
        else
            ui::stylePill(m_advice, u("建议放行"), conflict ? theme::warning() : theme::success());
        break;
    case AiExplanation::Advice::Caution:
        ui::stylePill(m_advice, blockToast ? u("难以判断") : u("谨慎处理"), theme::warning());
        break;
    case AiExplanation::Advice::Unknown:
        break;
    }
    m_advice->setVisible(r.advice != AiExplanation::Advice::Unknown);
    if (!r.confidence.isEmpty())
        ui::stylePill(m_confidence, u("置信度 ") + r.confidence, m_color);
    m_confidence->setVisible(!r.confidence.isEmpty());

    if (r.cached) {
        const QString age = cachedAgeText(r.cachedAgeMs).trimmed();
        const bool fresh = r.cachedAgeMs < 120000;
        if (r.entryId <= 0) {
            setMeta(r.cachedSimilar ? u("沿用本机同类行为的解读") : u("沿用本机%1的解读").arg(age));
        } else if (!r.cachedSimilar) {
            setMeta(u("沿用本机 #%1(%2)").arg(r.entryId).arg(age));
        } else {
            setMeta(fresh ? u("沿用本机 #%1 · 同类行为").arg(r.entryId)
                          : u("沿用本机 #%1 · 同类行为(%2)").arg(r.entryId).arg(age));
        }
        QString tip = u("本条取自本机已存的解读,没有请求大模型、没有消耗 token。\n");
        if (r.entryId > 0)
            tip += u("#%1 是它在本机解读库里的编号,同一类行为再遇到还是这个号。\n").arg(r.entryId);
        if (r.cachedSimilar)
            tip += u("「同类行为」= 事实一致、只换了随机文件名之类的皮毛,不是这个程序自己来过。\n");
        tip += u("解读保存一周:期间同一行为、或只换了随机文件名的同类行为再次")
               + (blockToast ? u("拦截") : u("询问")) + u(",直接沿用这一条;到期自动清理。\n")
               + u("解读库:%ProgramData%\\Bulwark\\ai_explain_cache.json");
        m_meta->setToolTip(tip);
    } else {
        QString meta = QString::number(r.elapsedMs / 1000.0, 'f', 1) + QStringLiteral("s");
        if (r.tokens > 0)
            meta += QStringLiteral(" · %1 tok").arg(r.tokens);
        if (r.entryId > 0)
            meta += u(" · 存为 #%1").arg(r.entryId);
        setMeta(meta);
        m_meta->setToolTip(r.entryId > 0
                               ? u("刚向大模型问来的解读(耗时 · token)。已存入本机解读库 #%1,"
                                   "保存一周 —— 期间同一行为、或只换了随机文件名的同类行为再遇到,"
                                   "直接沿用它,不再消耗 token。")
                                     .arg(r.entryId)
                               : u("刚向大模型问来的解读(耗时 · token)。"));
    }

    setPlainText(m_text, r.summary);
    m_text->show();
    if (conflict) {
        setPlainText(m_note, wasBlocked
                                 ? u("引擎检出了硬恶意指标,与「疑似误拦」的判断相左 —— 请以依据为准。")
                                 : blockToast
                                       ? u("引擎检出了硬恶意指标,与「多半无害」的判断相左 —— 请以依据为准。")
                                       : u("引擎在这次行为里检出了硬恶意指标,与这条放行建议相左 —— 请以上方证据为准。"));
        m_note->show();
    }
    if (blockToast && r.advice == AiExplanation::Advice::Allow && !m_actorPath.trimmed().isEmpty())
        showCorrectionRow(true);
    QString origin;
    if (r.cached) {
        origin = r.cachedSimilar ? u(" 本条沿用本机已存的同类行为解读") : u(" 本条沿用本机已存的解读");
        if (r.entryId > 0)
            origin += u(",编号 %1").arg(r.entryId);
        origin += u("。");
    }
    setAccessibleDescription((m_advice->isVisible() ? m_advice->text() + u(":") : QString()) + r.summary
                             + (conflict ? u(" ") + m_note->text() : QString()) + origin);
}

int AiInsightPanel::heightForWidth(int w) const
{
    if (QLayout* l = layout()) {
        const int h = l->totalHeightForWidth(w);
        if (h > 0)
            return h;
    }
    return sizeHint().height();
}

void AiInsightPanel::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    const QRectF r = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
    const qreal radius = m_compact ? 10 : 12;
    QPainterPath shape;
    shape.addRoundedRect(r, radius, radius);
    p.fillPath(shape, theme::blend(m_color, theme::surface(), 0.12));
    p.setPen(QPen(theme::blend(m_color, theme::surface(), 0.34), 1.0));
    p.drawPath(shape);
    p.save();
    p.setClipPath(shape);
    p.fillRect(QRectF(r.left(), r.top(), 3.5, r.height()), m_color);
    p.restore();
}

QLabel* AiInsightPanel::bodyLabel(const QColor& color) const
{
    if (m_compact) {
        auto* w = new WrapLabel;
        w->setTextFormat(Qt::PlainText);
        w->setStyleSheet(QStringLiteral("color:%1; font-size:9pt;").arg(color.name()));
        return w;
    }
    auto* l = new QLabel;
    l->setTextFormat(Qt::PlainText);
    l->setWordWrap(true);
    l->setTextInteractionFlags(Qt::TextSelectableByMouse);
    l->setStyleSheet(QStringLiteral("color:%1; font-size:9.5pt;").arg(color.name()));
    return l;
}

void AiInsightPanel::setTone(const QColor& c)
{
    m_color = c;
    m_tile->set(QStringLiteral("sparkles"), c);
    m_caption->setStyleSheet(QStringLiteral("font-size:9pt; font-weight:600; color:%1;").arg(c.name()));
    update();
}

void AiInsightPanel::setMeta(const QString& text)
{
    m_meta->setText(text);
    if (m_compact)
        m_meta->setVisible(!text.isEmpty());
}
