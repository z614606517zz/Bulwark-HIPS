#include "dialogs/ToastNotifier.h"
#include "ai/AiScanner.h"
#include "design/Components.h"
#include "design/Confirm.h"
#include "design/Banner.h"

#include <QHBoxLayout>
#include <QPushButton>
#include "dialogs/AiInsightPanel.h"
#include "dialogs/EventFormat.h"
#include "dialogs/ExplainCard.h"
#include "dialogs/ThreatCodeView.h"
#include "dialogs/ToastWindow.h"
#include "dialogs/YaraView.h"
#include "design/Theme.h"
#include "ipc/IpcClient.h"

#include "bulwark/engine/TrustPolicy.h"
#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"

#include <QDateTime>
#include <QEvent>
#include <QFileInfo>
#include <QGuiApplication>
#include <QPointer>
#include <QRect>
#include <QScreen>
#include <QTimer>
#include <QWidget>
#include <memory>

#include <utility>

using bulwark::SecurityEvent;

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

}

ToastNotifier::ToastNotifier(QObject* parent) : QObject(parent)
{
    m_coalesceTimer = new QTimer(this);
    m_coalesceTimer->setInterval(1000);
    m_coalesceTimer->setSingleShot(true);
    connect(m_coalesceTimer, &QTimer::timeout, this, [this] {
        flushSuppressed();
        if (m_suppressedBlocks > 0)
            m_coalesceTimer->start();
    });
}

void ToastNotifier::showBlock(const SecurityEvent& e, bulwark::EnforcementOutcome enforcement,
                              bool timeoutBlock, bool execBlocked)
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();

    const QString key = e.actorPath + QLatin1Char('|')
                      + QString::number(static_cast<int>(e.type)) + QLatin1Char('|') + e.target
                      + QLatin1Char('|') + QString::number(static_cast<int>(enforcement))
                      + (timeoutBlock ? QStringLiteral("|timeout") : QString())
                      + (execBlocked ? QStringLiteral("|execblocked") : QString());

    // 自我保护对可信系统工具(任务管理器等)的拦截不是威胁:完全静默,不弹任何
    // 提示。任务管理器预开危险句柄是常态行为,事件列表由服务端折叠留档,
    // 详情里带"要退出本产品请用托盘菜单"的说明。
    if (evtfmt::isSelfProtectBySystemTool(e))
        return;

    // 受保护目录拒掉了一次写入,引擎没有把它判成威胁:文件没被改动。换成一条平和的提醒,
    // 不进「已批量拦截危险行为」的合并计数,也不触发语音播报。
    if (isGuardedWriteDenial(e, enforcement, timeoutBlock, execBlocked)) {
        showGuardedWriteDenied(e, now);
        return;
    }

    auto it = m_recentBlockKeys.find(key);
    if (it != m_recentBlockKeys.end() && now - it.value() < kDedupWindowMs) {
        it.value() = now;
        return;
    }
    m_recentBlockKeys.insert(key, now);
    pruneRecentKeys(now);

    if (!timeoutBlock && !execBlocked && now - m_lastBlockToastMs < kMinBlockGapMs) {
        if (evtfmt::needsManualAction(enforcement))
            ++m_suppressedUnenforced;
        else
            ++m_suppressedBlocks;
        if (m_coalesceTimer && !m_coalesceTimer->isActive())
            m_coalesceTimer->start();
        return;
    }
    m_lastBlockToastMs = now;

    if (e.yaraLevel == SecurityEvent::YaraMalicious && !e.yaraRule.trimmed().isEmpty()) {
        showYaraBlock(e, enforcement, execBlocked);
        return;
    }

    const evtfmt::Threat threat = evtfmt::threatOf(e);
    QString source = threat.basis;
    // 内核前拦是已发生的事实,引擎可能同时判了放行(证据链里只有「健康签名,直接放行」)。
    // 此时依据必须写内核拦的原因,否则卡片会出现「已拦截 / 直接放行」自相矛盾。
    if (source.isEmpty() && e.kernelBlocked && !e.detail.trimmed().isEmpty()) {
        source = e.detail.trimmed();
        if (source.contains(u("受保护目录")))
            source += u(" · 该程序不在可信写入者名单,确认安全可将其加入信任");
    }
    if (source.isEmpty())
        source = evtfmt::strongestReason(e);
    if (source.isEmpty())
        source = u("命中高危行为规则");

    using EO = bulwark::EnforcementOutcome;
    const evtfmt::Badge disp = evtfmt::disposition(bulwark::VerdictAction::Block, enforcement);
    const bool enforced = !evtfmt::needsManualAction(enforcement);

    const ToastWindow::Kind kind = enforcement == EO::AlertedOnly ? ToastWindow::Kind::BlockAlertedOnly
                                 : enforcement == EO::Failed      ? ToastWindow::Kind::BlockFailed
                                                                  : ToastWindow::Kind::Block;
    const QString heading = (timeoutBlock && enforced)     ? u("无人响应,已按高风险自动拦截")
                          : enforcement == EO::AlertedOnly ? u("检测到危险行为,未能拦截")
                          : enforcement == EO::Failed      ? u("检测到危险行为,处置未成功")
                          : enforcement == EO::ExecDenied  ? u("已拦下危险行为,并禁止其再次启动")
                          : enforcement == EO::WriteUndone ? u("已拦下危险行为,并撤销了写入")
                          : enforcement == EO::ActorAlreadyGone
                                                           ? u("危险行为已处置(主体此前已被结束)")
                                                           : u("已拦截危险行为");
    QString meta = u("依据:") + source;
    if (!enforced)
        meta = evtfmt::dispositionDetail(bulwark::VerdictAction::Block, enforcement)
             + u("(") + meta + u(")");
    if (timeoutBlock)
        meta = u("询问超时、无人响应 · ") + meta;
    // 进程已被结束(或载荷已隔离)的同时,该映像也被禁止了再次启动:卡片上的『撤销』指的就是这一层,
    // 文案里必须写明。
    if (enforced && execBlocked && enforcement != EO::ExecDenied)
        meta += u(" · 同时已禁止该程序再次启动");

    const QString actorPathTrimmed = e.actorPath.trimmed();
    const bool pathLike = (actorPathTrimmed.size() >= 2 && actorPathTrimmed.at(1) == QLatin1Char(':'))
                          || actorPathTrimmed.startsWith(QLatin1Char('\\'));
    const bool undoable = pathLike && enforced
                          && (enforcement == EO::ExecDenied || timeoutBlock || execBlocked);

    threatcode::Options codeOpt;
    codeOpt.maxSnippets = 1;
    codeOpt.maxRows = 6;
    codeOpt.moreHint = u("另有 %1 段命中代码,见拦截记录详情");
    QWidget* codeBlock = threatcode::build(e, evtfmt::riskColor(e.riskScore), codeOpt);

    // 主按钮一律是「查看详情」。撤销 = 把这个程序整体加白 1 小时,不能是一张拦截通知上唯一醒目的
    // 按钮让人顺手点掉:降成次要按钮,点了还要再确认一次(见 undoBlockByTrust),
    // 与特征识别战报(showYaraBlock)同一套摆法。
    auto* t = new ToastWindow(kind, heading, evtfmt::arrowLine(e), meta, e.techniques,
                              ((enforced && !undoable) ? 8000 : 12000) + (codeBlock ? 4000 : 0),
                              disp.text, u("查看详情 ›"));
    if (codeBlock)
        t->setCode(codeBlock);   // 同样必须先于 present():它改卡片的宽和高
    if (undoable) {
        const QString actorPath = actorPathTrimmed;
        t->setSecondaryAction(u("撤销拦截 · 信任 1 小时"));
        connect(t, &ToastWindow::secondaryClicked, this,
                [this, actorPath](ToastWindow*) { undoBlockByTrust(actorPath); });
    }
    t->setThreat(threat.category, threat.name);

    const AiExplainContext aiCtx = enforced ? AiExplainContext::Blocked : AiExplainContext::Alerted;
    const bool aiWillExplain = m_ai && m_ai->isConfigured() && m_ai->blockExplainEnabled();
    if (!aiWillExplain) {
        // AI 不会给出解读时(没配、没开、或配置状态还不知道)改用离线解释,不联网、不需要配置。
        // 省掉「建议怎么做」:处置已经发生,卡片上已有「撤销拦截 · 信任 1 小时」。
        explaincard::Options opt;
        opt.compact = true;
        opt.omitAdvice = true;
        if (QWidget* card = explaincard::build(e, opt)) {
            t->setInsight(card);
            t->settleInsight(kLocalReadMs);
        }
    } else {
        auto* panel = new AiInsightPanel(aiCtx, true);
        panel->setCorrectionContext(e.actorPath, e.matchedRuleNote);
        panel->setLoading();
        t->setInsight(panel);
        const bool hardIndicator = e.hasThreatIndicator;
        const QPointer<ToastWindow> toast(t);
        const QString actorPath = e.actorPath;
        const QString ruleNote = e.matchedRuleNote;
        connect(panel, &AiInsightPanel::trustRequested, this,
                [this, panel, actorPath](bulwark::RememberScope scope) {
                    applyTrustCorrection(actorPath, scope, panel ? panel->window() : nullptr);
                });
        connect(panel, &AiInsightPanel::deleteRuleRequested, this,
                [this, panel, ruleNote] {
                    applyRuleDeletion(ruleNote, panel ? panel->window() : nullptr);
                });
        connect(panel, &AiInsightPanel::autoTrustUndoRequested, this,
                [this, panel, actorPath](const QUuid& ruleId) {
                    if (!m_ipc || !m_ipc->isConnected()) {
                        ui::notify(panel ? panel->window() : nullptr, ui::Tone::Danger,
                                   u("未连接后台服务,无法撤销自动信任。"));
                        return;
                    }
                    // id 在手就直接删;不在手就按路径回查(addTrust 与列表回包之间可能有竞态)。
                    if (!ruleId.isNull()) {
                        m_ipc->removeTrust(ruleId);
                        ui::notify(panel ? panel->window() : nullptr, ui::Tone::Success,
                                   u("已撤销自动信任。"));
                        return;
                    }
                    const QPointer<IpcClient> ipc = m_ipc;
                    const QPointer<QWidget> guard(panel ? panel->window() : nullptr);
                    auto conn = std::make_shared<QMetaObject::Connection>();
                    *conn = connect(m_ipc, &IpcClient::trustReceived, this,
                                    [ipc, guard, actorPath, conn](const QList<bulwark::DefenseRule>& entries) {
                                        QObject::disconnect(*conn);
                                        if (!ipc)
                                            return;
                                        for (const auto& t : entries) {
                                            if (t.actorPath.compare(actorPath, Qt::CaseInsensitive) == 0
                                                && t.note.contains(QStringLiteral("AI自动信任"))) {
                                                ipc->removeTrust(t.id);
                                                ui::notify(guard.data(), ui::Tone::Success, u("已撤销自动信任。"));
                                                return;
                                            }
                                        }
                                        ui::notify(guard.data(), ui::Tone::Warning,
                                                   u("没有找到自动信任条目,可能已到期或手动移除。"));
                                    });
                    m_ipc->requestTrust();
                });
        m_ai->explainEvent(e, panel, [this, panel, toast, hardIndicator](const AiExplanation& r) {
            panel->setResult(r, hardIndicator);
            if (toast) {
                const bool correcting = r.ok && r.advice == AiExplanation::Advice::Allow;
                toast->settleInsight(r.ok ? (correcting ? 25000 : kAiReadMs) : kAiFailReadMs);
            }
        }, aiCtx);
    }
    present(t, true, true, !enforced);
    emit blockPresented(e.actorPath, enforcement);
}

// 特征识别战报:后台扫描认出了已验证的恶意家族,进程已经在跑 —— 与兜底扫描同一条处置路径。
// 主角是「它是什么」(家族、来源、文件指纹),不是一句「启动进程 → …」;撤销降成次要按钮,
// 命中的是事先核对过不会误中的家族规则,不该让人顺手点掉。说明只用离线解释,不交给 AI 改写。
void ToastNotifier::showYaraBlock(const SecurityEvent& e, bulwark::EnforcementOutcome enforcement, bool execBlocked)
{
    using EO = bulwark::EnforcementOutcome;
    const bool enforced = !evtfmt::needsManualAction(enforcement);
    const bool k = !theme::mecha();
    const ToastWindow::Kind kind = enforcement == EO::AlertedOnly ? ToastWindow::Kind::BlockAlertedOnly
                                 : enforcement == EO::Failed      ? ToastWindow::Kind::BlockFailed
                                                                  : ToastWindow::Kind::Block;
    const QString heading = enforced ? (k ? u("小垒认出了一个坏家伙") : u("特征识别 · 目标已锁定"))
                                     : (k ? u("小垒认出了坏家伙,但没能拦住它") : u("特征识别 · 目标未能清除"));
    const QString name = QFileInfo(e.actorPath).fileName();
    const QString sentence = u("%1 的文件内容命中了恶意家族特征").arg(name.isEmpty() ? u("该程序") : name);
    const evtfmt::Badge disp = evtfmt::disposition(bulwark::VerdictAction::Block, enforcement);

    auto* t = new ToastWindow(kind, heading, sentence, QString(), {}, enforced ? 14000 : 20000, QString(),
                              u("查看详情 ›"));
    t->setCode(yaraview::reportHero(e, enforcement, execBlocked, disp.text));   // 必须先于 present()
    const QString actorPath = e.actorPath.trimmed();
    const bool pathLike = (actorPath.size() >= 2 && actorPath.at(1) == QLatin1Char(':'))
                          || actorPath.startsWith(QLatin1Char('\\'));
    if (pathLike && enforced) {
        t->setSecondaryAction(u("这是误报 · 信任 1 小时"));
        connect(t, &ToastWindow::secondaryClicked, this,
                [this, actorPath](ToastWindow*) { undoBlockByTrust(actorPath); });
    }
    explaincard::Options opt;
    opt.compact = true;
    opt.omitAdvice = true;
    if (QWidget* card = explaincard::build(e, opt)) {
        t->setInsight(card);
        t->settleInsight(kLocalReadMs);
    }
    present(t, true, true, !enforced);
    emit blockPresented(e.actorPath, enforcement);
}

void ToastNotifier::undoBlockByTrust(const QString& actorPath)
{
    const QString path = actorPath.trimmed();
    if (path.isEmpty()) {
        showInfo(u("无法撤销拦截"), u("缺少程序路径。请在主界面「信任名单」里手动加白。"), 8000);
        return;
    }
    if (!m_ipc || !m_ipc->isConnected()) {
        showInfo(u("无法撤销拦截"),
                 u("未连接后台服务。请稍后重试,或在主界面「信任名单」里手动加白该程序。"), 8000);
        return;
    }
    if (const auto rej = bulwark::engine::TrustPolicy::rejectsWholeProcessTrust(path, false); rej.ok) {
        showInfo(u("无法撤销拦截"), rej.reason, 9000);
        return;
    }
    // 这里是从通知卡片按钮的信号里进来的,卡片紧接着就开始淡出并销毁。确认框自带事件循环,
    // 不能在那次信号发射里面跑,排到下一轮事件循环再弹。
    QTimer::singleShot(0, this, [this, path] { confirmUndoBlock(path); });
}

// 撤销 = 把整个程序加白 1 小时,期间它的全部行为都不再检测,所以先确认一次,默认焦点在「保持拦截」上。
ui::ConfirmSpec ToastNotifier::undoBlockConfirmSpec(const QString& path)
{
    ui::ConfirmSpec c;
    c.risk = ui::Risk::Danger;
    c.title = u("撤销拦截,并信任这个程序 1 小时?");
    c.summary = u("确认后,这个程序在 1 小时内的【全部行为】都跳过检测直接放行,并解除对它的禁止启动。"
                  "这是应对误拦的临时例外,不代表它是安全的。");
    c.consequences = QStringList{
        u("信任期内不再对它做威胁检测 / 拦截"),
        u("如果它确实是恶意程序,这 1 小时里将畅通无阻"),
        u("1 小时后自动失效;想提前收回,到「信任名单」里移除"),
    };
    c.subjectLabel = u("程序");
    c.subject = path;
    c.confirmText = u("撤销拦截 · 信任 1 小时");
    c.cancelText = u("保持拦截");
    c.requireAck = false;
    // 发起它的通知卡片正在关闭,主窗口又可能藏在托盘里:不挂父窗口,居中在鼠标所在的屏幕并置顶。
    c.stayOnTop = true;
    return c;
}

void ToastNotifier::confirmUndoBlock(const QString& path)
{
    if (!ui::confirm(nullptr, undoBlockConfirmSpec(path)))
        return;
    // 确认框开着的这段时间里,与后台服务的连接可能已经断了。
    if (!m_ipc || !m_ipc->isConnected()) {
        showInfo(u("无法撤销拦截"),
                 u("未连接后台服务。请稍后重试,或在主界面「信任名单」里手动加白该程序。"), 8000);
        return;
    }
    m_ipc->addTrust(path, QStringLiteral("拦截通知·用户撤销"), false,
                    bulwark::RememberScope::OneHour);
    showInfo(u("已撤销拦截 · 信任 1 小时"),
             u("已为 %1 写入 1 小时信任:期间不再检测 / 拦截,并解除对它的禁止启动;到期自动失效。")
                 .arg(QFileInfo(path).fileName()),
             7000);
}

bool ToastNotifier::isGuardedWriteDenial(const SecurityEvent& e, bulwark::EnforcementOutcome enforcement,
                                         bool timeoutBlock, bool execBlocked)
{
    // 引擎自己也认为可疑的(硬指标、特征命中、风险分到了界面标红的档位)仍按拦截通知弹。
    return e.kernelBlocked && enforcement == bulwark::EnforcementOutcome::KernelBlocked
        && !timeoutBlock && !execBlocked
        && !e.hasThreatIndicator && e.riskScore < 50
        && e.yaraLevel != SecurityEvent::YaraMalicious
        && e.detail.contains(u("受保护目录"));
}

// 解压、保存这类正常操作会连着被拒几十次,所以同一个程序一分钟只提醒一次。
void ToastNotifier::showGuardedWriteDenied(const SecurityEvent& e, qint64 nowMs)
{
    const QString actorPath = e.actorPath.trimmed();
    const QString key = actorPath.toLower();
    const auto seen = m_guardNoticeMs.constFind(key);
    if (seen != m_guardNoticeMs.constEnd() && nowMs - seen.value() < kGuardNoticeGapMs)
        return;
    for (auto it = m_guardNoticeMs.begin(); it != m_guardNoticeMs.end();) {
        if (nowMs - it.value() >= kGuardNoticeGapMs)
            it = m_guardNoticeMs.erase(it);
        else
            ++it;
    }
    m_guardNoticeMs.insert(key, nowMs);

    const QString name = QFileInfo(actorPath).fileName();
    const bool pathLike = (actorPath.size() >= 2 && actorPath.at(1) == QLatin1Char(':'))
                          || actorPath.startsWith(QLatin1Char('\\'));
    QString meta = u("文件没有被改动。这个程序不在可信写入者名单里,它对受保护目录的写入、改名和删除都会被拒绝;"
                     "一分钟内它再被拒绝不会重复提醒。");
    if (pathLike)
        meta += u("如果是你自己在解压、保存或整理文件,信任它之后重做一遍即可。");

    auto* t = new ToastWindow(ToastWindow::Kind::Info,
                              u("受保护目录拒绝了 %1 的写入").arg(name.isEmpty() ? u("一个程序") : name),
                              evtfmt::arrowLine(e), meta, {}, 12000, u("已拒绝写入"),
                              pathLike ? u("信任并允许 · 1 小时") : u("查看详情 ›"));
    if (pathLike) {
        connect(t, &ToastWindow::clicked, this,
                [this, actorPath](ToastWindow*) { trustGuardedWriter(actorPath); });
        t->setSecondaryAction(u("查看详情 ›"));
        connect(t, &ToastWindow::secondaryClicked, this,
                [this](ToastWindow*) { emit blockToastClicked(false); });
    } else {
        connect(t, &ToastWindow::clicked, this, [this](ToastWindow*) { emit blockToastClicked(false); });
    }
    present(t, false);
}

void ToastNotifier::trustGuardedWriter(const QString& actorPath)
{
    const QString path = actorPath.trimmed();
    if (!m_ipc || !m_ipc->isConnected()) {
        showInfo(u("无法加入信任"),
                 u("未连接后台服务。请稍后重试,或在主界面「信任名单」里手动加白该程序。"), 8000);
        return;
    }
    if (const auto rej = bulwark::engine::TrustPolicy::rejectsWholeProcessTrust(path, false); rej.ok) {
        showInfo(u("无法加入信任"), rej.reason, 9000);
        return;
    }
    m_ipc->addTrust(path, QStringLiteral("受保护目录通知·用户信任"), false,
                    bulwark::RememberScope::OneHour);
    // 信任没生效(比如内核名单满了)的话,下一次被拒要立刻再提醒,不能静默。
    m_guardNoticeMs.remove(path.toLower());
    showInfo(u("已信任 1 小时"),
             u("%1 在 1 小时内可以写入受保护目录,期间也不再对它做其他检测 / 拦截;到期自动失效。"
               "刚才被拒绝的操作请重做一遍。要长期允许,请在主界面「信任名单」里加白。")
                 .arg(QFileInfo(path).fileName()),
             9000);
}

void ToastNotifier::setAiScanner(AiScanner* ai)
{
    m_ai = ai;
}

void ToastNotifier::setIpc(IpcClient* ipc)
{
    m_ipc = ipc;
}

void ToastNotifier::applyTrustCorrection(const QString& actorPath, bulwark::RememberScope scope,
                                         QWidget* parent)
{
    if (!m_ipc || !m_ipc->isConnected()) {
        ui::notify(parent, ui::Tone::Danger, u("未连接后台服务,无法写入信任。"));
        return;
    }
    const QString path = actorPath.trimmed();
    if (path.isEmpty()) {
        ui::notify(parent, ui::Tone::Danger, u("缺少程序路径,无法写入信任。"));
        return;
    }
    if (const auto rej = bulwark::engine::TrustPolicy::rejectsWholeProcessTrust(path, false); rej.ok) {
        ui::notify(parent, ui::Tone::Danger, rej.reason);
        return;
    }
    QString scopeText;
    switch (scope) {
    case bulwark::RememberScope::Session:   scopeText = u("仅本次会话"); break;
    case bulwark::RememberScope::OneHour:   scopeText = u("1 小时"); break;
    case bulwark::RememberScope::OneDay:    scopeText = u("1 天"); break;
    case bulwark::RememberScope::Permanent: scopeText = u("永久"); break;
    }
    ui::ConfirmSpec c;
    c.risk = scope == bulwark::RememberScope::Permanent ? ui::Risk::Danger : ui::Risk::Caution;
    c.title = u("信任此程序(纠正误拦)");
    c.summary = u("添加后该程序的【全部行为】将跳过检测直接放行,有效期:%1。"
                  "这是应对规则误伤的临时例外,不是确认它绝对安全。")
                    .arg(scopeText);
    c.consequences = QStringList{
        u("信任期内不再对该程序做威胁检测 / 拦截"),
        u("若它确实是恶意软件,这段时间内将畅通无阻"),
        scope == bulwark::RememberScope::Permanent
            ? u("永久信任不会自动过期,需到「信任名单」手动移除")
            : u("到期后自动失效,无需手动清理"),
    };
    c.subjectLabel = u("程序");
    c.subject = path;
    c.confirmText = u("确认信任 %1").arg(scopeText);
    if (!ui::confirm(parent, c))
        return;
    m_ipc->addTrust(path, QStringLiteral("AI纠错·疑似规则误伤"), false, scope);
    ui::notify(parent, ui::Tone::Success,
               u("已添加信任(%1):%2").arg(scopeText, QFileInfo(path).fileName()));
}

void ToastNotifier::applyRuleDeletion(const QString& matchedRuleNote, QWidget* parent)
{
    const QString note = matchedRuleNote.trimmed();
    if (note.isEmpty()) {
        ui::notify(parent, ui::Tone::Danger, u("这次拦截没有命中具名规则,无需删除。"));
        return;
    }
    if (!m_ipc || !m_ipc->isConnected()) {
        ui::notify(parent, ui::Tone::Danger, u("未连接后台服务,无法删除规则。"));
        return;
    }
    const QPointer<IpcClient> ipc = m_ipc;
    const QPointer<QWidget> guard(parent);
    auto conn = std::make_shared<QMetaObject::Connection>();
    *conn = connect(m_ipc, &IpcClient::rulesReceived, this,
                    [note, guard, ipc, conn](const QList<bulwark::DefenseRule>& rules) {
                        QObject::disconnect(*conn);
                        if (!ipc)
                            return;
                        QWidget* parent = guard.data();
                        QList<QUuid> ids;
                        QStringList labels;
                        for (const auto& r : rules) {
                            if (r.action != bulwark::VerdictAction::Block)
                                continue;
                            if (r.note.trimmed() != note)
                                continue;
                            ids << r.id;
                            labels << (r.actorPath.isEmpty() ? r.actorPattern : r.actorPath);
                        }
                        if (ids.isEmpty()) {
                            ui::notify(parent, ui::Tone::Warning,
                                       u("没有找到备注完全相同的拦截规则,可能已被删除。"));
                            return;
                        }
                        ui::ConfirmSpec c;
                        c.risk = ui::Risk::Danger;
                        c.title = ids.size() == 1 ? u("删除命中规则")
                                                  : u("删除 %1 条命中规则").arg(ids.size());
                        c.summary = u("删除后,同样行为不再被这条规则直接拦截,会重新走默认判定流程。"
                                      "这是在纠正规则本身,不是放行某个文件。");
                        c.consequences = QStringList{
                            u("立即生效,且不可撤销(需手动重建规则)"),
                            u("若这条规则其实拦对了,删除会降低防护"),
                            u("备注:") + note,
                        };
                        c.subjectLabel = u("规则");
                        c.subject = labels.join(QStringLiteral("\n"));
                        c.confirmText = u("删除规则");
                        if (!ui::confirm(parent, c))
                            return;
                        for (const QUuid& id : ids)
                            ipc->deleteRule(id);
                        ui::notify(parent, ui::Tone::Success, u("已删除规则:%1").arg(note));
                    });
    m_ipc->requestRules();
}

void ToastNotifier::showInfo(const QString& heading, const QString& detail, int lifetimeMs,
                             const QString& actionText, const QString& actionId)
{
    auto* t = new ToastWindow(ToastWindow::Kind::Info, heading, detail, QString(), {}, lifetimeMs,
                              QString(), actionText);
    if (!actionId.isEmpty())
        connect(t, &ToastWindow::clicked, this,
                [this, actionId](ToastWindow*) { emit infoToastActivated(actionId); });
    present(t, false);
}

void ToastNotifier::showRemediation(const bulwark::ipc::RemediationReportPayload& report)
{
    // quarantinedFiles 已经包含主体本身(服务端的 actorQuarantined 正是据此判定的),不要再 +1。
    const int quarantined = int(report.quarantinedFiles.size());
    const int removed = int(report.removedRegistryValues.size());
    const int failed = int(report.skipped.size());
    const int done = quarantined + removed;

    const QString heading = failed == 0 ? u("已清理恶意足迹")
                          : done == 0   ? u("恶意足迹未能清理")
                                        : u("恶意足迹部分清理");
    const QString badge = failed == 0 ? u("已清理") : done == 0 ? u("未能清理") : u("部分清理");

    QString subject = QFileInfo(report.actorPath).fileName();
    if (subject.isEmpty())
        subject = report.reason.isEmpty() ? u("未知程序") : report.reason;
    const QString sentence = u("%1:隔离 %2 文件 · 移除 %3 持久化").arg(subject).arg(quarantined).arg(removed);
    const QString meta = failed > 0 ? u("%1 项未能清理,需手动处理").arg(failed) : QString();

    auto* t = new ToastWindow(failed == 0 ? ToastWindow::Kind::Cleanup : ToastWindow::Kind::CleanupIncomplete,
                              heading, sentence, meta, {},
                              failed == 0 ? 5000 : 9000, badge);
    present(t, false);
}

void ToastNotifier::showQuarantineRetry(const bulwark::ipc::ManualQuarantineResultPayload& result)
{
    const QString detail = result.message.trimmed().isEmpty()
                               ? (result.success ? u("已隔离") : u("未成功"))
                               : result.message.trimmed();
    auto* t = new ToastWindow(result.success ? ToastWindow::Kind::Cleanup : ToastWindow::Kind::CleanupIncomplete,
                              u("重试隔离"), detail, QString(), {},
                              result.success ? 4000 : 8000,
                              result.success ? u("已隔离") : u("未成功"));
    present(t, false);
}

void ToastNotifier::present(ToastWindow* toast, bool isBlock, bool navigateOnClick, bool unenforced)
{
    connect(toast, &ToastWindow::closed, this, &ToastNotifier::remove);
    connect(toast, &ToastWindow::resized, this, [this](ToastWindow*) { scheduleReflow(); });
    if (isBlock && navigateOnClick)
        connect(toast, &ToastWindow::clicked, this,
                [this, unenforced](ToastWindow*) { emit blockToastClicked(unenforced); });

    m_stack.prepend(toast);

    while (m_stack.size() > kMaxVisible) {
        ToastWindow* old = m_stack.takeLast();
        old->hide();
        old->deleteLater();
    }

    reflow();
}

void ToastNotifier::reflow()
{
    QScreen* screen = QGuiApplication::primaryScreen();
    if (!screen)
        return;
    const QRect area = screen->availableGeometry();
    const int margin = 22;
    const int gap = 12;

    QList<QRect> obstacles;
    for (const QPointer<QWidget>& w : std::as_const(m_cornerWindows))
        if (w && w->isVisible())
            obstacles << w->frameGeometry();

    int baselineBottom = area.bottom() - margin;
    int placed = 0;
    for (; placed < m_stack.size(); ++placed) {
        ToastWindow* t = m_stack.at(placed);
        QRect slot(area.right() - margin - t->width(), baselineBottom - t->height(),
                   t->width(), t->height());
        for (bool hopped = true; hopped;) {
            hopped = false;
            for (const QRect& o : std::as_const(obstacles)) {
                if (slot.intersects(o)) {
                    slot.moveBottom(o.top() - 1);
                    hopped = true;
                }
            }
        }
        if (slot.top() < area.top())
            break;
        t->place(slot.topLeft());
        baselineBottom = slot.top() - gap;
    }
    while (m_stack.size() > placed) {
        ToastWindow* old = m_stack.takeLast();
        old->hide();
        old->deleteLater();
    }
}

void ToastNotifier::scheduleReflow()
{
    if (m_reflowPending)
        return;
    m_reflowPending = true;
    QTimer::singleShot(0, this, [this] {
        m_reflowPending = false;
        reflow();
    });
}

void ToastNotifier::reserveCorner(QWidget* window)
{
    m_cornerWindows.removeIf([](const QPointer<QWidget>& p) { return p.isNull(); });
    if (!window || m_cornerWindows.contains(window))
        return;
    m_cornerWindows.append(window);
    window->installEventFilter(this);
    scheduleReflow();
}

void ToastNotifier::releaseCorner(QWidget* window)
{
    if (!window)
        return;
    window->removeEventFilter(this);
    m_cornerWindows.removeAll(window);
    scheduleReflow();
}

bool ToastNotifier::eventFilter(QObject* watched, QEvent* event)
{
    switch (event->type()) {
    case QEvent::Show:
    case QEvent::Hide:
    case QEvent::Move:
    case QEvent::Resize:
        if (auto* w = qobject_cast<QWidget*>(watched); w && m_cornerWindows.contains(w))
            scheduleReflow();
        break;
    default:
        break;
    }
    return QObject::eventFilter(watched, event);
}

void ToastNotifier::remove(ToastWindow* toast)
{
    m_stack.removeAll(toast);
    reflow();
}

void ToastNotifier::flushSuppressed()
{
    const int blocked = m_suppressedBlocks;
    const int unenforced = m_suppressedUnenforced;
    if (blocked <= 0 && unenforced <= 0)
        return;
    m_suppressedBlocks = 0;
    m_suppressedUnenforced = 0;
    m_lastBlockToastMs = QDateTime::currentMSecsSinceEpoch();

    const int total = blocked + unenforced;
    if (unenforced <= 0) {
        auto* t = new ToastWindow(ToastWindow::Kind::Block,
                                  u("已批量拦截危险行为"),
                                  u("短时间内共拦截 %1 项").arg(blocked),
                                  u("磐垒已自动处置,无需手动操作"),
                                  {}, 6000, u("已拦截"), u("查看拦截记录 ›"));
        present(t, true);
        emit blockBatchPresented(blocked, 0);
        return;
    }
    auto* t = new ToastWindow(
        ToastWindow::Kind::BlockAlertedOnly,
        u("批量处置:有未能拦截的项"),
        blocked > 0 ? u("短时间内共 %1 项,其中 %2 项已拦下、%3 项未能拦截")
                          .arg(total).arg(blocked).arg(unenforced)
                    : u("短时间内共 %1 项危险行为未能拦截").arg(unenforced),
        u("未能拦截的动作已经发生,需要你手动处理"),
        {}, 12000, u("需人工处理"), u("查看拦截记录 ›"));
    present(t, true, true, true);
    emit blockBatchPresented(blocked, unenforced);
}

void ToastNotifier::pruneRecentKeys(qint64 nowMs)
{
    if (m_recentBlockKeys.size() <= 512)
        return;
    for (auto it = m_recentBlockKeys.begin(); it != m_recentBlockKeys.end(); ) {
        if (nowMs - it.value() > kDedupWindowMs)
            it = m_recentBlockKeys.erase(it);
        else
            ++it;
    }
    if (m_recentBlockKeys.size() > 4096)
        m_recentBlockKeys.clear();
}
