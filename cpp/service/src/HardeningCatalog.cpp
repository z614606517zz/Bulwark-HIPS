#include "bulwark/service/HardeningCatalog.h"

#include "bulwark/service/AtomicFile.h"
#include "bulwark/service/RegistryUtil.h"
#include "bulwark/service/SystemHardening.h"

#include <QDateTime>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <utility>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace bulwark::service {

namespace {

using regutil::Hive;
using regutil::kRegDword;
using regutil::kRegSz;

constexpr const char* kUacSub = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";

const QStringList& scriptProgIds() {
    static const QStringList l = {
        QStringLiteral("VBSFile"), QStringLiteral("VBEFile"), QStringLiteral("JSFile"),
        QStringLiteral("JSEFile"), QStringLiteral("WSFFile"), QStringLiteral("WSHFile"),
        QStringLiteral("htafile"),
    };
    return l;
}

QString extOf(const QString& progId) {
    if (progId == QLatin1String("VBSFile")) return QStringLiteral(".vbs");
    if (progId == QLatin1String("VBEFile")) return QStringLiteral(".vbe");
    if (progId == QLatin1String("JSFile")) return QStringLiteral(".js");
    if (progId == QLatin1String("JSEFile")) return QStringLiteral(".jse");
    if (progId == QLatin1String("WSFFile")) return QStringLiteral(".wsf");
    if (progId == QLatin1String("WSHFile")) return QStringLiteral(".wsh");
    return QStringLiteral(".hta");
}

QString notepadPath() {
    wchar_t buf[MAX_PATH] = {};
    const UINT n = ::GetSystemDirectoryW(buf, MAX_PATH);
    const QString dir = (n > 0 && n < MAX_PATH) ? QString::fromWCharArray(buf, static_cast<int>(n))
                                               : QStringLiteral("C:\\Windows\\System32");
    return dir + QStringLiteral("\\notepad.exe");
}

Hive hiveOf(const QString& name) {
    return name == QLatin1String("HKU") ? Hive::Users : Hive::Machine;
}

QString userAdvancedSub(const QString& sid) {
    return sid + QStringLiteral("\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced");
}

const QString kLlmnrSub = QStringLiteral("SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient");
const QString kLsaSub = QStringLiteral("SYSTEM\\CurrentControlSet\\Control\\Lsa");

}

HardeningCatalog::HardeningCatalog(SystemHardening* legacy, QString statePath)
    : legacy_(legacy), statePath_(std::move(statePath)) {
    if (statePath_.isEmpty())
        statePath_ = programDataDir() + QStringLiteral("/hardening-state.json");
    loadState();
}

bool HardeningCatalog::isKnown(const QString& id) {
    static const QStringList k = {
        QStringLiteral("ScriptHostAssoc"), QStringLiteral("ShowFileExt"), QStringLiteral("Llmnr"),
        QStringLiteral("RunAsPPL"),        QStringLiteral("UacEnabled"),  QStringLiteral("SmartScreen"),
        QStringLiteral("Firewall"),        QStringLiteral("Rdp"),         QStringLiteral("SelfServiceDacl"),
    };
    return k.contains(id);
}

void HardeningCatalog::loadState() {
    state_.clear();
    QFile f(statePath_);
    if (!f.exists() || !f.open(QIODevice::ReadOnly))
        return;
    QJsonParseError pe;
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
        log_.warning(QStringLiteral("加固目录:撤销记录文件损坏(%1),已忽略。已应用的加固在界面上将不再提供一键撤销;"
                                    "手动撤销方法见各项说明。").arg(pe.errorString()));
        return;
    }
    const QJsonObject items = doc.object().value(QLatin1String("items")).toObject();
    for (auto it = items.constBegin(); it != items.constEnd(); ++it) {
        const QJsonObject o = it.value().toObject();
        ItemState st;
        st.appliedUtc = o.value(QLatin1String("appliedUtc")).toString();
        st.needsReboot = o.value(QLatin1String("needsReboot")).toBool();
        for (const QJsonValue& v : o.value(QLatin1String("ops")).toArray()) {
            const QJsonObject po = v.toObject();
            RegOp op;
            op.hive = po.value(QLatin1String("hive")).toString();
            op.sub = po.value(QLatin1String("sub")).toString();
            op.name = po.value(QLatin1String("name")).toString();
            op.existed = po.value(QLatin1String("existed")).toBool();
            op.type = static_cast<quint32>(po.value(QLatin1String("type")).toInt());
            op.data = po.value(QLatin1String("data")).toString();
            st.ops << op;
        }
        for (const QJsonValue& v : o.value(QLatin1String("created")).toArray())
            st.created << v.toString();
        if (!st.ops.isEmpty())
            state_.insert(it.key(), st);
    }
}

void HardeningCatalog::saveState() const {
    QJsonObject items;
    for (auto it = state_.constBegin(); it != state_.constEnd(); ++it) {
        QJsonObject o;
        o["appliedUtc"] = it->appliedUtc;
        o["needsReboot"] = it->needsReboot;
        QJsonArray ops;
        for (const RegOp& op : it->ops) {
            QJsonObject po;
            po["hive"] = op.hive;
            po["sub"] = op.sub;
            po["name"] = op.name;
            po["existed"] = op.existed;
            po["type"] = static_cast<int>(op.type);
            po["data"] = op.data;
            ops.append(po);
        }
        o["ops"] = ops;
        QJsonArray created;
        for (const QString& c : it->created)
            created.append(c);
        o["created"] = created;
        items[it.key()] = o;
    }
    QJsonObject root;
    root["version"] = 1;
    root["items"] = items;
    if (!writeFileAtomically(statePath_, QJsonDocument(root).toJson(QJsonDocument::Indented),
                             QStringLiteral("加固撤销记录")))
        log_.warning(QStringLiteral("加固目录:撤销记录写入失败 —— 已做的改动无法在界面上一键撤销:%1").arg(statePath_));
}

bool HardeningCatalog::setTracked(const QString& hive, const QString& sub, const QString& name,
                                  quint32 type, const QString& text, ItemState* st, QString* err) {
    const Hive h = hiveOf(hive);
    const regutil::Value cur = regutil::readValue(h, sub, name);
    if (cur.present && !cur.supported) {
        *err = QStringLiteral("%1\\%2 的原值类型不受支持(%3),为了保证可撤销,不改它。")
                   .arg(hive, sub, cur.text);
        return false;
    }
    QStringList created;
    if (!regutil::keyExists(h, sub)) {
        quint32 e = 0;
        if (!regutil::createKeyPath(h, sub, &created, &e)) {
            for (const QString& c : std::as_const(created))
                st->created << hive + QLatin1Char('|') + c;
            *err = QStringLiteral("无法创建键 %1\\%2(错误 %3)。").arg(hive, sub).arg(e);
            return false;
        }
        for (const QString& c : std::as_const(created))
            st->created << hive + QLatin1Char('|') + c;
    }
    RegOp op;
    op.hive = hive;
    op.sub = sub;
    op.name = name;
    op.existed = cur.present;
    op.type = cur.type;
    op.data = cur.text;
    st->ops << op;
    quint32 e = 0;
    if (!regutil::writeValue(h, sub, name, type, text, &e)) {
        *err = QStringLiteral("写入 %1\\%2 失败(错误 %3)。").arg(hive, sub).arg(e);
        return false;
    }
    return true;
}

bool HardeningCatalog::undo(const ItemState& st, QString* err) {
    bool ok = true;
    QStringList failures;
    for (int i = static_cast<int>(st.ops.size()) - 1; i >= 0; --i) {
        const RegOp& op = st.ops[i];
        const Hive h = hiveOf(op.hive);
        quint32 e = 0;
        bool done = false;
        if (op.existed) {
            if (!regutil::keyExists(h, op.sub)) {
                QStringList created;
                regutil::createKeyPath(h, op.sub, &created, &e);
            }
            done = regutil::writeValue(h, op.sub, op.name, op.type, op.data, &e);
        } else {
            done = regutil::deleteValue(h, op.sub, op.name, &e);
        }
        if (!done) {
            ok = false;
            failures << QStringLiteral("%1\\%2[%3](错误 %4)").arg(op.hive, op.sub, op.name).arg(e);
        }
    }
    for (int i = static_cast<int>(st.created.size()) - 1; i >= 0; --i) {
        const QString& c = st.created[i];
        const int bar = c.indexOf(QLatin1Char('|'));
        if (bar <= 0)
            continue;
        regutil::deleteKeyIfEmpty(hiveOf(c.left(bar)), c.mid(bar + 1));
    }
    if (!ok)
        *err = QStringLiteral("以下项没能还原:%1").arg(failures.join(QStringLiteral(";")));
    return ok;
}

HardeningCatalog::Result HardeningCatalog::applyScriptAssoc() {
    ItemState st;
    QString err;
    int total = 0;
    for (const QString& pid : scriptProgIds()) {
        const QString base = QStringLiteral("SOFTWARE\\Classes\\") + pid;
        if (!regutil::keyExists(Hive::Machine, base))
            continue;
        ++total;
        const QString shell = base + QStringLiteral("\\Shell");
        const QString editCmd = shell + QStringLiteral("\\Edit\\Command");
        bool ok = true;
        const regutil::Value ec = regutil::readValue(Hive::Machine, editCmd, QString());
        if (!ec.present || ec.text.trimmed().isEmpty()) {
            ok = setTracked(QStringLiteral("HKLM"), editCmd, QString(), kRegSz,
                            QStringLiteral("\"") + notepadPath() + QStringLiteral("\" \"%1\""), &st, &err);
        }
        if (ok) {
            const regutil::Value def = regutil::readValue(Hive::Machine, shell, QString());
            if (!(def.present && def.text.compare(QStringLiteral("Edit"), Qt::CaseInsensitive) == 0))
                ok = setTracked(QStringLiteral("HKLM"), shell, QString(), kRegSz, QStringLiteral("Edit"), &st,
                                &err);
        }
        if (!ok) {
            QString undoErr;
            undo(st, &undoErr);
            log_.warning(QStringLiteral("加固:脚本文件关联应用失败,已回退本次改动 —— %1%2")
                             .arg(err, undoErr.isEmpty() ? QString() : QStringLiteral("(回退时又遇到:%1)").arg(undoErr)));
            return {false, false, QStringLiteral("没能应用:%1(本次已做的改动已回退)").arg(err)};
        }
    }
    if (total == 0)
        return {false, false, QStringLiteral("这台机器上没有登记 .vbs / .js / .hta 一类脚本的打开方式,无需处理。")};
    if (st.ops.isEmpty())
        return {true, false, QStringLiteral("这几类脚本已经是双击用记事本打开,没有需要改的。")};

    st.appliedUtc = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
    ItemState& dst = state_[QStringLiteral("ScriptHostAssoc")];
    if (dst.appliedUtc.isEmpty())
        dst.appliedUtc = st.appliedUtc;
    dst.ops += st.ops;
    dst.created += st.created;
    saveState();
    log_.warning(QStringLiteral("加固:已把 %1 类脚本文件(.vbs .vbe .js .jse .wsf .wsh .hta)的默认动作改为「编辑」"
                                "(记事本),共 %2 处写入,已记录原样供撤销。")
                     .arg(total)
                     .arg(st.ops.size()));
    return {true, false,
            QStringLiteral("已应用:%1 类脚本文件双击将用记事本打开。对之后的双击立即生效;"
                           "命令行里直接调用 wscript / cscript / mshta 不受影响。").arg(total)};
}

HardeningCatalog::Result HardeningCatalog::applyShowFileExt() {
    const QStringList sids = regutil::interactiveUserSids();
    if (sids.isEmpty())
        return {false, false, QStringLiteral("当前没有已登录的用户,没有可改的设置。")};
    ItemState st;
    QString err;
    int users = 0;
    for (const QString& sid : sids) {
        const QString sub = userAdvancedSub(sid);
        const regutil::Value cur = regutil::readValue(Hive::Users, sub, QStringLiteral("HideFileExt"));
        if (cur.present && cur.text == QLatin1String("0"))
            continue;
        if (!setTracked(QStringLiteral("HKU"), sub, QStringLiteral("HideFileExt"), kRegDword,
                        QStringLiteral("0"), &st, &err)) {
            QString undoErr;
            undo(st, &undoErr);
            return {false, false, QStringLiteral("没能应用:%1(本次已做的改动已回退)").arg(err)};
        }
        ++users;
    }
    if (st.ops.isEmpty())
        return {true, false, QStringLiteral("所有已登录用户都已经显示文件扩展名,没有需要改的。")};
    st.appliedUtc = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
    ItemState& dst = state_[QStringLiteral("ShowFileExt")];
    if (dst.appliedUtc.isEmpty())
        dst.appliedUtc = st.appliedUtc;
    dst.ops += st.ops;
    dst.created += st.created;
    saveState();
    log_.warning(QStringLiteral("加固:已让 %1 个已登录用户显示文件扩展名(HideFileExt=0),已记录原样供撤销。").arg(users));
    return {true, false,
            QStringLiteral("已应用:%1 个用户的资源管理器将显示文件扩展名。已经打开的文件夹窗口按 F5 或重新打开即可看到。")
                .arg(users)};
}

HardeningCatalog::Result HardeningCatalog::applyLlmnr() {
    const regutil::Value cur = regutil::readValue(Hive::Machine, kLlmnrSub, QStringLiteral("EnableMulticast"));
    if (cur.present && cur.text == QLatin1String("0"))
        return {true, false, QStringLiteral("LLMNR 已经被策略关闭,没有需要改的。")};
    ItemState st;
    QString err;
    if (!setTracked(QStringLiteral("HKLM"), kLlmnrSub, QStringLiteral("EnableMulticast"), kRegDword,
                    QStringLiteral("0"), &st, &err)) {
        QString undoErr;
        undo(st, &undoErr);
        return {false, false, QStringLiteral("没能应用:%1(本次已做的改动已回退)").arg(err)};
    }
    st.appliedUtc = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
    st.needsReboot = true;
    ItemState& dst = state_[QStringLiteral("Llmnr")];
    if (dst.appliedUtc.isEmpty())
        dst.appliedUtc = st.appliedUtc;
    dst.needsReboot = true;
    dst.ops += st.ops;
    dst.created += st.created;
    saveState();
    log_.warning(QStringLiteral("加固:已设置策略 EnableMulticast=0 关闭 LLMNR(需重启或重启 DNS Client 服务后生效),已记录原样供撤销。"));
    return {true, true, QStringLiteral("已应用:LLMNR 已通过策略关闭。需要重启(或重启 DNS Client 服务)后生效。")};
}

HardeningCatalog::Result HardeningCatalog::apply(const QString& id) {
    if (id == QLatin1String("ScriptHostAssoc"))
        return applyScriptAssoc();
    if (id == QLatin1String("ShowFileExt"))
        return applyShowFileExt();
    if (id == QLatin1String("Llmnr"))
        return applyLlmnr();
    if (id == QLatin1String("RunAsPPL")) {
        const regutil::Value cur = regutil::readValue(Hive::Machine, kLsaSub, QStringLiteral("RunAsPPL"));
        if (cur.present && (cur.text == QLatin1String("1") || cur.text == QLatin1String("2")))
            return {true, false, QStringLiteral("lsass 已经启用 PPL(RunAsPPL=%1),没有需要改的。").arg(cur.text)};
        ItemState st;
        QString err;
        if (!setTracked(QStringLiteral("HKLM"), kLsaSub, QStringLiteral("RunAsPPL"),
                        kRegDword, QStringLiteral("2"), &st, &err)) {
            QString undoErr;
            undo(st, &undoErr);
            return {false, false, QStringLiteral("写入 RunAsPPL 失败:%1").arg(err)};
        }
        st.appliedUtc = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
        st.needsReboot = true;
        state_[QStringLiteral("RunAsPPL")] = st;
        saveState();
        return {true, true, QStringLiteral("已写入 RunAsPPL=2并保存原值。【需要重启才生效】;"
                                           "撤销时只恢复本次修改前的状态。")};
    }
    if (isKnown(id))
        return {false, false, QStringLiteral("这是只读的体检项,不能在这里应用。")};
    return {false, false, QStringLiteral("未知的加固项:%1").arg(id)};
}

HardeningCatalog::Result HardeningCatalog::revert(const QString& id) {
    if (id == QLatin1String("RunAsPPL")) {
        const auto it = state_.constFind(id);
        if (it == state_.constEnd())
            return {false, false, QStringLiteral("没有本产品写入 RunAsPPL 的撤销记录,不会改动现有企业/管理员策略。")};
        const ItemState st = it.value();
        QString err;
        if (!undo(st, &err))
            return {false, false, QStringLiteral("撤销 RunAsPPL 失败:%1").arg(err)};
        state_.remove(id);
        saveState();
        return {true, true, QStringLiteral("已恢复应用前的 RunAsPPL 状态。【需要重启才生效】。")};
    }
    const auto it = state_.constFind(id);
    if (it == state_.constEnd())
        return {false, false, QStringLiteral("没有这一项的撤销记录 —— 它不是由本产品施加的(或记录已丢失),"
                                             "所以这里不替你撤销。")};
    const ItemState st = it.value();
    QString err;
    if (!undo(st, &err)) {
        log_.warning(QStringLiteral("加固:撤销 %1 时部分失败 —— %2").arg(id, err));
        return {false, false, err};
    }
    state_.remove(id);
    saveState();
    log_.warning(QStringLiteral("加固:已撤销 %1,回到应用之前的样子(%2 处写入已逐一还原)。").arg(id).arg(st.ops.size()));
    return {true, st.needsReboot,
            st.needsReboot ? QStringLiteral("已撤销,回到应用之前的样子。需要重启(或重启 DNS Client 服务)后生效。")
                           : QStringLiteral("已撤销,回到应用之前的样子。")};
}

QVector<ipc::HardeningItemPayload> HardeningCatalog::inspect() const {
    using ipc::HardeningItemPayload;
    QVector<HardeningItemPayload> out;
    const auto noteNotOurs = [](HardeningItemPayload& it) {
        if (it.satisfied && !it.revertible)
            it.note = QStringLiteral("已满足,但不是由本产品施加的(或撤销记录已丢失),所以这里不提供撤销。");
    };

    {
        HardeningItemPayload it;
        it.id = QStringLiteral("ScriptHostAssoc");
        it.group = QStringLiteral("harden");
        it.title = QStringLiteral("双击脚本文件时用记事本打开,而不是直接运行");
        QStringList present, bad;
        for (const QString& pid : scriptProgIds()) {
            const QString base = QStringLiteral("SOFTWARE\\Classes\\") + pid;
            if (!regutil::keyExists(Hive::Machine, base))
                continue;
            present << extOf(pid);
            const regutil::Value def = regutil::readValue(Hive::Machine, base + QStringLiteral("\\Shell"), QString());
            const regutil::Value ec =
                regutil::readValue(Hive::Machine, base + QStringLiteral("\\Shell\\Edit\\Command"), QString());
            const bool ok = def.present && def.text.compare(QStringLiteral("Edit"), Qt::CaseInsensitive) == 0
                            && ec.present && !ec.text.trimmed().isEmpty();
            if (!ok)
                bad << extOf(pid);
        }
        it.satisfied = bad.isEmpty();
        if (present.isEmpty())
            it.current = QStringLiteral("这台机器上没有登记这类脚本的打开方式。");
        else if (bad.isEmpty())
            it.current = QStringLiteral("%1 类脚本(%2)双击都会用记事本打开。")
                             .arg(present.size()).arg(present.join(QLatin1Char(' ')));
        else
            it.current = QStringLiteral("%1 类脚本里有 %2 类双击会【直接运行】:%3")
                             .arg(present.size()).arg(bad.size()).arg(bad.join(QLatin1Char(' ')));
        it.recommended = QStringLiteral("把 .vbs / .vbe / .js / .jse / .wsf / .wsh / .hta 的默认动作改为「编辑」(记事本)。");
        it.cost = QStringLiteral("双击这些文件将不再运行,而是在记事本里打开;确实要运行时,在命令行里用 wscript / cscript / mshta "
                                 "调用,或右键选「在命令提示符中打开」后运行。"
                                 "【诚实的边界】这只挡「双击」这一条路 —— 压缩包 / 邮件附件里的 .js .vbs .hta 是最常见的"
                                 "误点入口,但恶意程序仍可以直接调用 wscript.exe,所以它是减少误点的第一道门,不是拦截。"
                                 ".wsh 与 .hta 原本没有「编辑」动作,会为它们新增一个。可在本页随时撤销。");
        it.severity = it.satisfied ? QStringLiteral("ok") : QStringLiteral("warn");
        it.actionable = !it.satisfied && !present.isEmpty();
        it.revertible = state_.contains(it.id);
        noteNotOurs(it);
        out << it;
    }

    {
        HardeningItemPayload it;
        it.id = QStringLiteral("ShowFileExt");
        it.group = QStringLiteral("harden");
        it.title = QStringLiteral("显示已知文件类型的扩展名");
        const QStringList sids = regutil::interactiveUserSids();
        int hidden = 0;
        for (const QString& sid : sids) {
            const regutil::Value v = regutil::readValue(Hive::Users, userAdvancedSub(sid), QStringLiteral("HideFileExt"));
            if (!(v.present && v.text == QLatin1String("0")))
                ++hidden;
        }
        it.satisfied = (hidden == 0);
        it.current = sids.isEmpty() ? QStringLiteral("当前没有已登录的用户。")
                     : hidden == 0  ? QStringLiteral("%1 个已登录用户都已显示扩展名。").arg(sids.size())
                                    : QStringLiteral("%1 个已登录用户里有 %2 个仍在隐藏扩展名"
                                                     "(invoice.pdf.exe 会显示成 invoice.pdf)。")
                                          .arg(sids.size()).arg(hidden);
        it.recommended = QStringLiteral("关掉资源管理器的「隐藏已知文件类型的扩展名」。");
        it.cost = QStringLiteral("文件名后会多显示 .txt .jpg 之类的扩展名;重命名时注意别把扩展名改掉。"
                                 "已经打开的文件夹窗口按 F5 或重新打开即可看到。只影响此刻已登录的用户。可在本页随时撤销。");
        it.severity = it.satisfied ? QStringLiteral("ok") : QStringLiteral("warn");
        it.actionable = !it.satisfied && !sids.isEmpty();
        it.revertible = state_.contains(it.id);
        noteNotOurs(it);
        out << it;
    }

    {
        HardeningItemPayload it;
        it.id = QStringLiteral("Llmnr");
        it.group = QStringLiteral("harden");
        it.title = QStringLiteral("关闭 LLMNR(链路本地多播名称解析)");
        const regutil::Value v = regutil::readValue(Hive::Machine, kLlmnrSub, QStringLiteral("EnableMulticast"));
        it.satisfied = v.present && v.text == QLatin1String("0");
        it.current = it.satisfied ? QStringLiteral("已通过策略关闭(EnableMulticast=0)。")
                     : v.present  ? QStringLiteral("策略 EnableMulticast=%1(LLMNR 仍启用)。").arg(v.text)
                                  : QStringLiteral("未配置(Windows 默认启用 LLMNR)。");
        it.recommended = QStringLiteral("设置策略 HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast = 0。");
        it.cost = QStringLiteral("DNS 查不到名字时,Windows 会向局域网广播询问「谁叫这个名字」。攻击者在公共 Wi-Fi 或同一局域网里"
                                 "可以假冒应答,骗走你的登录凭据(Responder 一类攻击)。关闭后,按计算机名访问没有 DNS 记录的"
                                 "局域网设备可能解析失败(改用 IP,或让路由器提供 DNS 即可)。需要重启(或重启 DNS Client 服务)"
                                 "后生效。可在本页随时撤销。");
        it.needsReboot = true;
        it.severity = it.satisfied ? QStringLiteral("ok") : QStringLiteral("info");
        it.actionable = !it.satisfied;
        it.revertible = state_.contains(it.id);
        noteNotOurs(it);
        out << it;
    }

    if (legacy_) {
        HardeningItemPayload it;
        it.id = QStringLiteral("RunAsPPL");
        it.group = QStringLiteral("harden");
        it.title = QStringLiteral("lsass 以受保护进程轻量级(PPL)运行");
        const regutil::Value v = regutil::readValue(Hive::Machine, kLsaSub, QStringLiteral("RunAsPPL"));
        it.satisfied = v.present && (v.text == QLatin1String("1") || v.text == QLatin1String("2"));
        it.current = v.present ? QStringLiteral("RunAsPPL = %1").arg(v.text)
                               : QStringLiteral("未设置(lsass 未受 PPL 保护)。");
        it.recommended = QStringLiteral("设置 RunAsPPL = 2,阻止非受保护进程读取 lsass 内存(防凭据转储)。");
        it.cost = QStringLiteral("需要重启生效。会让部分依赖读取 lsass 内存的软件失效(单点登录代理、某些企业 VPN / 指纹驱动、"
                                 "部分调试器)。本产品只写 2、不写 1:1 会把该策略写进 UEFI 变量,之后从注册表删掉也关不掉;"
                                 "2 可以随时在本页撤销(同样需要重启)。");
        it.needsReboot = true;
        it.severity = it.satisfied ? QStringLiteral("ok") : QStringLiteral("info");
        it.actionable = !it.satisfied;
        it.revertible = it.satisfied && v.text == QLatin1String("2")
            && state_.contains(it.id);
        if (v.present && v.text == QLatin1String("1"))
            it.note = QStringLiteral("当前值是 1,该状态可能已写入 UEFI 变量,本产品不会去撤销它。");
        else if (it.satisfied && !it.revertible)
            it.note = QStringLiteral("已满足,但没有本产品的原值记录,所以这里不提供撤销。");
        out << it;
    }

    {
        HardeningItemPayload it;
        it.id = QStringLiteral("UacEnabled");
        it.group = QStringLiteral("baseline");
        it.title = QStringLiteral("用户账户控制(UAC)");
        const regutil::Value lua = regutil::readValue(Hive::Machine, QString::fromLatin1(kUacSub), QStringLiteral("EnableLUA"));
        const regutil::Value cpa =
            regutil::readValue(Hive::Machine, QString::fromLatin1(kUacSub), QStringLiteral("ConsentPromptBehaviorAdmin"));
        const bool luaOn = !lua.present || lua.text != QLatin1String("0");
        const bool consentOff = cpa.present && cpa.text == QLatin1String("0");
        it.satisfied = luaOn && !consentOff;
        it.current = !luaOn      ? QStringLiteral("UAC 已关闭(EnableLUA=0)。")
                     : consentOff ? QStringLiteral("UAC 已开启,但管理员提权时不再提示(ConsentPromptBehaviorAdmin=0)。")
                                  : QStringLiteral("UAC 已开启(管理员提权提示级别 %1)。").arg(cpa.present ? cpa.text : QStringLiteral("默认"));
        it.recommended = QStringLiteral("在「控制面板 → 用户账户控制设置」里恢复默认级别;关闭 UAC 的改动要重启才生效。");
        it.cost = QStringLiteral("UAC 关闭时,以管理员身份运行的程序不再弹出确认,恶意软件拿到管理员权限无需你点一下。"
                                 "关掉 UAC 常是有意为之(旧软件兼容、自动化),所以本产品只如实报告,不替你改。");
        it.severity = it.satisfied ? QStringLiteral("ok") : (!luaOn ? QStringLiteral("danger") : QStringLiteral("warn"));
        out << it;
    }
    {
        HardeningItemPayload it;
        it.id = QStringLiteral("SmartScreen");
        it.group = QStringLiteral("baseline");
        it.title = QStringLiteral("Windows SmartScreen(下载程序的信誉检查)");
        const regutil::Value ss = regutil::readValue(
            Hive::Machine, QStringLiteral("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer"),
            QStringLiteral("SmartScreenEnabled"));
        const regutil::Value pol = regutil::readValue(
            Hive::Machine, QStringLiteral("SOFTWARE\\Policies\\Microsoft\\Windows\\System"),
            QStringLiteral("EnableSmartScreen"));
        const bool off = (ss.present && ss.text.compare(QStringLiteral("off"), Qt::CaseInsensitive) == 0)
                         || (pol.present && pol.text == QLatin1String("0"));
        it.satisfied = !off;
        QStringList facts;
        if (ss.present) facts << QStringLiteral("SmartScreenEnabled=%1").arg(ss.text);
        if (pol.present) facts << QStringLiteral("策略 EnableSmartScreen=%1").arg(pol.text);
        it.current = off ? QStringLiteral("已关闭(%1)。").arg(facts.join(QStringLiteral(";")))
                         : QStringLiteral("已启用%1。").arg(facts.isEmpty() ? QString()
                                                                         : QStringLiteral("(") + facts.join(QStringLiteral(";")) + QStringLiteral(")"));
        it.recommended = QStringLiteral("在「Windows 安全中心 → 应用和浏览器控制 → 基于声誉的保护」里开启。");
        it.cost = QStringLiteral("SmartScreen 在你运行从网上下载、口碑不明的程序时弹出警告。关闭后少一道提示;"
                                 "若是系统策略或第三方安全软件接管了它,关闭可能是正常的。本产品只如实报告,不替你改。");
        it.severity = it.satisfied ? QStringLiteral("ok") : QStringLiteral("warn");
        out << it;
    }
    {
        HardeningItemPayload it;
        it.id = QStringLiteral("Firewall");
        it.group = QStringLiteral("baseline");
        it.title = QStringLiteral("Windows 防火墙");
        struct Prof { const char* key; const char* label; };
        const Prof profs[] = {{"DomainProfile", "域"}, {"StandardProfile", "专用"}, {"PublicProfile", "公用"}};
        QStringList parts, off;
        for (const Prof& p : profs) {
            const regutil::Value v = regutil::readValue(
                Hive::Machine,
                QStringLiteral("SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\")
                    + QString::fromLatin1(p.key),
                QStringLiteral("EnableFirewall"));
            const bool isOff = v.present && v.text == QLatin1String("0");
            parts << QStringLiteral("%1=%2").arg(QString::fromUtf8(p.label), isOff ? QStringLiteral("关") : QStringLiteral("开"));
            if (isOff) off << QString::fromUtf8(p.label);
        }
        it.satisfied = off.isEmpty();
        it.current = parts.join(QStringLiteral("  "));
        it.recommended = QStringLiteral("三个配置文件都保持开启;至少「公用」不要关。");
        it.cost = QStringLiteral("如果你装了第三方防火墙并让它接管,Windows 防火墙显示为关闭可能是正常的。本产品只如实报告,不替你改。");
        it.severity = it.satisfied ? QStringLiteral("ok")
                      : off.contains(QString::fromUtf8("公用")) ? QStringLiteral("danger") : QStringLiteral("warn");
        out << it;
    }
    {
        HardeningItemPayload it;
        it.id = QStringLiteral("Rdp");
        it.group = QStringLiteral("baseline");
        it.title = QStringLiteral("远程桌面(RDP)");
        const regutil::Value deny = regutil::readValue(
            Hive::Machine, QStringLiteral("SYSTEM\\CurrentControlSet\\Control\\Terminal Server"),
            QStringLiteral("fDenyTSConnections"));
        const regutil::Value nla = regutil::readValue(
            Hive::Machine,
            QStringLiteral("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"),
            QStringLiteral("UserAuthentication"));
        const bool enabled = deny.present && deny.text == QLatin1String("0");
        const bool nlaOn = nla.present && nla.text == QLatin1String("1");
        it.satisfied = !enabled;
        it.current = !enabled ? QStringLiteral("已关闭。")
                     : nlaOn  ? QStringLiteral("已开启,网络级别身份验证(NLA)已启用。")
                              : QStringLiteral("已开启,且【没有】启用网络级别身份验证(NLA)。");
        it.recommended = QStringLiteral("不需要远程桌面就保持关闭;需要的话保持 NLA 开启、使用强口令,并且不要把 3389 端口暴露到公网。");
        it.cost = QStringLiteral("本产品只如实报告,不替你开关远程桌面。");
        it.severity = it.satisfied ? QStringLiteral("ok") : (nlaOn ? QStringLiteral("info") : QStringLiteral("warn"));
        out << it;
    }
    if (legacy_) {
        for (const SystemHardening::Finding& f : legacy_->inspect()) {
            if (f.id != QLatin1String("SelfServiceDacl"))
                continue;
            HardeningItemPayload it;
            it.id = f.id;
            it.group = QStringLiteral("baseline");
            it.title = f.title;
            it.satisfied = f.satisfied;
            it.current = f.satisfied ? QStringLiteral("宽泛主体已无停止 / 改配置 / 删除权限。") : f.current;
            it.recommended = f.recommended;
            it.cost = f.cost;
            it.severity = f.satisfied ? QStringLiteral("ok") : QStringLiteral("info");
            it.note = f.satisfied ? QString()
                                  : QStringLiteral("此项没有配对的撤销动作(无法还原原有的服务权限描述符),所以不放在界面上应用;"
                                                   "需要的话由部署方在 appsettings.json 里开启 ApplySelfServiceDacl。");
            out << it;
        }
    }
    return out;
}

}
