#pragma once
#include <QRegularExpression>
#include <QSet>
#include <QString>
#include <QStringList>

#include <functional>

namespace bulwark::service {

class RegistryRollbackPolicy {
public:
    enum class Decision {
        Rollback,
        KeepTrusted,
        KeepUnjudgeable,
    };

    struct Deps {
        std::function<QString(const QString&)> expandEnv;
        std::function<bool(const QString&)> exists;
        std::function<bool(const QString&)> isUserTrusted;
        std::function<bool(const QString&)> isSigned;
        QString systemRoot = QStringLiteral("C:\\Windows");
    };

    static bool isScriptHostOrLolbin(const QString& path) {
        static const QSet<QString> k = {
            QStringLiteral("powershell.exe"), QStringLiteral("pwsh.exe"), QStringLiteral("cmd.exe"),
            QStringLiteral("wscript.exe"), QStringLiteral("cscript.exe"), QStringLiteral("mshta.exe"),
            QStringLiteral("rundll32.exe"), QStringLiteral("regsvr32.exe"), QStringLiteral("certutil.exe"),
            QStringLiteral("msiexec.exe"), QStringLiteral("wmic.exe"), QStringLiteral("bitsadmin.exe"),
            QStringLiteral("cmstp.exe"), QStringLiteral("installutil.exe"), QStringLiteral("regasm.exe"),
            QStringLiteral("regsvcs.exe"), QStringLiteral("msbuild.exe"), QStringLiteral("forfiles.exe"),
            QStringLiteral("pcalua.exe"), QStringLiteral("odbcconf.exe"),
            QStringLiteral("python.exe"), QStringLiteral("pythonw.exe"), QStringLiteral("py.exe"),
            QStringLiteral("pyw.exe"), QStringLiteral("node.exe"), QStringLiteral("deno.exe"),
            QStringLiteral("bun.exe"), QStringLiteral("java.exe"), QStringLiteral("javaw.exe"),
            QStringLiteral("ruby.exe"), QStringLiteral("rubyw.exe"), QStringLiteral("perl.exe"),
            QStringLiteral("php.exe"), QStringLiteral("lua.exe"), QStringLiteral("wsl.exe"),
            QStringLiteral("bash.exe"), QStringLiteral("sh.exe"), QStringLiteral("autohotkey.exe"),
            QStringLiteral("autohotkey32.exe"), QStringLiteral("autohotkey64.exe"),
            QStringLiteral("autohotkeyu32.exe"), QStringLiteral("autohotkeyu64.exe"),
            QStringLiteral("autoit3.exe"),
        };
        return k.contains(fileNameOf(path).toLower());
    }

    struct Parsed {
        QStringList programs;
        QStringList payloads;
        bool hostSeen = false;
    };

    static Parsed parse(const QString& valueName, const QString& data, const Deps& d) {
        Parsed out;
        const QString expanded = d.expandEnv ? d.expandEnv(data) : data;
        const QString vn = valueName.trimmed().toLower();
        QStringList commands;
        if (vn == QLatin1String("shell") || vn == QLatin1String("userinit")) {
            for (const QString& piece : expanded.split(QLatin1Char(',')))
                if (!piece.trimmed().isEmpty()) commands << piece.trimmed();
        } else if (!expanded.trimmed().isEmpty()) {
            commands << expanded.trimmed();
        }
        for (const QString& c : commands) {
            QString rest;
            const QString prog = firstProgram(c, d, &rest);
            if (prog.isEmpty()) continue;
            out.programs << prog;
            if (isScriptHostOrLolbin(prog)) {
                out.hostSeen = true;
                out.payloads << payloadPaths(rest);
            }
        }
        return out;
    }

    static Decision judge(const QString& valueName, const QString& data, const Deps& d,
                          QString* why = nullptr) {
        const Parsed p = parse(valueName, data, d);

        // 宿主/LOLBin 命令行里没有载荷路径即回滚:宿主自己的签名不能替参数背书。不要求宿主路径能解析
        // (powershell.exe 不在 %SystemRoot% 与 System32 根下)。声明的载荷都不在磁盘上则不判定。
        if (p.hostSeen) {
            if (p.payloads.isEmpty()) {
                if (why) *why = QStringLiteral("脚本宿主 / LOLBin 的光杆调用(命令行里没有任何载荷文件路径可核对)");
                return Decision::Rollback;
            }
            bool anyPayloadExists = false;
            for (const QString& pl : p.payloads)
                if (d.exists && d.exists(pl)) { anyPayloadExists = true; break; }
            if (!anyPayloadExists) {
                if (why) *why = QStringLiteral("命令行声明的载荷文件此刻不在磁盘上(安装器可能先写注册表后拷文件),不判定、不回滚");
                return Decision::KeepUnjudgeable;
            }
        }

        {
            const QString vn = valueName.trimmed().toLower();
            if (vn == QLatin1String("shell") || vn == QLatin1String("userinit")) {
                QStringList missing;
                for (const QString& t : p.programs)
                    if (!t.isEmpty() && !isScriptHostOrLolbin(t) && !(d.exists && d.exists(t)))
                        missing << t;
                if (!missing.isEmpty()) {
                    if (why) *why = QStringLiteral("Winlogon 程序列表里出现此刻不存在的程序:%1").arg(missing.join(QStringLiteral(" | ")));
                    return Decision::Rollback;
                }
            }
        }

        QStringList existing;
        for (const QString& t : p.programs + p.payloads)
            if (!t.isEmpty() && d.exists && d.exists(t) && !existing.contains(t, Qt::CaseInsensitive))
                existing << t;
        if (existing.isEmpty()) {
            if (why) *why = QStringLiteral("值数据里解析不出任何已存在的文件(安装器可能先写注册表后拷文件),不判定、不回滚");
            return Decision::KeepUnjudgeable;
        }

        // 每个存在的目标都必须是用户加白/自身组件/有效签名;宿主本身跳过,它的载荷在这里逐个核对。
        QStringList uncovered;
        for (const QString& t : existing) {
            if (d.isUserTrusted && d.isUserTrusted(t)) continue;
            if (isScriptHostOrLolbin(t)) continue;
            if (d.isSigned && d.isSigned(t)) continue;
            uncovered << t;
        }
        if (!uncovered.isEmpty()) {
            if (why) *why = QStringLiteral("目标未加白且无有效签名:%1").arg(uncovered.join(QStringLiteral(" | ")));
            return Decision::Rollback;
        }
        if (why) *why = QStringLiteral("全部目标已加白或带有效签名:%1").arg(existing.join(QStringLiteral(" | ")));
        return Decision::KeepTrusted;
    }

private:
    static QString fileNameOf(const QString& path) {
        QString p = path;
        p.replace(QLatin1Char('/'), QLatin1Char('\\'));
        const int i = p.lastIndexOf(QLatin1Char('\\'));
        return i < 0 ? p : p.mid(i + 1);
    }
    static QString norm(QString p) {
        p = p.trimmed();
        p.replace(QLatin1Char('/'), QLatin1Char('\\'));
        return p;
    }
    static bool isAbsolute(const QString& p) {
        return (p.size() >= 3 && p.at(1) == QLatin1Char(':') && p.at(2) == QLatin1Char('\\'))
            || p.startsWith(QLatin1String("\\\\"));
    }

    static QString firstProgram(const QString& cmdIn, const Deps& d, QString* restOut) {
        const QString cmd = cmdIn.trimmed();
        if (restOut) restOut->clear();
        if (cmd.isEmpty()) return QString();
        QString prog, rest;
        if (cmd.startsWith(QLatin1Char('"'))) {
            const int end = cmd.indexOf(QLatin1Char('"'), 1);
            if (end > 0) { prog = cmd.mid(1, end - 1); rest = cmd.mid(end + 1); }
            else { prog = cmd.mid(1); }
        } else {
            bool found = false;
            for (int i = 0; i < cmd.size(); ++i) {
                if (cmd.at(i) != QLatin1Char(' ')) continue;
                const QString cand = norm(cmd.left(i));
                if (isAbsolute(cand) && d.exists && d.exists(cand)) {
                    prog = cand; rest = cmd.mid(i + 1); found = true;
                    break;
                }
            }
            if (!found) {
                const QString whole = norm(cmd);
                if (isAbsolute(whole) && d.exists && d.exists(whole)) {
                    prog = whole; found = true;
                }
            }
            if (!found) {
                const int sp = cmd.indexOf(QLatin1Char(' '));
                if (sp < 0) prog = cmd;
                else { prog = cmd.left(sp); rest = cmd.mid(sp + 1); }
            }
        }
        prog = norm(prog);
        if (!prog.isEmpty() && !prog.contains(QLatin1Char('\\'))) {
            const QString root = norm(d.systemRoot);
            for (const QString& dir : { root, root + QStringLiteral("\\System32") }) {
                const QString cand = dir + QLatin1Char('\\') + prog;
                if (d.exists && d.exists(cand)) { prog = cand; break; }
            }
        }
        if (restOut) *restOut = rest.trimmed();
        return prog;
    }

    static QStringList payloadPaths(const QString& rest) {
        static const QRegularExpression re(
            QStringLiteral("[A-Za-z]:\\\\[^\"'<>|*?,;]*?\\.(?:dll|exe|scr|cpl|ocx|sys|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|bat|cmd|lnk|msi|py|pyw|pyc|jar|rb|pl|php|lua|sh|mjs|cjs|ahk|au3)(?![A-Za-z0-9_])"),
            QRegularExpression::CaseInsensitiveOption);
        QStringList out;
        QRegularExpressionMatchIterator it = re.globalMatch(rest);
        while (it.hasNext()) {
            const QString m = norm(it.next().captured(0));
            if (!m.isEmpty() && !out.contains(m, Qt::CaseInsensitive)) out << m;
        }
        return out;
    }
};

}
