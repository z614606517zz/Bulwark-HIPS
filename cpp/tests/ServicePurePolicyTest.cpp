#include "bulwark/ReleaseTrust.h"
#include "bulwark/service/AmsiContentPolicy.h"
#include "bulwark/service/FilelessPolicy.h"
#include "bulwark/service/SensitiveDataGuardPolicy.h"

#include <QByteArray>
#include <QString>

#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <iterator>

namespace {

int g_fail = 0;
int g_total = 0;

void check(bool ok, const char* what) {
    ++g_total;
    if (!ok) ++g_fail;
    std::printf("  %s %s\n", ok ? "PASS" : "FAIL", what);
}

QByteArray utf16le(const QString& s, bool bom) {
    QByteArray out;
    if (bom) out.append("\xFF\xFE", 2);
    out.append(reinterpret_cast<const char*>(s.utf16()), s.size() * 2);
    return out;
}

QByteArray bytes(std::initializer_list<int> v) {
    QByteArray b;
    for (int x : v) b.append(static_cast<char>(x));
    return b;
}

void testDecode() {
    using bulwark::service::amsi_content::decodeContent;
    const QString script = QStringLiteral("Write-Host 'hi'; IEX $x");

    check(decodeContent(QByteArray(), true).isEmpty(), "decode: 空缓冲 -> 空串");
    check(decodeContent(utf16le(script, true), false) == script,
          "decode: UTF-16LE BOM -> 正确解码(无视提示)");
    check(decodeContent(utf16le(script, false), false) == script,
          "decode: 无 BOM 的 UTF-16LE ASCII -> 按奇数位 0 判出(提示说不是也照判)");
    check(decodeContent(QByteArray("\xEF\xBB\xBF") + script.toUtf8(), true) == script,
          "decode: UTF-8 BOM -> 正确解码(提示说 UTF-16 也不信)");
    check(decodeContent(script.toUtf8(), true) == script,
          "decode: 无 BOM 的 UTF-8 -> 不被 UTF-16 提示带偏");
    const QString cn = QStringLiteral("下载并执行");
    check(decodeContent(cn.toUtf8(), false) == cn, "decode: UTF-8 中文");
}

void testScriptType() {
    using bulwark::engine::ScriptType;
    using bulwark::service::amsi_content::scriptTypeFor;
    check(scriptTypeFor(QStringLiteral("PowerShell_C:\\x\\powershell.exe_10.0"), QString())
              == ScriptType::PowerShell,
          "type: PowerShell 宿主名 -> PowerShell");
    check(scriptTypeFor(QStringLiteral("pwsh"), QString()) == ScriptType::PowerShell,
          "type: pwsh -> PowerShell");
    check(scriptTypeFor(QStringLiteral("VBScript"), QString()) == ScriptType::Vbscript,
          "type: VBScript -> Vbscript");
    check(scriptTypeFor(QStringLiteral("JScript"), QString()) == ScriptType::Javascript,
          "type: JScript -> Javascript");
    check(scriptTypeFor(QStringLiteral("SomeHost"), QString()) == ScriptType::Unknown,
          "type: 未知宿主、无内容名 -> Unknown");
}

void testBypassStub() {
    using bulwark::service::fileless_policy::isKnownBypassStub;
    check(isKnownBypassStub(bytes({0xC3})), "stub: ret");
    check(isKnownBypassStub(bytes({0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3})),
          "stub: mov eax,E_INVALIDARG; ret");
    check(isKnownBypassStub(bytes({0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00})),
          "stub: mov eax,E_INVALIDARG; ret imm16");
    check(isKnownBypassStub(bytes({0x31, 0xC0, 0xC3})), "stub: xor eax,eax; ret (31)");
    check(isKnownBypassStub(bytes({0x33, 0xC0, 0xC3})), "stub: xor eax,eax; ret (33)");
    check(isKnownBypassStub(bytes({0x48, 0x31, 0xC0, 0xC3})), "stub: xor rax,rax; ret");
    check(isKnownBypassStub(bytes({0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3})), "stub: mov eax,0; ret");

    check(!isKnownBypassStub(QByteArray()), "stub: 空字节 -> 不报");
    check(!isKnownBypassStub(bytes({0xE9, 0x10, 0x20, 0x30, 0x40})), "stub: E9 jmp hook -> 不报");
    check(!isKnownBypassStub(bytes({0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x08})),
          "stub: 正常 x64 序言 -> 不报");
    check(!isKnownBypassStub(bytes({0xB8, 0x57, 0x00, 0x07, 0x80})),
          "stub: 补丁被截断(缺 ret)-> 不报");
    check(!isKnownBypassStub(bytes({0x31, 0xC0, 0x90})), "stub: xor eax,eax 后不是 ret -> 不报");
}

void testSignerThumbprint() {
    const char* t = BULWARK_RELEASE_SIGNER_THUMBPRINT;
    bool hex = std::strlen(t) == 40;
    for (const char* p = t; hex && *p; ++p)
        hex = (*p >= '0' && *p <= '9') || (*p >= 'A' && *p <= 'F') || (*p >= 'a' && *p <= 'f');
    check(hex, "signer: 指纹是 40 位十六进制(sign-binaries.ps1 的正则要求)");
}

void testSensitiveDataGuard() {
    using namespace bulwark::service::sensitive_data_guard;

    const QStringList builtins = composeEntries(true, {});
    check(builtins.size() == static_cast<int>(std::size(kBuiltins)), "readguard: 内置条目全部有效且不重复");
    check(builtins.contains(QStringLiteral("\\Google\\Chrome\\User Data\\|\\Google\\Chrome\\Application\\;"
                                           "\\Google\\Update\\")),
          "readguard: Chrome 条目原样下发");
    bool wellFormed = true;
    for (const QString& e : builtins) {
        const int bar = e.indexOf(QLatin1Char('|'));
        const QString data = bar < 0 ? e : e.left(bar);
        wellFormed = wellFormed && e.size() < 520 && data.size() >= 4 && data.startsWith(QLatin1Char('\\'))
                     && !e.contains(QLatin1Char(':'));
    }
    check(wellFormed, "readguard: 内置条目都短于内核上限、无盘符、数据片段以 '\\' 开头");
    check(composeEntries(false, {}).isEmpty(), "readguard: 关掉内置条目且无自定义 -> 空");

    const QStringList custom = composeEntries(false, {
        QStringLiteral("D:\\Wallets\\MyCoin\\|C:\\Program Files\\MyCoin\\;"
                       "C:\\Users\\me\\AppData\\Local\\MyCoin\\bin\\coin.exe"),
        QStringLiteral("D:/Secret/Stuff/"),
        QStringLiteral("\\wallets\\mycoin\\|\\MyCoin\\;\\MyCoin\\bin\\coin.exe"),
        QStringLiteral("\\a|\\X\\"),
        QStringLiteral("|\\X\\"),
        QStringLiteral("\\Data\\Only\\|C:\\Program Files\\;;"),
    });
    check(custom.size() == 3, "readguard: 自定义条目去重、过滤过短数据片段");
    check(custom.value(0) == QStringLiteral("\\Wallets\\MyCoin\\|\\MyCoin\\;\\MyCoin\\bin\\coin.exe"),
          "readguard: 去盘符,读者完整路径换算成安装根之后");
    check(custom.value(1) == QStringLiteral("\\Secret\\Stuff\\"), "readguard: 正斜杠归一,没有读者就不带 '|'");
    check(custom.value(2) == QStringLiteral("\\Data\\Only\\"), "readguard: 只写安装根本身的读者被丢掉");
}


}

int main() {
    std::printf("=== service pure policy unit ===\n");
    testDecode();
    testScriptType();
    testBypassStub();
    testSignerThumbprint();
    testSensitiveDataGuard();
    std::printf("%d/%d passed\n", g_total - g_fail, g_total);
    return g_fail == 0 ? 0 : 1;
}
