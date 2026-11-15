// bulwark_yarac:YARA 的编译与扫描都在这个辅助进程里做,崩溃或卡死只影响它自己。
//
// 编译:把下载来的 YARA Forge 规则包解压并编译成 YARA-X 的二进制规则。规则包来自网络,
// 服务按退出码和报告决定是否换上新规则。编不过、或被 YARA-X 判为过慢的规则逐条剔除,
// 不影响其余规则。
//
//   bulwark_yarac --zip <包.zip> --out <规则.yarc> --report <报告.json>
//   bulwark_yarac --yar <规则.yar> --out <规则.yarc> --report <报告.json>
//
// 扫描:常驻,载入编译好的规则后从标准输入逐行收「编号<TAB>文件路径」(UTF-8),
// 每个文件读进内存、算 SHA-256、扫描,向标准输出回一行 JSON。扫描的就是算哈希的那份内容。
//
//   bulwark_yarac --serve --rules <规则.yarc> [--timeout <秒>] [--max-bytes <字节>]

#include "YaraForgePackage.h"

extern "C" {
#include "yara_x.h"
}

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <string>
#include <string_view>
#include <vector>

namespace {

using bulwark::yara::ForgePackageInfo;
using bulwark::yara::RuleChunk;
using bulwark::yara::SplitRules;

constexpr std::size_t kMaxZipBytes = 64u * 1024u * 1024u;
constexpr std::size_t kMaxSourceBytes = 128u * 1024u * 1024u;
constexpr std::size_t kMaxReportedSkips = 300;
constexpr std::size_t kMaxReasonChars = 240;

struct Args {
    std::wstring zip;
    std::wstring yar;
    std::wstring out;
    std::wstring report;
    std::string ns = "yaraforge";
};

struct Skipped {
    std::string rule;
    std::size_t line = 0;
    std::string reason;
};

struct Report {
    bool ok = false;
    std::string error;
    std::string engine;
    std::string sourceName;
    std::size_t sourceBytes = 0;
    ForgePackageInfo package;
    std::size_t rulesFound = 0;
    int rulesCompiled = 0;
    std::size_t rulesSkipped = 0;
    std::vector<Skipped> skipped;
    long long compileMs = 0;
    std::size_t outputBytes = 0;
    std::vector<std::string> hardening;
};

std::string utf8(const std::wstring& w) {
    if (w.empty())
        return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0,
                                      nullptr, nullptr);
    std::string s(static_cast<std::size_t>(n > 0 ? n : 0), '\0');
    if (n > 0)
        WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr,
                            nullptr);
    return s;
}

// 允许别人同时改名 / 删除:服务替换规则文件时不能被正在读它的扫描进程挡住。
bool readFile(const std::wstring& path, std::size_t limit, std::string& out, std::string& error) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        error = "cannot open input (error " + std::to_string(GetLastError()) + ")";
        return false;
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size) || size.QuadPart < 0 || static_cast<unsigned long long>(size.QuadPart) > limit) {
        CloseHandle(h);
        error = "input is missing or larger than the limit";
        return false;
    }
    out.resize(static_cast<std::size_t>(size.QuadPart));
    std::size_t done = 0;
    while (done < out.size()) {
        DWORD got = 0;
        const DWORD want = static_cast<DWORD>(std::min<std::size_t>(out.size() - done, 1u << 20));
        if (!ReadFile(h, out.data() + done, want, &got, nullptr) || got == 0)
            break;
        done += got;
    }
    CloseHandle(h);
    if (done != out.size()) {
        error = "short read on input";
        return false;
    }
    return true;
}

bool writeFile(const std::wstring& path, const void* data, std::size_t len) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    const auto* p = static_cast<const char*>(data);
    std::size_t done = 0;
    bool ok = true;
    while (done < len) {
        DWORD put = 0;
        const DWORD want = static_cast<DWORD>(std::min<std::size_t>(len - done, 1u << 20));
        if (!WriteFile(h, p + done, want, &put, nullptr) || put == 0) {
            ok = false;
            break;
        }
        done += put;
    }
    ok = ok && FlushFileBuffers(h);
    CloseHandle(h);
    return ok;
}

// 去掉用不到的特权,禁止派生子进程、加载远程 / 低完整性 / 非微软签名的映像(YARA-X 静态链接,
// 本进程只用到系统 DLL)。不能禁止动态代码 —— YARA-X 用 wasmtime 即时编译规则条件。
void hardenProcess(std::vector<std::string>& applied) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR);

    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        DWORD len = 0;
        GetTokenInformation(token, TokenPrivileges, nullptr, 0, &len);
        std::vector<unsigned char> buf(len);
        auto* tp = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data());
        LUID changeNotify{};
        LookupPrivilegeValueW(nullptr, SE_CHANGE_NOTIFY_NAME, &changeNotify);
        if (len > 0 && GetTokenInformation(token, TokenPrivileges, tp, len, &len)) {
            DWORD removed = 0;
            for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
                LUID_AND_ATTRIBUTES& la = tp->Privileges[i];
                if (la.Luid.LowPart == changeNotify.LowPart && la.Luid.HighPart == changeNotify.HighPart) {
                    la.Attributes = 0;
                    continue;
                }
                la.Attributes = SE_PRIVILEGE_REMOVED;
                ++removed;
            }
            if (AdjustTokenPrivileges(token, FALSE, tp, 0, nullptr, nullptr)
                && GetLastError() == ERROR_SUCCESS)
                applied.push_back("privileges-removed:" + std::to_string(removed));
        }
        CloseHandle(token);
    }

    PROCESS_MITIGATION_CHILD_PROCESS_POLICY child{};
    child.NoChildProcessCreation = 1;
    if (SetProcessMitigationPolicy(ProcessChildProcessPolicy, &child, sizeof(child)))
        applied.push_back("no-child-process");

    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ext{};
    ext.DisableExtensionPoints = 1;
    if (SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &ext, sizeof(ext)))
        applied.push_back("no-extension-points");

    PROCESS_MITIGATION_IMAGE_LOAD_POLICY img{};
    img.NoRemoteImages = 1;
    img.NoLowMandatoryLabelImages = 1;
    img.PreferSystem32Images = 1;
    if (SetProcessMitigationPolicy(ProcessImageLoadPolicy, &img, sizeof(img)))
        applied.push_back("image-load-restricted");

    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig{};
    sig.MicrosoftSignedOnly = 1;
    if (SetProcessMitigationPolicy(ProcessSignaturePolicy, &sig, sizeof(sig)))
        applied.push_back("microsoft-signed-images-only");
}

// 扫描进程载入规则后把自己降到低完整性:读文件不受影响(默认不禁止向上读),但写不了
// 中完整性及以上的文件、注册表和进程 —— 万一解析某个文件时被攻破,它能动的东西很少。
void lowerIntegrity(std::vector<std::string>& applied) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, &token))
        return;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    PSID low = nullptr;
    if (AllocateAndInitializeSid(&authority, 1, SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 0, 0, 0, &low)) {
        TOKEN_MANDATORY_LABEL label{};
        label.Label.Attributes = SE_GROUP_INTEGRITY;
        label.Label.Sid = low;
        if (SetTokenInformation(token, TokenIntegrityLevel, &label, sizeof(label) + GetLengthSid(low)))
            applied.push_back("integrity-low");
        FreeSid(low);
    }
    CloseHandle(token);
}

std::string clipUtf8(std::string s, std::size_t maxBytes) {
    if (s.size() <= maxBytes)
        return s;
    std::size_t cut = maxBytes;
    while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0u) == 0x80u)
        --cut;
    s.resize(cut);
    return s;
}

// YARA-X 的错误报告是多行带图示的文本,只留第一行,并把 "error[E009]: x" 收成 "E009: x"。
std::string firstLineOf(const char* text) {
    std::string_view s = text ? std::string_view(text) : std::string_view();
    while (!s.empty() && (s.front() == '\n' || s.front() == '\r' || s.front() == ' '))
        s.remove_prefix(1);
    const std::size_t eol = s.find_first_of("\r\n");
    std::string line(s.substr(0, eol));
    if (line.rfind("error[", 0) == 0) {
        const std::size_t close = line.find("]: ");
        if (close != std::string::npos)
            line = line.substr(6, close - 6) + ": " + line.substr(close + 3);
    }
    line = clipUtf8(std::move(line), kMaxReasonChars);
    return line.empty() ? std::string("compile error") : line;
}

std::string engineName() {
    return "YARA-X " + std::to_string(YARA_X_MAJOR) + "." + std::to_string(YARA_X_MINOR) + "."
         + std::to_string(YARA_X_PATCH);
}

std::string jsonString(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('"');
    for (const char ch : s) {
        const auto c = static_cast<unsigned char>(ch);
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out.push_back(ch);
            }
        }
    }
    out.push_back('"');
    return out;
}

std::string renderReport(const Report& r) {
    std::string j = "{";
    const auto field = [&j](const char* key, const std::string& value, bool comma = true) {
        j += jsonString(key);
        j += ':';
        j += value;
        if (comma)
            j += ',';
    };
    field("ok", r.ok ? "true" : "false");
    field("error", jsonString(r.error));
    field("engine", jsonString(r.engine));
    field("sourceName", jsonString(r.sourceName));
    field("sourceBytes", std::to_string(r.sourceBytes));
    field("packageName", jsonString(r.package.name));
    field("packageCreated", jsonString(r.package.created));
    field("packageDeclaredRules", std::to_string(r.package.declaredRules));
    field("rulesFound", std::to_string(r.rulesFound));
    field("rulesCompiled", std::to_string(r.rulesCompiled));
    field("rulesSkipped", std::to_string(r.rulesSkipped));
    field("compileMs", std::to_string(r.compileMs));
    field("outputBytes", std::to_string(r.outputBytes));

    std::string sources = "[";
    for (std::size_t i = 0; i < r.package.sources.size(); ++i) {
        if (i)
            sources += ',';
        sources += "{\"repository\":" + jsonString(r.package.sources[i].repository)
                 + ",\"rules\":" + std::to_string(r.package.sources[i].rules) + "}";
    }
    sources += ']';
    field("sources", sources);

    std::string skipped = "[";
    for (std::size_t i = 0; i < r.skipped.size(); ++i) {
        if (i)
            skipped += ',';
        skipped += "{\"rule\":" + jsonString(r.skipped[i].rule) + ",\"line\":"
                 + std::to_string(r.skipped[i].line) + ",\"reason\":" + jsonString(r.skipped[i].reason) + "}";
    }
    skipped += ']';
    field("skipped", skipped);

    std::string hardening = "[";
    for (std::size_t i = 0; i < r.hardening.size(); ++i) {
        if (i)
            hardening += ',';
        hardening += jsonString(r.hardening[i]);
    }
    hardening += ']';
    field("hardening", hardening, false);
    j += '}';
    return j;
}

bool parseArgs(int argc, wchar_t** argv, Args& a) {
    for (int i = 1; i + 1 < argc; i += 2) {
        const std::wstring_view k = argv[i];
        const std::wstring v = argv[i + 1];
        if (k == L"--zip") a.zip = v;
        else if (k == L"--yar") a.yar = v;
        else if (k == L"--out") a.out = v;
        else if (k == L"--report") a.report = v;
        else if (k == L"--namespace") a.ns = utf8(v);
        else return false;
    }
    return (a.zip.empty() != a.yar.empty()) && !a.out.empty() && !a.report.empty() && !a.ns.empty();
}

bool endsWithYar(std::string_view name) {
    if (name.size() < 5 || name.back() == '/')
        return false;
    const std::string_view ext = name.substr(name.size() - 4);
    return (ext[0] == '.') && (ext[1] == 'y' || ext[1] == 'Y') && (ext[2] == 'a' || ext[2] == 'A')
        && (ext[3] == 'r' || ext[3] == 'R');
}

int run(const Args& args, Report& rep) {
    rep.engine = engineName();

    std::string source;
    if (!args.zip.empty()) {
        std::string zip;
        if (!readFile(args.zip, kMaxZipBytes, zip, rep.error))
            return 2;
        bulwark::yara::ZipEntry entry;
        if (!bulwark::yara::extractZipEntry(zip, endsWithYar, kMaxSourceBytes, entry, rep.error)) {
            rep.error = "zip: " + rep.error;
            return 2;
        }
        rep.sourceName = entry.name;
        source = std::move(entry.data);
    } else {
        if (!readFile(args.yar, kMaxSourceBytes, source, rep.error))
            return 2;
        rep.sourceName = utf8(args.yar);
    }
    rep.sourceBytes = source.size();
    rep.package = bulwark::yara::parseForgePackageInfo(source);

    const SplitRules split = bulwark::yara::splitRules(source);
    source.clear();
    source.shrink_to_fit();
    rep.rulesFound = split.rules.size();
    if (split.rules.empty()) {
        rep.error = "no rules found in the package";
        return 3;
    }

    const auto started = std::chrono::steady_clock::now();
    YRX_COMPILER* compiler = nullptr;
    const uint32_t flags = YRX_RELAXED_RE_SYNTAX | YRX_ERROR_ON_SLOW_PATTERN | YRX_ERROR_ON_SLOW_LOOP
                         | YRX_DISABLE_INCLUDES;
    if (yrx_compiler_create(flags, &compiler) != YRX_SUCCESS || !compiler) {
        rep.error = "cannot create compiler: " + firstLineOf(yrx_last_error());
        return 4;
    }
    yrx_compiler_max_warnings(compiler, 0);
    yrx_compiler_new_namespace(compiler, args.ns.c_str());

    std::string src;
    for (const RuleChunk& chunk : split.rules) {
        src.assign(split.imports);
        src.push_back('\n');
        src.append(chunk.text);
        const std::string origin = "rule " + chunk.name + " (line " + std::to_string(chunk.line) + ")";
        if (yrx_compiler_add_source_with_origin(compiler, src.c_str(), origin.c_str()) == YRX_SUCCESS)
            continue;
        ++rep.rulesSkipped;
        if (rep.skipped.size() < kMaxReportedSkips)
            rep.skipped.push_back({chunk.name, chunk.line, firstLineOf(yrx_last_error())});
    }

    YRX_RULES* rules = yrx_compiler_build(compiler);
    yrx_compiler_destroy(compiler);
    if (!rules) {
        rep.error = "build failed: " + firstLineOf(yrx_last_error());
        return 4;
    }
    rep.rulesCompiled = yrx_rules_count(rules);

    YRX_BUFFER* buf = nullptr;
    const YRX_RESULT ser = yrx_rules_serialize(rules, &buf);
    yrx_rules_destroy(rules);
    rep.compileMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - started).count();
    if (ser != YRX_SUCCESS || !buf) {
        rep.error = "serialize failed: " + firstLineOf(yrx_last_error());
        return 4;
    }
    const bool written = writeFile(args.out, buf->data, buf->length);
    rep.outputBytes = buf->length;
    yrx_buffer_destroy(buf);
    if (!written) {
        rep.error = "cannot write compiled rules (error " + std::to_string(GetLastError()) + ")";
        return 5;
    }
    if (rep.rulesCompiled <= 0) {
        rep.error = "every rule failed to compile";
        return 3;
    }
    rep.ok = true;
    return 0;
}

// 常驻扫描

constexpr std::size_t kMaxRulesBytes = 512u * 1024u * 1024u;
constexpr std::size_t kMaxRequestLine = 64u * 1024u;
constexpr std::size_t kMaxMatchesReported = 32;
constexpr std::size_t kMaxMetaChars = 240;
constexpr std::size_t kKeepBufferBytes = 16u * 1024u * 1024u;

struct ServeArgs {
    std::wstring rules;
    unsigned long long timeoutSeconds = 10;
    unsigned long long maxBytes = 64ull * 1024u * 1024u;
};

bool parseServeArgs(int argc, wchar_t** argv, ServeArgs& a) {
    if ((argc - 2) % 2 != 0)
        return false;
    for (int i = 2; i + 1 < argc; i += 2) {
        const std::wstring_view k = argv[i];
        const wchar_t* v = argv[i + 1];
        if (k == L"--rules") a.rules = v;
        else if (k == L"--timeout") a.timeoutSeconds = std::wcstoull(v, nullptr, 10);
        else if (k == L"--max-bytes") a.maxBytes = std::wcstoull(v, nullptr, 10);
        else return false;
    }
    a.timeoutSeconds = std::clamp<unsigned long long>(a.timeoutSeconds, 1, 600);
    return !a.rules.empty() && a.maxBytes > 0;
}

std::wstring widen(std::string_view s) {
    if (s.empty())
        return {};
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()),
                                      nullptr, 0);
    if (n <= 0)
        return {};
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::wstring extendedPath(const std::wstring& p) {
    if (p.size() < 240 || p.rfind(L"\\\\?\\", 0) == 0)
        return p;
    if (p.size() > 2 && p[1] == L':' && p[2] == L'\\')
        return L"\\\\?\\" + p;
    if (p.rfind(L"\\\\", 0) == 0)
        return L"\\\\?\\UNC\\" + p.substr(2);
    return p;
}

class Sha256 {
public:
    Sha256() {
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg_, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
            alg_ = nullptr;
    }
    ~Sha256() {
        if (alg_)
            BCryptCloseAlgorithmProvider(alg_, 0);
    }
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;

    std::string hex(const std::uint8_t* data, std::size_t len) const {
        if (!alg_)
            return {};
        BCRYPT_HASH_HANDLE h = nullptr;
        if (!BCRYPT_SUCCESS(BCryptCreateHash(alg_, &h, nullptr, 0, nullptr, 0, 0)))
            return {};
        bool ok = true;
        std::size_t done = 0;
        while (ok && done < len) {
            const ULONG n = static_cast<ULONG>(std::min<std::size_t>(len - done, 1u << 30));
            ok = BCRYPT_SUCCESS(BCryptHashData(h, const_cast<PUCHAR>(data + done), n, 0));
            done += n;
        }
        unsigned char digest[32];
        ok = ok && BCRYPT_SUCCESS(BCryptFinishHash(h, digest, sizeof(digest), 0));
        BCryptDestroyHash(h);
        if (!ok)
            return {};
        static constexpr char kHex[] = "0123456789abcdef";
        std::string s;
        s.reserve(64);
        for (const unsigned char b : digest) {
            s.push_back(kHex[b >> 4]);
            s.push_back(kHex[b & 0x0F]);
        }
        return s;
    }

private:
    BCRYPT_ALG_HANDLE alg_ = nullptr;
};

struct MatchInfo {
    std::string rule;
    std::string ns;
    std::string author;
    std::string description;
    long long score = -1;
};

struct ScanState {
    std::vector<MatchInfo> matches;
    std::size_t total = 0;
};

void collectMeta(const YRX_METADATA* m, void* user) {
    auto* mi = static_cast<MatchInfo*>(user);
    if (!m || !m->identifier)
        return;
    const std::string_view id = m->identifier;
    if (m->value_type == YRX_STRING && m->value.string) {
        if (id == "author" && mi->author.empty())
            mi->author = clipUtf8(m->value.string, kMaxMetaChars);
        else if (id == "description" && mi->description.empty())
            mi->description = clipUtf8(m->value.string, kMaxMetaChars);
    } else if (m->value_type == YRX_I64 && id == "score") {
        mi->score = m->value.i64;
    }
}

void collectRule(const YRX_RULE* rule, void* user) {
    auto* st = static_cast<ScanState*>(user);
    ++st->total;
    if (st->matches.size() >= kMaxMatchesReported)
        return;
    MatchInfo mi;
    const std::uint8_t* p = nullptr;
    std::size_t n = 0;
    if (yrx_rule_identifier(rule, &p, &n) == YRX_SUCCESS && p)
        mi.rule.assign(reinterpret_cast<const char*>(p), n);
    if (yrx_rule_namespace(rule, &p, &n) == YRX_SUCCESS && p)
        mi.ns.assign(reinterpret_cast<const char*>(p), n);
    yrx_rule_iter_metadata(rule, collectMeta, &mi);
    st->matches.push_back(std::move(mi));
}

bool writeLine(HANDLE out, std::string line) {
    line.push_back('\n');
    std::size_t done = 0;
    while (done < line.size()) {
        DWORD put = 0;
        if (!WriteFile(out, line.data() + done, static_cast<DWORD>(line.size() - done), &put, nullptr) || put == 0)
            return false;
        done += put;
    }
    return true;
}

class LineReader {
public:
    explicit LineReader(HANDLE in) : in_(in) {}

    // 读到 EOF、出错或单行超长时返回 false:服务关掉管道就是让本进程退出。
    bool next(std::string& line) {
        for (;;) {
            const std::size_t nl = buf_.find('\n');
            if (nl != std::string::npos) {
                line.assign(buf_, 0, nl);
                buf_.erase(0, nl + 1);
                if (!line.empty() && line.back() == '\r')
                    line.pop_back();
                return true;
            }
            if (buf_.size() > kMaxRequestLine)
                return false;
            char chunk[4096];
            DWORD got = 0;
            if (!ReadFile(in_, chunk, sizeof(chunk), &got, nullptr) || got == 0)
                return false;
            buf_.append(chunk, got);
        }
    }

private:
    HANDLE in_;
    std::string buf_;
};

std::string scanFile(YRX_SCANNER* scanner, ScanState& st, const Sha256& sha, std::vector<std::uint8_t>& buf,
                     const std::string& id, const std::wstring& path, unsigned long long maxBytes) {
    const auto started = std::chrono::steady_clock::now();
    const std::string head = "{\"id\":" + id + ",";
    const auto fail = [&head](const std::string& error, const std::string& extra) {
        return head + "\"ok\":false,\"error\":" + jsonString(error) + extra + "}";
    };

    HANDLE h = CreateFileW(extendedPath(path).c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return fail("open " + std::to_string(GetLastError()), std::string());
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size) || size.QuadPart < 0) {
        const DWORD e = GetLastError();
        CloseHandle(h);
        return fail("size " + std::to_string(e), std::string());
    }
    const auto bytes = static_cast<unsigned long long>(size.QuadPart);
    const std::string sizeField = ",\"size\":" + std::to_string(bytes);
    if (bytes > maxBytes) {
        CloseHandle(h);
        return fail("too-large", sizeField);
    }
    buf.resize(static_cast<std::size_t>(bytes));
    std::size_t done = 0;
    while (done < buf.size()) {
        DWORD got = 0;
        const DWORD want = static_cast<DWORD>(std::min<std::size_t>(buf.size() - done, 1u << 20));
        if (!ReadFile(h, buf.data() + done, want, &got, nullptr) || got == 0)
            break;
        done += got;
    }
    CloseHandle(h);
    if (done != buf.size())
        return fail("read", sizeField);

    const std::string digest = sha.hex(buf.data(), buf.size());
    st.matches.clear();
    st.total = 0;
    const YRX_RESULT rc = yrx_scanner_scan(scanner, buf.data(), buf.size());
    const long long ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - started).count();
    if (buf.capacity() > kKeepBufferBytes) {
        buf.clear();
        buf.shrink_to_fit();
    }
    const std::string common = sizeField + ",\"sha256\":" + jsonString(digest) + ",\"ms\":" + std::to_string(ms);
    if (rc == YRX_SCAN_TIMEOUT)
        return fail("timeout", common);
    if (rc != YRX_SUCCESS)
        return fail("scan: " + firstLineOf(yrx_last_error()), common);

    std::string j = head + "\"ok\":true" + common + ",\"total\":" + std::to_string(st.total) + ",\"matches\":[";
    for (std::size_t i = 0; i < st.matches.size(); ++i) {
        const MatchInfo& m = st.matches[i];
        if (i)
            j += ',';
        j += "{\"rule\":" + jsonString(m.rule) + ",\"ns\":" + jsonString(m.ns) + ",\"author\":"
           + jsonString(m.author) + ",\"description\":" + jsonString(m.description)
           + ",\"score\":" + std::to_string(m.score) + "}";
    }
    j += "]}";
    return j;
}

int serve(const ServeArgs& args) {
    std::vector<std::string> hardening;
    hardenProcess(hardening);
    const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    const std::string engine = engineName();
    const auto notReady = [&](const std::string& error, int rc) {
        writeLine(out, "{\"ready\":false,\"engine\":" + jsonString(engine) + ",\"error\":" + jsonString(error) + "}");
        return rc;
    };

    std::string data;
    std::string error;
    if (!readFile(args.rules, kMaxRulesBytes, data, error))
        return notReady("rules: " + error, 2);
    YRX_RULES* rules = nullptr;
    if (yrx_rules_deserialize(reinterpret_cast<const std::uint8_t*>(data.data()), data.size(), &rules)
            != YRX_SUCCESS
        || !rules)
        return notReady("deserialize: " + firstLineOf(yrx_last_error()), 4);
    data.clear();
    data.shrink_to_fit();

    YRX_SCANNER* scanner = nullptr;
    if (yrx_scanner_create(rules, &scanner) != YRX_SUCCESS || !scanner) {
        yrx_rules_destroy(rules);
        return notReady("scanner: " + firstLineOf(yrx_last_error()), 4);
    }
    ScanState st;
    yrx_scanner_set_timeout(scanner, args.timeoutSeconds);
    yrx_scanner_fast_scan(scanner, true);
    yrx_scanner_on_matching_rule(scanner, collectRule, &st);
    const int count = yrx_rules_count(rules);

    lowerIntegrity(hardening);
    std::string ready = "{\"ready\":true,\"engine\":" + jsonString(engine) + ",\"rules\":" + std::to_string(count)
                      + ",\"hardening\":[";
    for (std::size_t i = 0; i < hardening.size(); ++i) {
        if (i)
            ready += ',';
        ready += jsonString(hardening[i]);
    }
    ready += "]}";

    int rc = 0;
    if (writeLine(out, ready)) {
        const Sha256 sha;
        std::vector<std::uint8_t> buf;
        LineReader in(GetStdHandle(STD_INPUT_HANDLE));
        std::string line;
        while (in.next(line)) {
            if (line == "quit")
                break;
            const std::size_t tab = line.find('\t');
            if (tab == 0 || tab == std::string::npos || tab > 18
                || line.find_first_not_of("0123456789") < tab)
                continue;
            const std::string id = line.substr(0, tab);
            const std::wstring path = widen(std::string_view(line).substr(tab + 1));
            const std::string reply = path.empty()
                ? "{\"id\":" + id + ",\"ok\":false,\"error\":\"path\"}"
                : scanFile(scanner, st, sha, buf, id, path, args.maxBytes);
            if (!writeLine(out, reply))
                break;
        }
    } else {
        rc = 5;
    }
    yrx_scanner_destroy(scanner);
    yrx_rules_destroy(rules);
    return rc;
}

}

int wmain(int argc, wchar_t** argv) {
    if (argc >= 2 && std::wstring_view(argv[1]) == L"--serve") {
        ServeArgs sargs;
        if (!parseServeArgs(argc, argv, sargs)) {
            std::fwprintf(stderr, L"usage: bulwark_yarac --serve --rules <rules.yarc> [--timeout <sec>] "
                                  L"[--max-bytes <n>]\n");
            return 64;
        }
        return serve(sargs);
    }

    Args args;
    if (!parseArgs(argc, argv, args)) {
        std::fwprintf(stderr, L"usage: bulwark_yarac (--zip <pkg.zip> | --yar <rules.yar>) --out <rules.yarc> "
                              L"--report <report.json> [--namespace <ns>]\n");
        return 64;
    }
    Report rep;
    hardenProcess(rep.hardening);
    const int rc = run(args, rep);
    const std::string json = renderReport(rep);
    if (!writeFile(args.report, json.data(), json.size()))
        return rc == 0 ? 6 : rc;
    return rc;
}
