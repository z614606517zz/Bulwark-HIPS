#include "MatchCore.h"

#include <stdio.h>

static int g_checks = 0;
static int g_failed = 0;

static void
Check(int ok, const char* what)
{
    g_checks++;
    if (!ok) {
        g_failed++;
        printf("  FAIL: %s\n", what);
    }
}

static void
MakeUs(UNICODE_STRING* us, const wchar_t* s)
{
    us->Buffer = (PWCH)s;
    us->Length = (USHORT)(wcslen(s) * sizeof(WCHAR));
    us->MaximumLength = us->Length;
}

static USHORT
Chars(const wchar_t* s)
{
    return (USHORT)wcslen(s);
}

static void
ListAdd(BLW_PROTECTED_PATH* list, const wchar_t* pattern)
{
    BlwAddToList(list, pattern, Chars(pattern));
}

static LONG
ListCount(const BLW_PROTECTED_PATH* list)
{
    LONG n = 0;
    ULONG i;
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (list[i].InUse) {
            n++;
        }
    }
    return n;
}

static void
ListClear(BLW_PROTECTED_PATH* list)
{
    memset(list, 0, sizeof(BLW_PROTECTED_PATH) * BLW_MAX_PROTECTED);
}

static BOOLEAN
ListHas(const BLW_PROTECTED_PATH* list, const wchar_t* patternUpper)
{
    const USHORT n = Chars(patternUpper);
    ULONG i;

    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (list[i].InUse && list[i].Length == n &&
            wcsncmp(list[i].Path, patternUpper, n) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
HitsSub(const wchar_t* pattern, const wchar_t* target)
{
    static BLW_PROTECTED_PATH list[BLW_MAX_PROTECTED];
    BLW_MATCH_CTX ctx;
    UNICODE_STRING us;

    ListClear(list);
    ListAdd(list, pattern);
    MakeUs(&us, target);
    BlwPrepareMatch(&ctx, &us);
    return BlwMatchInListCtx(list, ListCount(list), &ctx, 0);
}

static BOOLEAN
HitsAnchored(const wchar_t* pattern, const wchar_t* target)
{
    static BLW_PROTECTED_PATH list[BLW_MAX_PROTECTED];
    BLW_MATCH_CTX ctx;
    UNICODE_STRING us;

    ListClear(list);
    ListAdd(list, pattern);
    MakeUs(&us, target);
    BlwPrepareMatch(&ctx, &us);
    return BlwMatchInListAnchoredCtx(list, ListCount(list), &ctx);
}

static BOOLEAN
CmdHits(const wchar_t* pattern, const wchar_t* cmdline)
{
    static BLW_PROTECTED_PATH list[BLW_MAX_PROTECTED];

    ListClear(list);
    ListAdd(list, pattern);
    return BlwCmdPatternMatches(&list[0], cmdline, (ULONG)wcslen(cmdline));
}

static void
TestVolumeOffset(void)
{
    printf("[1] BlwVolumeRelativeOffset\n");

    Check(BlwVolumeRelativeOffset(L"\\??\\C:\\Windows\\x.exe",
                                  Chars(L"\\??\\C:\\Windows\\x.exe")) == 6,
          "\\??\\C:\\ -> 6");

    Check(BlwVolumeRelativeOffset(L"\\Device\\HarddiskVolume3\\Windows\\x.exe",
                                  Chars(L"\\Device\\HarddiskVolume3\\Windows\\x.exe")) == 23,
          "\\Device\\HarddiskVolume3\\ -> 23");
    Check(BlwVolumeRelativeOffset(L"\\Device\\HarddiskVolume12\\Windows\\x.exe",
                                  Chars(L"\\Device\\HarddiskVolume12\\Windows\\x.exe")) == 24,
          "\\Device\\HarddiskVolume12\\ -> 24(两位卷号)");

    Check(BlwVolumeRelativeOffset(L"C:\\Windows\\x.exe", Chars(L"C:\\Windows\\x.exe")) == 2,
          "C:\\ -> 2");

    Check(BlwVolumeRelativeOffset(L"\\??\\UNC\\srv\\share\\x.exe",
                                  Chars(L"\\??\\UNC\\srv\\share\\x.exe")) == 0,
          "\\??\\UNC\\(网络路径)-> 0");
    Check(BlwVolumeRelativeOffset(L"\\Device\\Mup\\srv\\share\\x.exe",
                                  Chars(L"\\Device\\Mup\\srv\\share\\x.exe")) == 0,
          "\\Device\\Mup\\ -> 0");
    Check(BlwVolumeRelativeOffset(L"\\Device\\HarddiskVolume\\x.exe",
                                  Chars(L"\\Device\\HarddiskVolume\\x.exe")) == 0,
          "HarddiskVolume 后没有数字 -> 0");
    Check(BlwVolumeRelativeOffset(L"ab", 2) == 0, "过短 -> 0");
    Check(BlwVolumeRelativeOffset(NULL, 0) == 0, "NULL -> 0");
}

static void
TestVolumePathStartsWith(void)
{
    printf("[2] BLW_SYSVOL_PATH_STARTS(系统卷未知时退回任意卷)\n");

#define VPS(p, lit) BLW_SYSVOL_PATH_STARTS((p), Chars(p), lit)

    Check(!VPS(L"C:\\Users\\u\\Program Files\\evil.exe", L"\\Program Files\\"),
          "用户自建的 \\Users\\u\\Program Files\\ 不算可信安装目录");
    Check(VPS(L"C:\\Program Files\\App\\a.exe", L"\\Program Files\\"),
          "真正的 C:\\Program Files\\ 算可信安装目录");

    Check(!VPS(L"C:\\temp\\Windows\\System32\\csrss.exe", L"\\Windows\\System32\\"),
          "C:\\temp\\Windows\\System32\\ 不算系统目录");
    Check(VPS(L"\\Device\\HarddiskVolume2\\Windows\\System32\\csrss.exe",
              L"\\Windows\\System32\\"),
          "真正的 System32(\\Device 形式)算系统目录");
    Check(VPS(L"\\??\\C:\\Windows\\System32\\csrss.exe", L"\\Windows\\System32\\"),
          "真正的 System32(\\??\\C: 形式)算系统目录");

    Check(!VPS(L"\\Device\\Mup\\srv\\Windows\\System32\\x.exe", L"\\Windows\\System32\\"),
          "网络路径认不出卷 -> 不匹配");

#undef VPS
}

static void
TestImageNameIn(void)
{
    static const BLW_NAME_ENTRY table[] = {
        BLW_NAME(L"cmd.exe"),
        BLW_NAME(L"csrss.exe"),
    };

    printf("[3] BlwImageNameIn\n");

#define NIN(p) BlwImageNameIn(table, RTL_NUMBER_OF(table), (p), Chars(p))

    Check(NIN(L"\\Device\\HarddiskVolume1\\Windows\\System32\\CMD.EXE"),
          "大小写不敏感命中");
    Check(NIN(L"\\??\\C:\\Windows\\System32\\cmd.exe"), "\\??\\ 形式命中");
    Check(!NIN(L"cmd.exe"), "整条路径里没有 '\\' -> 不匹配(与原尾部匹配语义一致)");
    Check(!NIN(L"C:\\x\\notcmd.exe"), "notcmd.exe 不是 cmd.exe");
    Check(!NIN(L"C:\\x\\cmd.exe.bak"), "cmd.exe.bak 不是 cmd.exe");
    Check(!NIN(L"C:\\x\\"), "以 '\\' 结尾(无文件名)-> 不匹配");
    Check(!NIN(L""), "空串 -> 不匹配");

#undef NIN
}

static void
TestWideContains(void)
{
    printf("[4] BlwWideContainsCI\n");

#define WC(s, sub) BlwWideContainsCI((s), Chars(s), sub)

    Check(WC(L"C:\\Users\\u\\AppData\\Local\\Temp\\x.dll", L"\\temp\\"),
          "大小写不敏感的中段命中");
    Check(WC(L"\\DEVICE\\HARDDISKVOLUME1\\USERS\\PUBLIC\\a.exe", L"\\Users\\Public\\"),
          "目标已大写也能命中");
    Check(!WC(L"C:\\x", L"\\this-is-longer-than-target\\"), "子串比目标长 -> 不匹配");
    Check(!WC(L"C:\\Users\\u\\x.dll", L"\\ProgramData\\"), "不含则不匹配");
    Check(!WC(L"", L"\\temp\\"), "空目标 -> 不匹配");
    Check(!WC(L"C:\\Temp\\x", L""), "空子串 -> 不匹配(绝不匹配一切)");

#undef WC
}

static void
TestListAddRemove(void)
{
    static BLW_PROTECTED_PATH list[BLW_MAX_PROTECTED];
    wchar_t buf[64];
    int i;

    printf("[5] BlwAddToList / BlwRemoveFromList\n");

    ListClear(list);
    ListAdd(list, L"\\users\\u\\temp\\a.exe");
    ListAdd(list, L"\\USERS\\U\\TEMP\\A.EXE");
    ListAdd(list, L"\\Users\\U\\Temp\\a.exe");
    Check(ListCount(list) == 1, "大小写不同的同一条只占一个槽(去重)");
    Check(list[0].Length == Chars(L"\\users\\u\\temp\\a.exe"), "存入长度正确");
    Check(list[0].Path[1] == L'U', "存入时已大写化(存储约定)");

    ListClear(list);
    for (i = 0; i < BLW_MAX_PROTECTED + 3; i++) {
        swprintf(buf, RTL_NUMBER_OF(buf), L"\\dir%03d\\x.exe", i);
        ListAdd(list, buf);
    }
    Check(ListCount(list) == BLW_MAX_PROTECTED, "满槽后不再增长");
    Check(ListHas(list, L"\\DIR000\\X.EXE"), "满槽时先入的条目不被覆盖");
    Check(!ListHas(list, L"\\DIR064\\X.EXE"), "满槽后第 65 条被丢弃");

    ListClear(list);
    ListAdd(list, L"\\users\\u\\temp\\a.exe");
    ListAdd(list, L"\\users\\u\\temp\\b.exe");
    Check(ListCount(list) == 2, "删除前 2 条");
    Check(!BlwRemoveFromList(list, L"\\users\\u\\temp\\zzz.exe",
                             Chars(L"\\users\\u\\temp\\zzz.exe")),
          "删不存在的条目 -> FALSE(调用方据此决定不标脏)");
    Check(BlwRemoveFromList(list, L"\\USERS\\U\\TEMP\\A.EXE",
                            Chars(L"\\USERS\\U\\TEMP\\A.EXE")),
          "大小写不敏感的精确删除 -> TRUE");
    Check(ListCount(list) == 1, "删掉一条后剩 1 条");
    Check(!BlwRemoveFromList(list, L"\\users\\u\\temp\\a.exe",
                             Chars(L"\\users\\u\\temp\\a.exe")),
          "同一条不能删两次");
    ListAdd(list, L"\\users\\u\\temp\\c.exe");
    Check(ListCount(list) == 2, "删除腾出的槽可被复用");
    Check(!BlwRemoveFromList(list, L"", 0), "空串删除 -> FALSE");
}

static void
TestSubstringSemantics(void)
{
    static BLW_PROTECTED_PATH list[BLW_MAX_PROTECTED];
    BLW_MATCH_CTX ctx;
    UNICODE_STRING us;

    printf("[6] BlwMatchInListCtx(子串语义)\n");

    Check(HitsSub(L"\\START MENU\\PROGRAMS\\STARTUP\\",
                  L"\\Device\\HarddiskVolume1\\Users\\u\\AppData\\Roaming\\Microsoft"
                  L"\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk"),
          "中段目录片段命中(启动目录)");
    Check(HitsSub(L"\\HOSTS", L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\etc\\hosts"),
          "hosts 命中");
    Check(!HitsSub(L"\\HOSTS", L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\etc\\lmhosts"),
          "lmhosts 不命中 \\HOSTS(前导 '\\' 挡住了)");

    ListClear(list);
    ListAdd(list, L"\\WINLOGON\\SHELL");
    MakeUs(&us, L"\\REGISTRY\\MACHINE\\...\\WINLOGON\\SHELL");
    BlwPrepareMatch(&ctx, &us);
    Check(BlwMatchInListCtx(list, 1, &ctx, 0), "UseChars=0 匹配整个目标");
    Check(!BlwMatchInListCtx(list, 1, &ctx, (USHORT)Chars(L"\\REGISTRY\\MACHINE\\...\\WINLOGON")),
          "UseChars 截到键部分时,值名不参与匹配");

    ListClear(list);
    MakeUs(&us, L"C:\\x");
    BlwPrepareMatch(&ctx, &us);
    Check(!BlwMatchInListCtx(list, 0, &ctx, 0), "空名单 -> 不匹配");
    BlwPrepareMatch(&ctx, NULL);
    Check(!BlwMatchInListCtx(list, 0, &ctx, 0), "NULL 目标 -> 不匹配");
}

static void
TestAnchoredSemantics(void)
{
    printf("[7] BlwMatchInListAnchoredCtx(锚定语义)\n");

    Check(HitsAnchored(L"\\users\\u\\temp\\a.exe",
                       L"\\Device\\HarddiskVolume1\\Users\\u\\Temp\\a.exe"),
          "去盘符完整路径 -> 命中");
    Check(HitsAnchored(L"\\users\\u\\temp\\a.exe", L"C:\\Users\\u\\Temp\\a.exe"),
          "同上(C:\\ 形式的目标)");

    Check(HitsSub(L"\\users\\u\\temp\\a.exe",
                  L"\\Device\\HarddiskVolume1\\Users\\u\\Temp\\a.exe.bak"),
          "回归对照:子串语义会命中 a.exe.bak");
    Check(!HitsAnchored(L"\\users\\u\\temp\\a.exe",
                        L"\\Device\\HarddiskVolume1\\Users\\u\\Temp\\a.exe.bak"),
          "锚定:备份文件 a.exe.bak 不再被命中");
    Check(!HitsAnchored(L"\\users\\u\\temp\\a.exe",
                        L"\\Device\\HarddiskVolume1\\Users\\u\\Temp\\a.exeX"),
          "锚定:a.exeX 不再被命中");
    Check(!HitsAnchored(L"\\users\\u\\temp\\a.exe",
                        L"\\Device\\HarddiskVolume1\\Users\\u\\Temp\\a.exe\\sub\\x.dll"),
          "锚定:恰好叫 a.exe 的【目录】下的模块不再被命中");

    // (c) 备用数据流(ADS)必须仍然命中,否则加一个流名就能绕过。
    Check(HitsAnchored(L"\\users\\u\\temp\\a.exe",
                       L"\\Device\\HarddiskVolume1\\Users\\u\\Temp\\a.exe:payload"),
          "锚定:ADS(a.exe:payload)仍然命中");

    Check(HitsAnchored(L"\\evil.exe", L"\\Device\\HarddiskVolume1\\Users\\u\\evil.exe"),
          "基线用法 '\\evil.exe' -> 命中");
    Check(!HitsAnchored(L"\\evil.exe", L"\\Device\\HarddiskVolume1\\Users\\u\\notevil.exe"),
          "'\\evil.exe' 不命中 notevil.exe");
    Check(!HitsAnchored(L"\\evil.exe", L"\\Device\\HarddiskVolume1\\Users\\u\\evil.exe.txt"),
          "'\\evil.exe' 不命中 evil.exe.txt");

    Check(HitsAnchored(L"\\users\\u\\temp\\",
                       L"\\Device\\HarddiskVolume1\\Users\\u\\Temp\\anything.dll"),
          "目录前缀 -> 其下内容命中");
    Check(!HitsAnchored(L"\\users\\u\\temp\\",
                        L"\\Device\\HarddiskVolume1\\Users\\u\\Temporary\\x.dll"),
          "目录前缀不会误命中 Temporary\\");

    Check(HitsAnchored(L"evil.exe", L"\\Device\\HarddiskVolume1\\u\\evil.exe"),
          "无前导 '\\' 的模式:落在目录边界 -> 命中");
    Check(!HitsAnchored(L"evil.exe", L"\\Device\\HarddiskVolume1\\u\\notevil.exe"),
          "无前导 '\\' 的模式:不在目录边界 -> 不命中");

    Check(HitsAnchored(L"\\share\\evil.dll", L"\\Device\\Mup\\srv\\share\\evil.dll"),
          "网络路径(\\Device\\Mup\\)仍能命中");
}

static void
TestLongTargetFallback(void)
{
    static wchar_t big[BLW_MAX_PATH + 200];
    static BLW_PROTECTED_PATH list[BLW_MAX_PROTECTED];
    BLW_MATCH_CTX ctx;
    UNICODE_STRING us;
    const wchar_t* tail = L"\\users\\u\\temp\\a.exe";
    USHORT i;
    USHORT pad = BLW_MAX_PATH + 40;

    printf("[8] 超长目标的即时归一化回退路径\n");

    for (i = 0; i < pad; i++) {
        big[i] = (i % 20 == 0) ? L'\\' : L'a';
    }
    wcscpy_s(&big[pad], RTL_NUMBER_OF(big) - pad, tail);

    MakeUs(&us, big);
    BlwPrepareMatch(&ctx, &us);
    Check(ctx.Chars == 0, "超长目标不做预归一化(走 Original 回退)");
    Check(ctx.Original != NULL, "回退路径保留了原串");

    ListClear(list);
    ListAdd(list, tail);
    Check(BlwMatchInListCtx(list, 1, &ctx, 0), "回退路径:子串匹配仍然命中");
    Check(BlwMatchInListAnchoredCtx(list, 1, &ctx), "回退路径:锚定匹配仍然命中");

    ListClear(list);
    ListAdd(list, L"\\users\\u\\temp\\a.exe.bak");
    Check(!BlwMatchInListCtx(list, 1, &ctx, 0), "回退路径:不该命中的不命中");
}

static void
TestCmdPattern(void)
{
    printf("[9] BlwCmdPatternMatches(token 合取)\n");

    Check(CmdHits(L"VSSADMIN+DELETE+SHADOWS", L"vssadmin.exe  Delete   Shadows /All /Quiet"),
          "多空格 + 混合大小写 -> 命中");
    Check(CmdHits(L"VSSADMIN+DELETE+SHADOWS",
                  L"C:\\Windows\\System32\\vssadmin.exe /for=c: delete shadows /quiet"),
          "全路径 + 参数顺序不同 -> 命中");
    Check(!CmdHits(L"VSSADMIN+DELETE+SHADOWS", L"vssadmin list shadows"),
          "缺一个 token -> 不命中(合取语义)");
    Check(!CmdHits(L"VSSADMIN+DELETE+SHADOWS", L"delete shadows"),
          "缺 vssadmin -> 不命中");

    Check(CmdHits(L"SAVE+HKLM\\SAM", L"reg save HKLM\\SAM c:\\out.hiv"), "短写法命中");
    Check(!CmdHits(L"SAVE+HKLM\\SAM", L"reg save HKEY_LOCAL_MACHINE\\SAM c:\\out.hiv"),
          "长写法不被短写法覆盖(这正是要额外列一条模式的原因)");

    Check(!CmdHits(L"+++", L"anything at all"), "全是分隔符的空模式 -> 不命中");
    Check(!CmdHits(L"+", L"anything at all"), "单个分隔符 -> 不命中");

    Check(!CmdHits(L"AVERYLONGTOKENTHATCANNOTFIT", L"short"), "token 比命令行长 -> 不命中");

    Check(CmdHits(L"MIMIKATZ", L"C:\\x\\MiMiKatz.exe sekurlsa::logonpasswords"),
          "单 token 命中");
}

static void
TestDriveLetterPattern(void)
{
    printf("[10] BlwPatternHasDriveLetter(死条目判据)\n");

#define DL(p) BlwPatternHasDriveLetter((p), Chars(p))

    Check(DL(L"C:\\Users\\u\\a.exe"), "C:\\... -> 死条目");
    Check(DL(L"d:\\x"), "小写盘符也算");
    Check(DL(L"\\Users\\u\\z:\\weird"), "出现在中段也算");
    Check(!DL(L"\\Users\\u\\a.exe"), "去盘符的正常条目 -> 不是死条目");
    Check(!DL(L"\\Device\\HarddiskVolume3\\x"), "规范名形式 -> 不是死条目");
    Check(!DL(L"\\evil.exe"), "文件名片段 -> 不是死条目");
    Check(!DL(L"a:b"), "冒号后面不是 '\\' -> 不算(注册表值名允许含 ':')");
    Check(!DL(L"VSSADMIN+DELETE+SHADOWS"), "命令行模式 -> 不算");
    Check(!DL(L"C:"), "过短 -> 不算");
    Check(!BlwPatternHasDriveLetter(NULL, 0), "NULL -> 不算");

#undef DL
}

static void
TestGuardDirSemantics(void)
{
    printf("[11] 受保护对象 / 可信写入者 = 路径边界锚定\n");

    Check(HitsAnchored(L"\\WINDOWS\\SYSTEM32\\CONFIG\\",
                       L"\\Device\\HarddiskVolume3\\Windows\\System32\\config\\SAM"),
          "注册表 hive 在受保护目录内 -> 命中");
    Check(HitsAnchored(L"\\SYSTEM VOLUME INFORMATION\\",
                       L"\\Device\\HarddiskVolume5\\System Volume Information\\{guid}{3808876b}"),
          "卷影副本目录(任意卷)-> 命中");
    Check(HitsAnchored(L"\\MYDATA\\",
                       L"\\Device\\Mup\\server\\share\\MyData\\x.docx"),
          "网络路径不依赖卷前缀识别，目录边界仍命中");
    Check(!HitsAnchored(L"\\WINDOWS\\SYSTEM32\\CONFIG\\",
                        L"\\Device\\HarddiskVolume3\\Windows\\System32\\drivers\\etc\\hosts"),
          "同在 System32 但不在该子目录 -> 不命中");
    Check(!HitsAnchored(L"\\WINDOWS\\SYSTEM32\\CONFIG\\SYSTEM",
                        L"\\Device\\HarddiskVolume3\\Windows\\System32\\config\\systemprofile\\x"),
          "SYSTEM 文件条目不再误命中 systemprofile 子目录");
    Check(!HitsAnchored(L"\\DATA", L"\\Device\\HarddiskVolume2\\Database\\x.db"),
          "无尾斜杠按完整文件匹配，不会误命中 Database");
    Check(!HitsAnchored(L"\\DATA\\", L"\\Device\\HarddiskVolume2\\Database\\x.db"),
          "目录边界不会误命中同前缀目录");
    Check(HitsAnchored(L"\\BOOT\\BCD", L"\\Device\\HarddiskVolume1\\Boot\\BCD"),
          "BCD 无扩展名文件条目 -> 精确命中");

    Check(HitsAnchored(L"\\PROGRAM FILES\\MYAPP\\MYAPP.EXE",
                       L"\\Device\\HarddiskVolume3\\Program Files\\MyApp\\myapp.exe"),
          "精确映像路径 -> 可信");
    Check(HitsAnchored(L"\\PROGRAM FILES\\MYAPP\\",
                       L"\\Device\\HarddiskVolume3\\Program Files\\MyApp\\tools\\helper.exe"),
          "目录前缀(信任整个文件夹)-> 其下程序都可信");
    Check(!HitsAnchored(L"\\PROGRAM FILES\\MYAPP\\MYAPP.EXE",
                        L"\\Device\\HarddiskVolume3\\Temp\\myapp.exe.tmp\\dropper.exe"),
          "加白名被用作目录名 -> 【不】可信");
    Check(!HitsAnchored(L"\\MYAPP.EXE",
                        L"\\Device\\HarddiskVolume3\\Temp\\notmyapp.exe"),
          "不在目录边界起 -> 【不】可信");
    Check(HitsAnchored(L"\\MYAPP.EXE",
                       L"\\Device\\HarddiskVolume3\\Temp\\myapp.exe"),
          "目录边界起、到串尾止 -> 可信(文件名片段写法仍可用)");
}

static void
TestUninstallerData(void)
{
    printf("[12] BlwFileIsUninstallerData(Inno 卸载器数据豁免)\n");

    UNICODE_STRING us;
    BLW_MATCH_CTX ctx;

#define UD(path) (MakeUs(&us, path), BlwPrepareMatch(&ctx, &us), BlwFileIsUninstallerData(&ctx))

    Check(UD(L"C:\\Program Files\\Bulwark\\unins000.dat"), "unins000.dat -> 豁免");
    Check(UD(L"C:\\Program Files\\Bulwark\\unins000.msg"), "unins000.msg -> 豁免");
    Check(UD(L"C:\\Program Files\\Bulwark\\unins001.dat"), "unins001.dat(第二套卸载器)-> 豁免");
    Check(UD(L"\\Device\\HarddiskVolume3\\Program Files\\Bulwark\\UNINS000.DAT"),
          "规范名 + 已大写 -> 豁免");
    Check(UD(L"unins000.dat"), "无目录前缀 -> 仍认文件名");

    Check(!UD(L"C:\\Program Files\\Bulwark\\unins000.exe"), "unins000.exe -> 不豁免");
    Check(!UD(L"C:\\Program Files\\Bulwark\\bulwark_ui.exe"), "产品 exe -> 不豁免");
    Check(!UD(L"C:\\Program Files\\Bulwark\\appsettings.json"), "产品配置 -> 不豁免");
    Check(!UD(L"C:\\ProgramData\\Bulwark\\rules.json"), "规则文件 -> 不豁免");

    Check(!UD(L"C:\\Program Files\\Bulwark\\unins.dat"), "UNINS 后必须有数字 -> 不豁免");
    Check(!UD(L"C:\\Program Files\\Bulwark\\unins000"), "无扩展名 -> 不豁免");
    Check(!UD(L"C:\\Program Files\\Bulwark\\unins000.txt"), "别的扩展名 -> 不豁免");
    Check(!UD(L"C:\\Program Files\\Bulwark\\unins000.dat.bak"), "后缀不对 -> 不豁免");
    Check(!UD(L"C:\\Temp\\evil_unins000.dat.tmp\\dropper.dat"),
          "同名用作目录段 -> 不豁免(只看最后一段文件名)");

    {
        BLW_MATCH_CTX empty;
        empty.Original = NULL;
        empty.Chars = 0;
        Check(!BlwFileIsUninstallerData(&empty), "空 ctx -> 不豁免");
    }

#undef UD
}

static void
TestInjectionTelemetryTargets(void)
{
    printf("[13] BlwIsInjectionTelemetryTarget(远程线程遥测目标)\n");

#define IT(path) BlwIsInjectionTelemetryTarget((path), Chars(path))

    Check(IT(L"\\Device\\HarddiskVolume3\\Windows\\System32\\lsass.exe"),
          "传统高价值目标 lsass -> 命中");
    Check(IT(L"C:\\Program Files\\Tencent\\QQNT\\QQ.exe"),
          "IM 高价值目标 QQ -> 命中");
    Check(!IT(L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
          "PowerShell 初始线程由 ETW 覆盖 -> 驱动不命中");
    Check(!IT(L"C:\\Program Files\\PowerShell\\7\\PWSH.EXE"),
          "pwsh 初始线程由 ETW 覆盖 -> 驱动不命中");
    Check(!IT(L"C:\\Windows\\System32\\wscript.exe"), "WSH wscript -> 驱动不命中");
    Check(!IT(L"C:\\Windows\\System32\\cscript.exe"), "WSH cscript -> 驱动不命中");
    Check(!IT(L"C:\\Windows\\System32\\mshta.exe"), "mshta -> 驱动不命中");
    Check(!IT(L"C:\\Windows\\System32\\rundll32.exe"), "rundll32 -> 驱动不命中");
    Check(!IT(L"C:\\Windows\\System32\\regsvr32.exe"), "regsvr32 -> 驱动不命中");
    Check(!IT(L"C:\\Windows\\System32\\notpowershell.exe"),
          "后缀伪装名称 -> 不命中");
    Check(!IT(L"C:\\Program Files\\Browser\\browser.exe"),
          "普通进程 -> 不命中");
    Check(!IT(L"powershell.exe"),
          "无路径分隔符不满足内核映像路径语义 -> 不命中");
    Check(!BlwIsInjectionTelemetryTarget(NULL, 0), "空路径 -> 不命中");

#undef IT
}

static void
TestProtectedPathInstallScenarios(void)
{
    printf("[13] 受保护路径 = 装机/卸载场景不误伤\n");

    /* 启动文件夹:卸载器删除自启快捷方式是正常动作 */
    Check(HitsAnchored(L"\\START MENU\\PROGRAMS\\STARTUP\\",
                       L"\\Device\\HarddiskVolume3\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\MyApp.lnk"),
          "启动文件夹 .lnk -> 受保护(命中)");
    Check(!HitsAnchored(L"\\START MENU\\PROGRAMS\\STARTUP\\",
                        L"\\Device\\HarddiskVolume3\\Program Files\\MyApp\\unins000.exe"),
          "启动文件夹条目不误命中卸载器自身");

    /* hosts:合法软件改 hosts 常见,条目须精确到文件 */
    Check(HitsAnchored(L"\\SYSTEM32\\DRIVERS\\ETC\\HOSTS",
                       L"\\Device\\HarddiskVolume3\\Windows\\System32\\drivers\\etc\\hosts"),
          "hosts 精确文件 -> 受保护(命中)");
    Check(!HitsAnchored(L"\\SYSTEM32\\DRIVERS\\ETC\\HOSTS",
                        L"\\Device\\HarddiskVolume3\\Windows\\System32\\drivers\\etc\\hosts.backup"),
          "hosts.backup 不在保护范围 -> 不命中");

    /* 任务计划:装机/卸载注册与删除任务定义是常态 */
    Check(HitsAnchored(L"\\SYSTEM32\\TASKS\\",
                       L"\\Device\\HarddiskVolume3\\Windows\\System32\\Tasks\\Microsoft\\Windows\\UpdateOrchestrator\\Scan"),
          "任务定义在 Tasks 目录内 -> 受保护(命中)");
    Check(HitsAnchored(L"\\WINDOWS\\TASKS\\",
                       L"\\Device\\HarddiskVolume3\\Windows\\Tasks\\MyAppUpdater.job"),
          "Windows\\Tasks 条目 -> 受保护(命中)");
    Check(!HitsAnchored(L"\\SYSTEM32\\TASKS\\",
                        L"\\Device\\HarddiskVolume3\\Windows\\System32\\TasksFolder\\x"),
          "同前缀但非该目录 -> 不命中");

    /* 无目录前缀写法不得靠子串误命中 */
    Check(!HitsAnchored(L"HOSTS",
                        L"\\Device\\HarddiskVolume3\\Users\\u\\Downloads\\hosts-samples\\list.txt"),
          "裸 HOSTS 名不误命中同名子串目录");
}

static void
TestSystemVolume(void)
{
    printf("[14] 系统卷判定(可信路径必须落在 Windows 所在卷)\n");

    BlwSetSystemVolume(L'c', L"\\Device\\HarddiskVolume3", Chars(L"\\Device\\HarddiskVolume3"));
    Check(BlwSystemVolumeKnown(), "设置后系统卷已知");

#define SVO(p) BlwSystemVolumeRelativeOffset((p), Chars(p))
#define SPS(p, lit) BLW_SYSVOL_PATH_STARTS((p), Chars(p), lit)

    Check(SVO(L"\\Device\\HarddiskVolume3\\Windows\\x.exe") == 23, "系统卷设备名 -> 23");
    Check(SVO(L"\\DEVICE\\HARDDISKVOLUME3\\Windows\\x.exe") == 23, "设备名大小写不敏感");
    Check(SVO(L"\\Device\\HarddiskVolume4\\Windows\\x.exe") == 0, "别的卷 -> 0");
    Check(SVO(L"\\Device\\HarddiskVolume30\\Windows\\x.exe") == 0, "卷号前缀相同但不是同一卷 -> 0");
    Check(SVO(L"\\??\\C:\\Windows\\x.exe") == 6, "\\??\\C:\\ -> 6");
    Check(SVO(L"\\??\\c:\\Windows\\x.exe") == 6, "小写盘符 -> 6");
    Check(SVO(L"\\??\\E:\\Windows\\x.exe") == 0, "\\??\\E:\\ -> 0");
    Check(SVO(L"C:\\Windows\\x.exe") == 2, "C:\\ -> 2");
    Check(SVO(L"E:\\Windows\\x.exe") == 0, "E:\\ -> 0");
    Check(SVO(L"\\??\\UNC\\srv\\share\\x.exe") == 0, "网络路径 -> 0");
    Check(SVO(L"\\Device\\Mup\\srv\\Windows\\System32\\x.exe") == 0, "\\Device\\Mup -> 0");

    Check(SPS(L"\\??\\C:\\Windows\\System32\\svchost.exe", L"\\Windows\\System32\\"),
          "系统盘的 System32 -> 系统目录");
    Check(!SPS(L"\\??\\E:\\Windows\\System32\\svchost.exe", L"\\Windows\\System32\\"),
          "U 盘 / ISO 上的 E:\\Windows\\System32 -> 不是系统目录");
    Check(!SPS(L"\\Device\\HarddiskVolume5\\Windows\\System32\\lsass.exe", L"\\Windows\\System32\\"),
          "第二块硬盘上的 \\Windows\\System32 -> 不是系统目录");
    Check(!SPS(L"E:\\Program Files\\x\\evil.exe", L"\\Program Files\\"),
          "非系统盘的 Program Files -> 不可信");
    Check(SPS(L"\\Device\\HarddiskVolume3\\Program Files\\App\\a.exe", L"\\Program Files\\"),
          "系统卷的 Program Files -> 可信");

    BlwSetSystemVolume(L'C', L"\\Device\\HarddiskVolume3", BLW_SYSVOL_DEVICE_MAX);
    Check(!BlwSystemVolumeKnown(), "设备名过长 -> 保持未知");
    BlwSetSystemVolume(L'1', L"\\Device\\HarddiskVolume3", Chars(L"\\Device\\HarddiskVolume3"));
    Check(!BlwSystemVolumeKnown(), "非法盘符 -> 保持未知");

    BlwSetSystemVolume(0, NULL, 0);
    Check(!BlwSystemVolumeKnown(), "清空后回到未知");
    Check(SVO(L"\\??\\E:\\Windows\\x.exe") == 6, "未知时退回任意卷语义");

#undef SVO
#undef SPS
}

// 假的存在性探测:Context 指向「存在」的那条剩余路径(大写),NULL 表示什么都不存在。
static const wchar_t* g_probeLastRest = NULL;

static BOOLEAN
FakeProbe(PVOID Context, PCWSTR Rest, USHORT RestChars)
{
    const wchar_t* exists = (const wchar_t*)Context;
    g_probeLastRest = Rest;
    return exists != NULL && Chars(exists) == RestChars && wcsncmp(exists, Rest, RestChars) == 0;
}

// 改名只动最后一段(LastStart = 最后一段起点);整棵恢复改写整个子树(LastStart = 0)。
static BOOLEAN
SubtreeHitsProbe(const wchar_t* pattern, const wchar_t* dir, BOOLEAN wholeTree,
                 BLW_SUBTREE_PROBE probe, PVOID context)
{
    static BLW_PROTECTED_PATH list[BLW_MAX_PROTECTED];
    BLW_MATCH_CTX ctx;
    UNICODE_STRING us;
    USHORT last;

    ListClear(list);
    ListAdd(list, pattern);
    MakeUs(&us, dir);
    BlwPrepareMatch(&ctx, &us);
    last = ctx.Chars;
    while (last > 0 && ctx.Up[last - 1] != L'\\') {
        last--;
    }
    return BlwListHitsSubtree(ctx.Up, ctx.Chars, wholeTree ? 0 : last, list, ListCount(list),
                              probe, context);
}

static BOOLEAN
SubtreeHits(const wchar_t* pattern, const wchar_t* dir, BOOLEAN wholeTree)
{
    return SubtreeHitsProbe(pattern, dir, wholeTree, NULL, NULL);
}

static void
TestSubtreeHits(void)
{
    static const wchar_t kDocs[] = L"\\Users\\alice\\Documents\\";
    static const wchar_t kVol[] = L"\\Device\\HarddiskVolume3";

    printf("[15] 目录改名 / 整棵恢复会不会让名单条目失配\n");

    Check(SubtreeHits(kDocs, L"\\Device\\HarddiskVolume3\\Users\\alice\\Documents", FALSE),
          "改名受保护目录本身");
    Check(SubtreeHits(kDocs, L"\\Device\\HarddiskVolume3\\Users\\alice", FALSE),
          "改名上级目录");
    Check(SubtreeHits(kDocs, L"\\Device\\HarddiskVolume3\\Users", FALSE),
          "改名更上一级目录");
    Check(!SubtreeHits(kDocs, L"\\Device\\HarddiskVolume3\\Users\\alice\\Documents\\Proj", FALSE),
          "改名受保护目录里的子目录不归这里管(逐路径判定已覆盖)");
    Check(!SubtreeHits(kDocs, L"\\Device\\HarddiskVolume3\\Users\\alice\\Downloads", FALSE),
          "兄弟目录不命中");
    Check(!SubtreeHits(kDocs, L"\\Device\\HarddiskVolume3\\Users\\alice\\Docs", FALSE),
          "前缀相近的兄弟目录不命中");
    Check(!SubtreeHits(kDocs, kVol, FALSE), "卷根不命中");

    Check(SubtreeHits(L"\\Start Menu\\Programs\\Startup\\",
                      L"\\Device\\HarddiskVolume3\\Users\\a\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu",
                      FALSE),
          "相对条目:改名其中一段命中");
    Check(!SubtreeHits(L"\\Start Menu\\Programs\\Startup\\",
                       L"\\Device\\HarddiskVolume3\\Users\\a\\AppData\\Roaming", FALSE),
          "相对条目:改名条目之外的上级,改名后条目仍然成立");
    Check(SubtreeHits(L"\\System32\\drivers\\etc\\hosts",
                      L"\\Device\\HarddiskVolume3\\Windows\\System32\\drivers\\etc", FALSE),
          "文件条目所在目录改名命中");

    Check(SubtreeHits(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
                      L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", TRUE),
          "整棵恢复硬拦值所在的键");
    Check(!SubtreeHits(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
                       L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify",
                       TRUE),
          "整棵恢复旁支键不命中");
    Check(SubtreeHits(L"\\Services\\Bulwark",
                      L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services", TRUE),
          "整棵恢复 Services 命中相对条目");
    Check(SubtreeHits(L"\\Services\\Bulwark",
                      L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\Bulwark\\Parameters", TRUE),
          "整棵恢复条目下的子键也命中");
    Check(!SubtreeHits(L"\\Services\\Bulwark",
                       L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\Bulwark\\Parameters", FALSE),
          "只改名条目下的子键不影响条目本身");

    {
        static BLW_PROTECTED_PATH empty[BLW_MAX_PROTECTED];
        ListClear(empty);
        Check(!BlwListHitsSubtree(L"\\X", 2, 0, empty, 0, NULL, NULL), "空名单不命中");
    }

    /* 条目是任意位置的子串:随便一个叫 boot 的目录名字都对得上 \BOOT\BCD,
       有探测时必须核实子树里真有那条路径才算。 */
    Check(!SubtreeHitsProbe(L"\\Boot\\BCD", L"\\Device\\HarddiskVolume5\\proj\\boot", FALSE,
                            FakeProbe, NULL),
          "探测:项目里叫 boot 的目录(子树里没有 BCD)可以改名");
    Check(g_probeLastRest != NULL && wcsncmp(g_probeLastRest, L"BCD", 3) == 0,
          "探测收到的剩余部分是 BCD");
    Check(SubtreeHitsProbe(L"\\Boot\\BCD", L"\\Device\\HarddiskVolume3\\Boot", FALSE,
                           FakeProbe, (PVOID)L"BCD"),
          "探测:真正的 \\Boot(子树里有 BCD)改名被拦");
    Check(SubtreeHitsProbe(kDocs, L"\\Device\\HarddiskVolume3\\Users", FALSE,
                           FakeProbe, (PVOID)L"ALICE\\DOCUMENTS\\"),
          "探测:Users 下真有 alice\\Documents 时改名 Users 被拦");
    Check(!SubtreeHitsProbe(kDocs, L"\\Device\\HarddiskVolume5\\data\\users", FALSE, FakeProbe, NULL),
          "探测:别处叫 users 的目录可以改名");
    g_probeLastRest = NULL;
    Check(SubtreeHitsProbe(kDocs, L"\\Device\\HarddiskVolume3\\Users\\alice\\Documents", FALSE,
                           FakeProbe, NULL),
          "探测:条目完整落在目录路径里(改名受保护目录本身)不需要探测也命中");
    Check(g_probeLastRest == NULL, "条目完整落在路径里时不调用探测");
}

// 返回的条目只在下一次调用前有效。
static const BLW_PROTECTED_PATH*
RgEntry(const wchar_t* s)
{
    static BLW_PROTECTED_PATH list[BLW_MAX_PROTECTED];
    ListClear(list);
    ListAdd(list, s);
    return &list[0];
}

static BOOLEAN
RgDataHit(const wchar_t* entry, const wchar_t* target)
{
    BLW_MATCH_CTX ctx;
    UNICODE_STRING us;
    MakeUs(&us, target);
    BlwPrepareMatch(&ctx, &us);
    return BlwReadGuardDataHit(RgEntry(entry), ctx.Up, ctx.Chars);
}

static BOOLEAN
RgReader(const wchar_t* entry, const wchar_t* image)
{
    return BlwReadGuardReaderHit(RgEntry(entry), image, Chars(image));
}

static BOOLEAN
RgGlobal(const wchar_t* reader, const wchar_t* image)
{
    return BlwReadGuardGlobalReaderHit(RgEntry(reader), image, Chars(image));
}

static void
TestReadGuard(void)
{
    static const wchar_t kChrome[] =
        L"\\Google\\Chrome\\User Data\\|\\Google\\Chrome\\Application\\;\\Google\\Update\\";
    static const wchar_t kTelegram[] = L"\\Telegram Desktop\\tdata\\|\\Telegram Desktop\\Telegram.exe";

    printf("[16] 窃密防护:数据片段命中、指定读者(锚在安装根)、全局读者\n");

    BlwSetSystemVolume(L'C', L"\\Device\\HarddiskVolume3", Chars(L"\\Device\\HarddiskVolume3"));

    {
        const BLW_PROTECTED_PATH* e = RgEntry(kChrome);
        Check(BlwReadGuardDataChars(e) == Chars(L"\\Google\\Chrome\\User Data\\"), "数据片段长度到 '|' 为止");
        Check(wcschr(e->Path, L'|') != NULL && wcschr(e->Path, L';') != NULL, "大写化保留分隔符");
        e = RgEntry(L"\\Exodus\\exodus.wallet\\");
        Check(BlwReadGuardDataChars(e) == e->Length, "没有 '|' 时整条都是数据片段");
    }

    Check(RgDataHit(kChrome, L"\\Device\\HarddiskVolume3\\Users\\alice\\AppData\\Local\\Google\\Chrome"
                             L"\\User Data\\Default\\Login Data"),
          "数据:浏览器登录库命中");
    Check(RgDataHit(kChrome, L"\\??\\C:\\Users\\alice\\AppData\\Local\\google\\chrome\\user data\\Local State"),
          "数据:原始名 \\??\\ 前缀、小写也命中");
    Check(!RgDataHit(kChrome, L"\\Device\\HarddiskVolume3\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
          "数据:程序目录不是数据");
    Check(!RgDataHit(kChrome, L"\\Device\\HarddiskVolume3\\Users\\alice\\AppData\\Local\\Google\\Chrome\\User Data"),
          "数据:目录本身(无结尾 '\\')不命中,其子项才命中");
    Check(RgDataHit(L"\\FileZilla\\sitemanager.xml|\\FileZilla FTP Client\\",
                    L"\\Device\\HarddiskVolume3\\Users\\a\\AppData\\Roaming\\FileZilla\\sitemanager.xml.bak"),
          "数据:文件片段也命中其备份");

#define IR(p) BlwImageInstallRelative((p), Chars(p))
    Check(IR(L"\\Device\\HarddiskVolume3\\Program Files\\Google\\Chrome\\Application\\chrome.exe") == 37,
          "安装根:Program Files");
    Check(IR(L"\\Device\\HarddiskVolume3\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe") == 43,
          "安装根:Program Files (x86)");
    Check(IR(L"\\Device\\HarddiskVolume3\\Users\\alice\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe") == 49,
          "安装根:用户 AppData\\Local");
    Check(IR(L"\\??\\C:\\Users\\bob\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe") == 32,
          "安装根:用户 AppData\\Roaming(\\??\\ 形式)");
    Check(IR(L"\\Device\\HarddiskVolume3\\Users\\Public\\AppData\\Local\\Google\\Chrome\\Application\\x.exe") == 0,
          "安装根:Public 人人可写,不认");
    Check(IR(L"\\Device\\HarddiskVolume3\\Users\\alice\\AppData\\LocalLow\\x\\x.exe") == 0, "安装根:LocalLow 不认");
    Check(IR(L"\\Device\\HarddiskVolume3\\Users\\alice\\Downloads\\x.exe") == 0, "安装根:下载目录不认");
    Check(IR(L"\\Device\\HarddiskVolume5\\Program Files\\x\\x.exe") == 0, "安装根:别的卷不认");
    Check(IR(L"\\Device\\HarddiskVolume3\\Program Files") == 0, "安装根:根本身不算");
    Check(IR(L"\\Device\\HarddiskVolume3\\Users\\\\AppData\\Local\\x\\x.exe") == 0, "安装根:空用户名不认");
#undef IR

    Check(RgReader(kChrome, L"\\Device\\HarddiskVolume3\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
          "读者:系统级安装的 Chrome");
    Check(RgReader(kChrome, L"\\Device\\HarddiskVolume3\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe"),
          "读者:第二个读者片段(更新程序)");
    Check(RgReader(kChrome, L"\\Device\\HarddiskVolume3\\Users\\alice\\AppData\\Local\\Google\\Chrome"
                            L"\\Application\\121.0\\crashpad_handler.exe"),
          "读者:按用户安装的 Chrome 子目录里的辅助程序");
    Check(!RgReader(kChrome, L"\\Device\\HarddiskVolume3\\Users\\alice\\AppData\\Local\\Temp\\Google\\Chrome"
                             L"\\Application\\chrome.exe"),
          "读者:Temp 里仿造的安装目录不认");
    Check(!RgReader(kChrome, L"\\Device\\HarddiskVolume3\\Users\\alice\\Google\\Chrome\\Application\\chrome.exe"),
          "读者:用户目录根下仿造的不认");
    Check(!RgReader(kChrome, L"\\Device\\HarddiskVolume5\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
          "读者:别的卷上的同名目录不认");
    Check(!RgReader(kChrome, L"\\Device\\HarddiskVolume3\\Program Files\\Google\\Chrome\\ApplicationX\\x.exe"),
          "读者:目录片段按目录边界比");
    Check(!RgReader(kChrome, L"\\Device\\HarddiskVolume3\\Users\\alice\\AppData\\Local\\Google\\Chrome"
                             L"\\User Data\\evil.exe"),
          "读者:数据目录里的程序不认");
    Check(RgReader(kTelegram, L"\\Device\\HarddiskVolume3\\Users\\a\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe"),
          "读者:文件片段整段相等");
    Check(!RgReader(kTelegram, L"\\Device\\HarddiskVolume3\\Users\\a\\AppData\\Roaming\\Telegram Desktop\\evil.exe"),
          "读者:同目录别的程序不认");
    Check(!RgReader(kTelegram, L"\\Device\\HarddiskVolume3\\Users\\a\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe.x"),
          "读者:文件片段不按前缀比");
    Check(!RgReader(L"\\Exodus\\exodus.wallet\\", L"\\Device\\HarddiskVolume3\\Program Files\\Exodus\\Exodus.exe"),
          "读者:没有读者片段的条目谁都不是读者");
    Check(RgReader(L"\\X\\Data\\|;;\\Vendor\\App\\;", L"\\Device\\HarddiskVolume3\\Program Files\\Vendor\\App\\a.exe"),
          "读者:空片段跳过");

    Check(RgGlobal(L"\\Program Files\\Acme\\backup.exe", L"\\Device\\HarddiskVolume3\\Program Files\\Acme\\backup.exe"),
          "全局读者:系统卷 Program Files 下的程序");
    Check(!RgGlobal(L"\\Program Files\\Acme\\backup.exe", L"\\Device\\HarddiskVolume5\\Program Files\\Acme\\backup.exe"),
          "全局读者:Program Files 只认系统卷");
    Check(!RgGlobal(L"\\Program Files\\Acme\\backup.exe",
                    L"\\Device\\HarddiskVolume3\\Program Files\\Acme\\backup.exe.old"),
          "全局读者:文件按整段比");
    Check(RgGlobal(L"\\Tools\\Sync\\", L"\\Device\\HarddiskVolume5\\Tools\\Sync\\sync.exe"),
          "全局读者:其他目录任意卷");
    Check(!RgGlobal(L"\\Tools\\Sync\\", L"\\Device\\HarddiskVolume5\\Tools\\SyncX\\sync.exe"),
          "全局读者:目录边界");
    Check(!RgGlobal(L"\\Tools\\Sync\\", L"\\Device\\HarddiskVolume5\\x\\Tools\\Sync\\sync.exe"),
          "全局读者:从卷根比,不是任意位置子串");

    {
        static const wchar_t kTok[] = L"\\GOOGLE\\CHROME\\USER DATA\\";
        BLW_MATCH_CTX ctx;
        UNICODE_STRING us;
        USHORT last;

#define RG_SUBTREE(dir, expect, what)                                                         \
        do {                                                                                  \
            MakeUs(&us, dir);                                                                 \
            BlwPrepareMatch(&ctx, &us);                                                       \
            last = ctx.Chars;                                                                 \
            while (last > 0 && ctx.Up[last - 1] != L'\\') last--;                             \
            Check(BlwPatternHitsSubtree(ctx.Up, ctx.Chars, last, kTok, Chars(kTok), NULL, NULL) \
                  == (expect), what);                                                         \
        } while (0)

        RG_SUBTREE(L"\\Device\\HarddiskVolume3\\Users\\a\\AppData\\Local\\Google\\Chrome\\User Data", TRUE,
                   "改名:数据目录本身");
        RG_SUBTREE(L"\\Device\\HarddiskVolume3\\Users\\a\\AppData\\Local\\Google\\Chrome", TRUE,
                   "改名:数据目录的上级");
        RG_SUBTREE(L"\\Device\\HarddiskVolume3\\Users\\a\\AppData\\Local\\Google\\Chrome\\User Data\\Default",
                   FALSE, "改名:数据目录里的子目录(改完仍在保护范围内)");
        RG_SUBTREE(L"\\Device\\HarddiskVolume3\\Users\\a\\AppData\\Local", FALSE,
                   "改名:与数据片段不重叠的上级");
#undef RG_SUBTREE
    }

    BlwSetSystemVolume(0, NULL, 0);
}

int
main(void)
{
    printf("Bulwark driver match-core unit test\n");

    TestVolumeOffset();
    TestVolumePathStartsWith();
    TestImageNameIn();
    TestWideContains();
    TestListAddRemove();
    TestSubstringSemantics();
    TestAnchoredSemantics();
    TestLongTargetFallback();
    TestCmdPattern();
    TestDriveLetterPattern();
    TestGuardDirSemantics();
    TestUninstallerData();
    TestInjectionTelemetryTargets();
    TestProtectedPathInstallScenarios();
    TestSystemVolume();
    TestSubtreeHits();
    TestReadGuard();

    Check(RgDataHit(L"\\.SSH\\ID_RSA$", L"C:\\Users\\Alice\\.ssh\\id_rsa"),
          "credential: exact private key path is protected");
    Check(!RgDataHit(L"\\.SSH\\ID_RSA$", L"C:\\Users\\Alice\\.ssh\\id_rsa.pub"),
          "credential: public key is not a private key");
    Check(RgDataHit(L"\\.AWS\\CREDENTIALS$|\\AMAZON\\AWSCLIV2\\AWS.EXE", L"C:\\Users\\Alice\\.aws\\credentials"),
          "credential: anchored data works with designated-reader suffix");
    {
        UCHAR address[16] = {0};
        Check(BlwParseIpv6Hex(L"20010db8000000000000000000000001", 32, address)
              && address[0] == 0x20 && address[1] == 1 && address[15] == 1,
              "network: IPv6 config decodes all 128 bits in network order");
        Check(!BlwParseIpv6Hex(L"20010db800000000000000000000000Z", 32, address),
              "network: invalid hex rejected");
        Check(!BlwParseIpv6Hex(L"1234", 4, address), "network: truncated IPv6 rejected");
    }

    {
        static const wchar_t systemVolume[] = L"\\Device\\HarddiskVolume3";
        BlwSetSystemVolume(L'C', systemVolume, Chars(systemVolume));
        Check(BlwIsRansomGuardSystemWriter(L"\\Device\\HarddiskVolume3\\Windows\\System32\\notepad.exe",
              Chars(L"\\Device\\HarddiskVolume3\\Windows\\System32\\notepad.exe")),
              "writer: exact OS editor on the system volume");
        Check(!BlwIsRansomGuardSystemWriter(L"\\Device\\HarddiskVolume3\\Program Files\\Audit\\payload.exe",
              Chars(L"\\Device\\HarddiskVolume3\\Program Files\\Audit\\payload.exe")),
              "writer: Program Files is not a blanket authorization");
        Check(!BlwIsRansomGuardSystemWriter(L"\\Device\\HarddiskVolume3\\Windows\\System32\\payload.exe",
              Chars(L"\\Device\\HarddiskVolume3\\Windows\\System32\\payload.exe")),
              "writer: arbitrary system-directory images are not OS writers");
        Check(!BlwIsRansomGuardSystemWriter(L"\\Device\\HarddiskVolume5\\Windows\\System32\\notepad.exe",
              Chars(L"\\Device\\HarddiskVolume5\\Windows\\System32\\notepad.exe")),
              "writer: OS writer paths remain pinned to the system volume");
        BlwSetSystemVolume(0, NULL, 0);
    }

    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    return g_failed;
}
