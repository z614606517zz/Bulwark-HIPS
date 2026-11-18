#pragma once

#ifdef BLW_MATCHCORE_HOST

#include <sal.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

typedef wchar_t            WCHAR;
typedef unsigned char      UCHAR;
typedef unsigned char      BOOLEAN;
typedef unsigned short     USHORT;
typedef unsigned long      ULONG;
typedef long               LONG;
typedef unsigned long long ULONG64;
typedef size_t             SIZE_T;
typedef const WCHAR*       PCWSTR;
typedef WCHAR*             PWCH;
typedef WCHAR*             PWSTR;
typedef const char*        PCSTR;
typedef void*              PVOID;

typedef struct _BLW_HOST_UNICODE_STRING {
    USHORT Length;          // 字节数(与内核 UNICODE_STRING 一致)
    USHORT MaximumLength;
    PWCH   Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif
#ifndef NULL
#define NULL ((void*)0)
#endif

#define FORCEINLINE                 static __forceinline
#define RTL_NUMBER_OF(a)            (sizeof(a) / sizeof((a)[0]))
#define C_ASSERT(e)                 typedef char __C_ASSERT__[(e) ? 1 : -1]
#define UNREFERENCED_PARAMETER(p)   ((void)(p))
#define RtlEqualMemory(d, s, n)     (!memcmp((d), (s), (n)))
#define RtlZeroMemory(d, n)         memset((d), 0, (n))
#define RtlCopyMemory(d, s, n)      memcpy((d), (s), (n))
#define RtlUpcaseUnicodeChar(c)     ((WCHAR)towupper((wint_t)(c)))
#define KdPrint(x)                  ((void)0)
#define KeMemoryBarrier()           ((void)0)

FORCEINLINE void
RtlInitUnicodeString(_Out_ PUNICODE_STRING Dest, _In_opt_ PCWSTR Src)
{
    size_t n = (Src != NULL) ? wcslen(Src) : 0;
    Dest->Buffer = (PWCH)Src;
    Dest->Length = (USHORT)(n * sizeof(WCHAR));
    Dest->MaximumLength = Dest->Length;
}

#endif

#include "Protocol.h"

#define BLW_MAX_PROTECTED 64

typedef struct _BLW_PROTECTED_PATH {
    WCHAR   Path[BLW_MAX_PATH];
    USHORT  Length;
    BOOLEAN InUse;
} BLW_PROTECTED_PATH, *PBLW_PROTECTED_PATH;

FORCEINLINE WCHAR
BlwUpcaseChar(_In_ WCHAR c)
{
    if (c >= L'a' && c <= L'z') {
        return (WCHAR)(c - L'a' + L'A');
    }
    if (c < 0x80) {
        return c;
    }
    return RtlUpcaseUnicodeChar(c);
}

FORCEINLINE BOOLEAN
BlwStartsWithCI(_In_reads_(Chars) PCWSTR Path, _In_ USHORT Chars,
                _In_ PCWSTR Literal, _In_ USHORT LiteralChars)
{
    USHORT i;

    if (Path == NULL || Chars < LiteralChars) {
        return FALSE;
    }
    for (i = 0; i < LiteralChars; i++) {
        if (BlwUpcaseChar(Path[i]) != BlwUpcaseChar(Literal[i])) {
            return FALSE;
        }
    }
    return TRUE;
}

FORCEINLINE USHORT
BlwVolumeRelativeOffset(_In_reads_(Chars) PCWSTR Path, _In_ USHORT Chars)
{
    if (Path == NULL || Chars < 3) {
        return 0;
    }

    if (BlwStartsWithCI(Path, Chars, L"\\??\\", 4)) {
        if (BlwStartsWithCI(Path, Chars, L"\\??\\UNC\\", 8)) {
            return 0;
        }
        if (Chars >= 7 && Path[5] == L':' && Path[6] == L'\\') {
            return 6;
        }
        return 0;
    }

    if (BlwStartsWithCI(Path, Chars, L"\\Device\\HarddiskVolume", 22)) {
        USHORT i = 22;
        while (i < Chars && Path[i] >= L'0' && Path[i] <= L'9') {
            i++;
        }
        // 必须真的读到过数字,且其后紧跟 '\'
        if (i > 22 && i < Chars && Path[i] == L'\\') {
            return i;
        }
        return 0;
    }

    if (Chars >= 3 && Path[1] == L':' && Path[2] == L'\\') {
        return 2;
    }

    return 0;
}

#define BLW_SYSVOL_DEVICE_MAX 64

// 系统卷(Windows 所在卷)只在驱动初始化或服务连接时设置一次。DriveLetter 为 0 或设备名
// 不合法时回到「未知」;未知期间系统卷判定退回到任意卷,宁可沿用旧语义也不拒绝系统组件。
void    BlwSetSystemVolume(_In_ WCHAR DriveLetter,
                           _In_reads_opt_(DeviceChars) PCWSTR DeviceName, _In_ USHORT DeviceChars);
BOOLEAN BlwSystemVolumeKnown(void);

// 路径在系统卷上时返回卷前缀之后 '\' 的下标,否则返回 0。「位于系统目录 / Program Files
// 即可信」一类判定必须用它而不是 BlwVolumeRelativeOffset:U 盘、挂载的 ISO、第二块硬盘上
// 都能建出同名目录。
USHORT  BlwSystemVolumeRelativeOffset(_In_reads_(Chars) PCWSTR Path, _In_ USHORT Chars);

// 路径是否位于系统卷且卷内部分以 Literal 开头。Literal 必须以 '\' 开头,如 L"\\Windows\\System32\\"。
BOOLEAN BlwSystemVolumePathStartsWith(_In_opt_ PCWSTR Path, _In_ USHORT Chars,
                                      _In_ PCWSTR Literal, _In_ USHORT LiteralChars);

// lit 须为宽字符串字面量,长度由 sizeof 算出。
#define BLW_SYSVOL_PATH_STARTS(path, chars, lit) \
    BlwSystemVolumePathStartsWith((path), (chars), (lit), (USHORT)(sizeof(lit) / sizeof(WCHAR) - 1))

typedef struct _BLW_MATCH_CTX {
    PCUNICODE_STRING Original;      // 仅 Chars==0 时使用,须在 ctx 生命周期内有效
    USHORT           Chars;         // Up 中的有效字符数;0 = 未预归一化(走 Original 回退)
    WCHAR            Up[BLW_MAX_PATH];
} BLW_MATCH_CTX, *PBLW_MATCH_CTX;

typedef struct _BLW_NAME_ENTRY {
    PCWSTR Name;
    USHORT Chars;   // Name 的字符数(编译期常量)
} BLW_NAME_ENTRY;

#define BLW_NAME(s) { (s), (USHORT)(sizeof(s) / sizeof(WCHAR) - 1) }

void     BlwPrepareMatch(_Out_ PBLW_MATCH_CTX Ctx, _In_opt_ PCUNICODE_STRING Target);

BOOLEAN  BlwMatchInListCtx(_In_ BLW_PROTECTED_PATH* List, _In_ LONG Count,
                           _In_ PBLW_MATCH_CTX Ctx, _In_ USHORT UseChars);

BOOLEAN  BlwMatchInListAnchoredCtx(_In_ BLW_PROTECTED_PATH* List, _In_ LONG Count,
                                   _In_ PBLW_MATCH_CTX Ctx);

// 条目越过 Dir 时,Rest 是条目剩下的部分,拼在「Dir\」后面就是子树里那条候选路径。
// 返回 FALSE 表示候选路径并不存在,这次重叠不算命中。
typedef BOOLEAN (*BLW_SUBTREE_PROBE)(_In_opt_ PVOID Context,
                                     _In_reads_(RestChars) PCWSTR Rest, _In_ USHORT RestChars);

// Dir 为目录或注册表键全路径的大写形式(不带结尾 '\'),末尾补一个 '\' 记作 T。某条目在 T 中的
// 一次出现越过了 LastStart,或 T 的某个后缀恰是条目的前缀,即返回 TRUE —— 改名或整体替换 Dir 后,
// 子树里原本命中该条目的路径就不再命中。只改最后一段(改名)时 LastStart 传最后一段的起点,
// 整棵子树都被改写时传 0。不看锚定规则。条目是可出现在任意位置的子串,Probe 为空时只要
// 名字对得上就算命中(随便一个叫 BOOT 的目录都会被当成 \BOOT\BCD 的上级),所以改名一类
// 高频操作应传 Probe 核实候选路径确实存在。
BOOLEAN  BlwListHitsSubtree(_In_reads_(DirChars) PCWSTR Dir, _In_ USHORT DirChars,
                            _In_ USHORT LastStart,
                            _In_ BLW_PROTECTED_PATH* List, _In_ LONG Count,
                            _In_opt_ BLW_SUBTREE_PROBE Probe, _In_opt_ PVOID Context);

// 单个模式版的 BlwListHitsSubtree,Pat 须已大写。
BOOLEAN  BlwPatternHitsSubtree(_In_reads_(DirChars) PCWSTR Dir, _In_ USHORT DirChars,
                               _In_ USHORT LastStart,
                               _In_reads_(PatChars) PCWSTR Pat, _In_ USHORT PatChars,
                               _In_opt_ BLW_SUBTREE_PROBE Probe, _In_opt_ PVOID Context);

// 窃密防护条目 "数据片段|读者;读者"(条目已大写,格式见 Protocol.h)

// 数据片段的字符数('|' 之前;没有 '|' 时为整条)。
USHORT   BlwReadGuardDataChars(_In_ const BLW_PROTECTED_PATH* Entry);

// 数据片段是否出现在 Up(已大写)中。
BOOLEAN  BlwReadGuardDataHit(_In_ const BLW_PROTECTED_PATH* Entry,
                             _In_reads_(Chars) PCWSTR Up, _In_ USHORT Chars);

// 映像位于系统卷 \Program Files\、\Program Files (x86)\ 或 \Users\<用户名>\AppData\Local\、
// \AppData\Roaming\ 之下时,返回根之后那个 '\' 的下标,否则返回 0。不认 \Users\Public\:
// 那里人人可写,在下面造一个「安装目录」就能冒充读者。
USHORT   BlwImageInstallRelative(_In_reads_(Chars) PCWSTR Image, _In_ USHORT Chars);

// 映像是否是条目的指定读者:从安装根之后比,读者片段以 '\' 结尾时按目录前缀,否则须整段相等。
BOOLEAN  BlwReadGuardReaderHit(_In_ const BLW_PROTECTED_PATH* Entry,
                               _In_reads_(Chars) PCWSTR Image, _In_ USHORT Chars);

// 映像是否是全局读者(去盘符的完整程序路径,或以 '\' 结尾的目录)。以 \Program Files、\Windows\
// 开头的只认系统卷:别的卷根目录普通用户就能建同名目录。
BOOLEAN  BlwReadGuardGlobalReaderHit(_In_ const BLW_PROTECTED_PATH* Entry,
                                     _In_reads_(Chars) PCWSTR Image, _In_ USHORT Chars);

BOOLEAN  BlwAddToList(_In_ BLW_PROTECTED_PATH* List, _In_ PCWSTR Path, _In_ USHORT Length);

BOOLEAN  BlwRemoveFromList(_In_ BLW_PROTECTED_PATH* List, _In_ PCWSTR Path, _In_ USHORT Length);

BOOLEAN  BlwPatternHasDriveLetter(_In_opt_ PCWSTR Pattern, _In_ USHORT Chars);

BOOLEAN  BlwWideContainsCI(_In_ PCWSTR Str, _In_ USHORT StrChars, _In_ PCWSTR Sub);

BOOLEAN  BlwFileIsUninstallerData(_In_ PBLW_MATCH_CTX Ctx);

BOOLEAN  BlwImageNameIn(_In_reads_(TableCount) const BLW_NAME_ENTRY* Table,
                        _In_ ULONG TableCount,
                        _In_opt_ PCWSTR Path, _In_ USHORT Chars);

BOOLEAN  BlwIsInjectionTelemetryTarget(_In_opt_ PCWSTR Path, _In_ USHORT Chars);
BOOLEAN  BlwIsRansomGuardSystemWriter(_In_opt_ PCWSTR Path, _In_ USHORT Chars);

BOOLEAN  BlwCmdPatternMatches(_In_ const BLW_PROTECTED_PATH* Entry,
                              _In_reads_(TargetChars) PCWSTR Target,
                              _In_ ULONG TargetChars);

void     BlwLogPattern(_In_ PCSTR Reason, _In_opt_ PCWSTR Path, _In_ USHORT Chars);

BOOLEAN BlwParseIpv6Hex(_In_reads_(Chars) PCWSTR Hex, _In_ USHORT Chars, _Out_writes_(16) UCHAR* Address);
