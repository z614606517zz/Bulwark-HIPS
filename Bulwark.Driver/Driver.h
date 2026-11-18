#pragma once

#include <fltKernel.h>
#include <ntddk.h>
#include <wdm.h>
#include "Protocol.h"

#include "MatchCore.h"

#define BLW_TAG 'dhSI'

FORCEINLINE PVOID
BlwAllocPool(_In_ POOL_TYPE PoolType, _In_ SIZE_T NumberOfBytes, _In_ ULONG Tag)
{
    PVOID p;

#pragma warning(suppress: 4996 28751)
    p = ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
    if (p != NULL) {
        RtlZeroMemory(p, NumberOfBytes);
    }
    return p;
}

// 名单读多写极少:热路径(每次文件打开、注册表写入)只取共享锁,互不排队。
// Flt* 推锁自带进出临界区,调用方须在 <= APC_LEVEL。
FORCEINLINE void BlwLockShared(_Inout_ PEX_PUSH_LOCK Lock)    { FltAcquirePushLockShared(Lock); }
FORCEINLINE void BlwLockExclusive(_Inout_ PEX_PUSH_LOCK Lock) { FltAcquirePushLockExclusive(Lock); }
FORCEINLINE void BlwUnlock(_Inout_ PEX_PUSH_LOCK Lock)        { FltReleasePushLock(Lock); }

// 注册表回调的临时缓冲:值名捕获、匹配上下文、上报时拼接「键\值」。
typedef struct _BLW_REG_SCRATCH {
    BLW_MATCH_CTX Ctx;
    WCHAR         Name[256];
    WCHAR         Report[BLW_MAX_PATH];
} BLW_REG_SCRATCH, *PBLW_REG_SCRATCH;

#define BLW_EVENT_PATHS_BYTES ((SIZE_T)2 * BLW_MAX_PATH * sizeof(WCHAR))

#define BLW_WFP_LAYER_COUNT 2

#define BLW_WFP_UNREG_RETRIES  5
#define BLW_WFP_UNREG_DELAY_MS 50

#define BLW_MAX_HASHES     1024  // 内置已知恶意哈希上限(32KB;线性匹配,off 热路径)
#define BLW_HASH_QUEUE_CAP 128   // 待扫描 PID 环容量(满则丢弃,漏扫下次仍会扫)
// 必须是 2 的幂:下标推进用位与而非取模(下标为有符号 LONG,编译器无法把 % 优化成位与)。
#define BLW_HASH_QUEUE_MASK (BLW_HASH_QUEUE_CAP - 1)
C_ASSERT((BLW_HASH_QUEUE_CAP & BLW_HASH_QUEUE_MASK) == 0);

#define BLW_WRITE_SLOTS 64
#define BLW_WRITE_SLOT_MASK (BLW_WRITE_SLOTS - 1)
C_ASSERT((BLW_WRITE_SLOTS & BLW_WRITE_SLOT_MASK) == 0);

#define BLW_PID_BIT(pid)  (1ULL << (((pid) >> 2) & 63))

#define BLW_IP_BIT(ip)    (1ULL << ((((ip) >> 13) ^ (ip)) & 63))

typedef struct _BLW_BLOCK_IP {
    ULONG   IpV4;              // 主机字节序
    UCHAR   IpV6[16];
    BOOLEAN IsV6;
    USHORT  Port;              // 0 = 任意端口
    BOOLEAN InUse;
} BLW_BLOCK_IP, *PBLW_BLOCK_IP;

// 窃密防护的「某 PID 对各 ReadGuard 条目能否读」掩码缓存,按 PID 直接映射。
// Tag=(Gen<<32)|Pid(0 为空),Mask 的第 i 位=该 PID 是条目槽 i 的指定读者,全 1 = 对全部放行。
// Seq 偶数=稳定、奇数=有写者在改;写者靠 CAS 抢到奇数才能写,读者前后两次读到同一个偶数才采信,
// 否则两个碰撞 PID 同时写同一格时,读者可能拿到别的进程的掩码。
// SeLocateProcessImageName 很贵,不缓存的话每个读打开都要取一次映像名。PID 复用由进程退出清槽兜底。
#define BLW_RG_CACHE_SLOTS 256
C_ASSERT((BLW_RG_CACHE_SLOTS & (BLW_RG_CACHE_SLOTS - 1)) == 0);
typedef struct _BLW_RG_CACHE_SLOT {
    volatile LONG64 Seq;
    volatile LONG64 Tag;
    volatile LONG64 Mask;
} BLW_RG_CACHE_SLOT, *PBLW_RG_CACHE_SLOT;

typedef struct _BLW_GLOBALS {
    PFLT_FILTER     Filter;
    PFLT_PORT       ServerPort;
    PFLT_PORT       ClientPort;
    EX_RUNDOWN_REF  ClientPortRundown;
                                       // 发送方先 acquire,断开时 wait-for-idle 后再关闭,
                                       // 避免对已释放端口做 FltSendMessage(use-after-free 蓝屏)。
    BOOLEAN         ProcessCallbackRegistered;

    volatile BOOLEAN ClientTrusted;

    volatile BOOLEAN Active;

    BLW_PROTECTED_PATH ProtectedPaths[BLW_MAX_PROTECTED];
    EX_PUSH_LOCK    PathLock;
    volatile LONG   ProtectedPathCount;

    BLW_PROTECTED_PATH FileHardBlock[BLW_MAX_PROTECTED];
    EX_PUSH_LOCK    FileHardLock;
    volatile LONG   FileHardCount;

    BLW_PROTECTED_PATH SelfGuard[BLW_MAX_PROTECTED];
    EX_PUSH_LOCK    SelfGuardLock;
    volatile LONG   SelfGuardCount;

    BLW_PROTECTED_PATH GuardDirs[BLW_MAX_PROTECTED];
    EX_PUSH_LOCK    GuardDirLock;
    volatile LONG   GuardDirCount;
    BLW_PROTECTED_PATH GuardWriters[BLW_MAX_PROTECTED];
    EX_PUSH_LOCK    GuardWriterLock;
    volatile LONG   GuardWriterCount;

    // 窃密防护:条目为 "数据片段|读者;读者"(大写),只许指定程序打开命中数据片段的文件。
    // ReadGuardReaders 是对所有条目放行的全局读者。名单任意变更都会自增 ReadGuardGen,
    // 使下面按 PID 缓存的「可读位掩码」整体失效。
    BLW_PROTECTED_PATH ReadGuard[BLW_MAX_PROTECTED];
    EX_PUSH_LOCK    ReadGuardLock;
    volatile LONG   ReadGuardCount;
    BLW_PROTECTED_PATH ReadGuardReaders[BLW_MAX_PROTECTED];
    EX_PUSH_LOCK    ReadGuardReaderLock;
    volatile LONG   ReadGuardReaderCount;
    volatile LONG   ReadGuardGen;
    DECLSPEC_CACHEALIGN BLW_RG_CACHE_SLOT ReadGuardCache[BLW_RG_CACHE_SLOTS];

    BLW_PROTECTED_PATH FileNoLoad[BLW_MAX_PROTECTED];
    EX_PUSH_LOCK    FileNoLoadLock;
    volatile LONG   FileNoLoadCount;

    // 「禁止执行」名单(执行前拦截):进程创建回调里新进程映像命中即把 CreateInfo->CreationStatus 置为 STATUS_ACCESS_DENIED,
    // 已确认恶意的样本无法启动。与 FileNoLoad 互补:那个拦模块加载,这个拦进程创建。
    // 名单来自本地规则、用户裁决或哈希确认;关键系统进程始终排除。
    BLW_PROTECTED_PATH FileExecBlock[BLW_MAX_PROTECTED];
    EX_PUSH_LOCK    FileExecBlockLock;
    volatile LONG   FileExecBlockCount;

    BLW_PROTECTED_PATH CmdHardBlock[BLW_MAX_PROTECTED];
    EX_PUSH_LOCK    CmdHardLock;
    volatile LONG   CmdHardCount;

    volatile LONG   FileTelemetryEnabled;

    volatile LONG   BootGuardEnabled;

    DECLSPEC_CACHEALIGN volatile LONG   WriteSampleSlots[BLW_WRITE_SLOTS];
    DECLSPEC_CACHEALIGN volatile LONG64 WriteSeenFile[BLW_WRITE_SLOTS];

    DECLSPEC_CACHEALIGN LARGE_INTEGER RegCookie;
    BOOLEAN         RegCallbackRegistered;
    BLW_PROTECTED_PATH ProtectedRegKeys[BLW_MAX_PROTECTED];
    EX_PUSH_LOCK    RegLock;
    volatile LONG   ProtectedRegCount;

    // 注册表「内核硬拦截」名单:命中即在内核直接拒绝写入(STATUS_ACCESS_DENIED),不经过用户态。
    // 只用于极少数绝不允许修改的精确键值(如 Winlogon\Shell、IFEO\<exe>\Debugger),名单必须精确,不能放宽到常被写的热键。
    BLW_PROTECTED_PATH RegHardBlock[BLW_MAX_PROTECTED];
    EX_PUSH_LOCK    RegHardLock;
    volatile LONG   RegHardCount;

    PVOID           ObRegHandle;
    BOOLEAN         ObCallbackRegistered;
    volatile LONG   ProtectedPids[BLW_MAX_PROTECTED]; // 受保护进程 PID(0 表示空槽)
    volatile LONG64 ProtectedPidMask;

    KSPIN_LOCK      PidSetLock;

    volatile LONG   MemProtPids[BLW_MAX_PROTECTED];
    volatile LONG64 MemProtPidMask;

    volatile LONG   CredProtPids[BLW_MAX_PROTECTED];
    volatile LONG64 CredProtPidMask;

    volatile LONG   BannedPids[BLW_MAX_PROTECTED];
    volatile LONG   BannedPidCount;
    volatile LONG64 BannedPidMask;
    KSPIN_LOCK      BannedLock;      // 仅写侧互斥(加入 / 摘除 / 清空);读侧全程无锁。

    volatile LONG64 WfpClassifyCalls;
    volatile LONG64 WfpRightsCleared;
    volatile LONG64 WfpBannedBlocks;
    volatile LONG64 WfpIpBlocks;

    volatile LONG   WfpBringUpAttempts;
    volatile LONG   WfpLastStage;
    volatile LONG   WfpLastStatus;
    volatile LONG   WfpLastLayer;

    HANDLE          WfpEngine;
    UINT32          WfpCalloutIds[BLW_WFP_LAYER_COUNT];
    UINT64          WfpFilterIds[BLW_WFP_LAYER_COUNT];
    BOOLEAN         WfpRegistered;
    PDEVICE_OBJECT  WfpDeviceObject;
    HANDLE          WfpBfeSubscription;
    ERESOURCE       WfpLock;
    BOOLEAN         WfpLockReady;
    BOOLEAN         WfpUnloading;
    BLW_BLOCK_IP    BlockList[BLW_MAX_PROTECTED];
    KSPIN_LOCK      NetLock;         // 保护 BlockList(WFP classify 可能在 DISPATCH_LEVEL,
                                     // 必须用自旋锁而非 FAST_MUTEX,否则会触发 IRQL_NOT_LESS_OR_EQUAL 蓝屏)
    volatile LONG   BlockIpCount;    // 当前 InUse 项数(在 NetLock 下与 BlockList 一致地读写,
    volatile LONG64 BlockIpMask;

    DECLSPEC_CACHEALIGN PBLW_EVENT_MESSAGE EventRing;
    volatile LONG   RingHead;         // 生产者写入下标(与容量掩码相与)
    volatile LONG   RingTail;         // 消费者读取下标(与容量掩码相与)
    KSPIN_LOCK      RingLock;         // 保护环形缓冲下标(入队可能在 DISPATCH_LEVEL)
    volatile LONG   SenderIdle;
    volatile LONG   SenderStop;
    volatile LONG64 NextEventId;
    volatile LONG64 DroppedEvents;
    volatile LONG64 EventsDelivered;
    volatile LONG64 EventsDroppedNoClient;
    volatile LONG64 EventsDroppedSendFailed;
    volatile LONG64 EventSendWaits;
    KEVENT          RingEvent;
    PETHREAD        SenderThread;

    volatile LONG   PolicyDirtyMask;
    KEVENT          PolicyEvent;
    PETHREAD        PolicyThread;
    volatile LONG   PolicyStop;

    volatile LONG   PolicyDeadDropMask;

    WCHAR           RegistryPathBuffer[300];
    UNICODE_STRING  RegistryPath;

    WCHAR           ServiceImageBuffer[BLW_MAX_PATH];
    volatile LONG   ServiceImageChars;   // 0 = 尚未记录(此时按 TOFU 接受第一个合法客户端)

    UCHAR           KnownBadHashes[BLW_MAX_HASHES][32];
    volatile LONG   KnownBadCount;
    EX_PUSH_LOCK    KnownBadLock;

    // 热路径上的大块临时缓冲一律从这里取,不放内核栈(I/O 路径嵌套很深,栈只有 24KB)。
    // 回调全部摘除、过滤器注销之后才能删除(BlwFreePools)。
    LOOKASIDE_LIST_EX MatchCtxPool;      // BLW_MATCH_CTX
    LOOKASIDE_LIST_EX RegScratchPool;    // BLW_REG_SCRATCH(注册表回调)
    LOOKASIDE_LIST_EX EventPathPool;     // 入队前在自旋锁外拷路径用的非分页缓冲
    BOOLEAN         PoolsReady;

    volatile LONG   HashRing[BLW_HASH_QUEUE_CAP];
    volatile LONG   HashRingHead;
    volatile LONG   HashRingTail;
    KSPIN_LOCK      HashRingLock;
    KEVENT          HashRingEvent;
    PETHREAD        HashWorkerThread;
    volatile LONG   HashWorkerStop;
} BLW_GLOBALS, *PBLW_GLOBALS;

#define BLW_EVENT_QUEUE_CAP  1024
#define BLW_EVENT_QUEUE_MASK (BLW_EVENT_QUEUE_CAP - 1)
C_ASSERT((BLW_EVENT_QUEUE_CAP & BLW_EVENT_QUEUE_MASK) == 0);

// 用户态暂时没有挂起读取时发送线程的单次等待上限。也是断开回调等待在途发送的最长时间。
#define BLW_EVENT_SEND_TIMEOUT_MS 100

#define BLW_WRITE_SAMPLE_RATE 32

extern BLW_GLOBALS g_Blw;

// PASSIVE_LEVEL。已解析过则立即返回。
void     BlwResolveSystemVolume(void);

NTSTATUS BlwRegisterProcessCallback(void);
void     BlwUnregisterProcessCallback(void);

BOOLEAN  BlwImageIsTrustedSystemPath(_In_ PCWSTR Path, _In_ USHORT Chars);
BOOLEAN  BlwImageIsLolBin(_In_ PCWSTR Path, _In_ USHORT Chars);
// 系统卷 System32 / SysWOW64 下的程序或 \Windows\explorer.exe,且不是 LOLBin。比上面的「可信系统路径」严:
// 不含 Program Files —— 拿到管理员权限的恶意程序能往那里放东西。
BOOLEAN  BlwImageIsOsComponent(_In_ PCWSTR Path, _In_ USHORT Chars);

// 本产品界面(与已登记服务映像同目录的 bulwark_ui.exe)。
BOOLEAN  BlwProcessIsProductUi(_In_ PEPROCESS Process);
// 当前进程能否启动 / 触碰本产品界面:本产品进程或系统组件。ActorPid 须是当前进程的 PID。
BOOLEAN  BlwActorMayTouchUi(_In_ ULONG ActorPid);
// 路径是否就在已登记服务映像所在的目录里(本产品安装目录,不含子目录)。
BOOLEAN  BlwPathInProductDir(_In_reads_(Chars) PCWSTR Path, _In_ USHORT Chars);

// 每个主体在 BLW_REPORT_WINDOW_S 秒内只报一次,表由调用方提供(BLW_REPORT_SLOTS 格)。
#define BLW_REPORT_SLOTS 64
#define BLW_REPORT_WINDOW_S 60
BOOLEAN  BlwReportOncePerWindow(_Inout_updates_(BLW_REPORT_SLOTS) volatile LONG64* Table,
                                _In_ ULONG ActorPid);
NTSTATUS BlwKillProcessById(_In_ ULONG Pid);

void     BlwClearCmdHardBlock(void);
void     BlwAddCmdHardBlock(_In_ PCWSTR Pattern, _In_ USHORT Length);
BOOLEAN  BlwDelCmdHardBlock(_In_ PCWSTR Pattern, _In_ USHORT Length);
// 判定命令行是否命中名单。直接比对完整的原始 UNICODE_STRING,不截断、不预先归一化:
// 命令行最长 32767 字符,先截断再匹配会被前置填充绕过。仅 PASSIVE_LEVEL(进程创建回调)调用。
BOOLEAN  BlwCmdLineIsBlocked(_In_opt_ PCUNICODE_STRING CommandLine);

NTSTATUS BlwRegisterImageCallback(void);
void     BlwUnregisterImageCallback(void);

NTSTATUS BlwRegisterThreadCallback(void);
void     BlwUnregisterThreadCallback(void);
// 进程创建回调登记「新进程 + 创建者」,线程回调据此认出新进程的第一个线程(由创建者建立,不是注入)。
void     BlwNoteProcessCreated(_In_ ULONG Pid, _In_ ULONG CreatorPid);

// 内存池:DriverEntry 最早初始化,FilterUnload 最后删除。取不到时调用方按「放行」降级。
void           BlwInitPools(void);
void           BlwFreePools(void);
PBLW_MATCH_CTX BlwAllocMatchCtx(void);
void           BlwFreeMatchCtx(_In_opt_ PBLW_MATCH_CTX Ctx);

FLT_PREOP_CALLBACK_STATUS BlwPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS BlwPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

// 预创建取不到文件名(按文件 ID 打开)时,把名单判定挪到这里:此时名字已可查询,命中就撤销这次打开。
FLT_POSTOP_CALLBACK_STATUS BlwPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

// IRP_MJ_WRITE 预操作:就地加密检测(采样遥测,绝不拦截)+ 引导区扇区写硬拦。
FLT_PREOP_CALLBACK_STATUS BlwPreAcquireSection(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS BlwPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

#define BLW_BOOT_GUARD_BYTES  (512ULL * 64ULL)

BOOLEAN BlwCreateIsRawVolumeOpen(_In_ PFLT_CALLBACK_DATA Data);

FLT_PREOP_CALLBACK_STATUS BlwBootGuardPreCreate(_Inout_ PFLT_CALLBACK_DATA Data);

void     BlwClearProtectedPaths(void);
void     BlwAddProtectedPath(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwPathIsProtected(_In_ PBLW_MATCH_CTX Ctx);
void     BlwClearFileHardBlock(void);
void     BlwAddFileHardBlock(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwFileIsHardBlocked(_In_ PBLW_MATCH_CTX Ctx);
void     BlwClearSelfGuard(void);
void     BlwAddSelfGuard(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwFileIsSelfGuarded(_In_ PBLW_MATCH_CTX Ctx);

void     BlwClearGuardDirs(void);
void     BlwAddGuardDir(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwDelGuardDir(_In_ PCWSTR Path, _In_ USHORT Length);
void     BlwClearGuardWriters(void);
void     BlwAddGuardWriter(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwDelGuardWriter(_In_ PCWSTR Path, _In_ USHORT Length);

BOOLEAN  BlwGuardDirDenies(_In_ PBLW_MATCH_CTX Ctx, _In_ ULONG ActorPid,
                           _In_opt_ PCUNICODE_STRING ReportName, _In_ ULONG OriginalOp);

// 窃密防护名单管理(ReadGuard 条目 / 全局读者)。增删改都会自增 ReadGuardGen 使缓存失效。
void     BlwClearReadGuard(void);
void     BlwAddReadGuard(_In_ PCWSTR Entry, _In_ USHORT Length);
BOOLEAN  BlwDelReadGuard(_In_ PCWSTR Entry, _In_ USHORT Length);
void     BlwClearReadGuardReaders(void);
void     BlwAddReadGuardReader(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwDelReadGuardReader(_In_ PCWSTR Path, _In_ USHORT Length);
// 进程退出时清掉它在 PID 掩码缓存里的槽,防止 PID 复用后沿用旧主体的判定。
void     BlwReadGuardOnProcessExit(_In_ ULONG Pid);
// 预创建快筛:原始绝对名(无 RelatedFileObject、无 '~')是否可能命中某条目的数据片段。
BOOLEAN  BlwReadGuardRawNameMightHit(_In_ PCUNICODE_STRING RawName);
// Ctx 为目标规范化大写路径。命中「敏感数据被非指定程序打开」即上报并返回 TRUE。
BOOLEAN  BlwReadGuardDenies(_In_ PBLW_MATCH_CTX Ctx, _In_ ULONG ActorPid,
                            _In_opt_ PCUNICODE_STRING ReportName);
// 某 PID 对各 ReadGuard 条目的可读位掩码(带缓存),~0 表示对全部放行。仅 PASSIVE_LEVEL 精算。
LONG64   BlwReadGuardMaskForPid(_In_ ULONG ActorPid);
// 上报一条「敏感数据被拦」事件(同一主体 60 秒去重)。
void     BlwReportSensitiveRead(_In_ ULONG ActorPid, _In_opt_ PCUNICODE_STRING Target);
// 改名整棵目录以把敏感子树移出数据片段命中范围的,按受限主体拒绝(目录子树重叠判定)。
BOOLEAN  BlwReadGuardDirRenameDenies(_In_ PBLW_MATCH_CTX Ctx, _In_ ULONG ActorPid,
                                     _In_ PFLT_INSTANCE Instance, _In_ PCUNICODE_STRING DirName);
void     BlwClearFileNoLoad(void);
BOOLEAN  BlwAddFileNoLoad(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwFileIsNoLoad(_In_ PBLW_MATCH_CTX Ctx);
void     BlwClearFileExecBlock(void);
BOOLEAN  BlwAddFileExecBlock(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwFileIsExecBlocked(_In_ PBLW_MATCH_CTX Ctx);

BOOLEAN  BlwRemoveFromGuardedList(_In_ BLW_PROTECTED_PATH* List, _In_ PEX_PUSH_LOCK Lock,
                                  _Inout_ volatile LONG* Count,
                                  _In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwDelProtectedPath(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwDelFileHardBlock(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwDelFileNoLoad(_In_ PCWSTR Path, _In_ USHORT Length);
BOOLEAN  BlwDelFileExecBlock(_In_ PCWSTR Path, _In_ USHORT Length);

NTSTATUS BlwRegisterRegistryCallback(_In_ PDRIVER_OBJECT DriverObject);
void     BlwUnregisterRegistryCallback(void);
void     BlwClearProtectedRegKeys(void);
void     BlwAddProtectedRegKey(_In_ PCWSTR Key, _In_ USHORT Length);
void     BlwClearRegHardBlock(void);
BOOLEAN  BlwAddRegHardBlock(_In_ PCWSTR Key, _In_ USHORT Length);
BOOLEAN  BlwDelRegHardBlock(_In_ PCWSTR Key, _In_ USHORT Length);

NTSTATUS BlwRegisterObCallbacks(void);
void     BlwUnregisterObCallbacks(void);
void     BlwClearProtectedPids(void);
void     BlwAddProtectedPid(_In_ ULONG Pid);
BOOLEAN  BlwPidIsProtected(_In_ ULONG Pid);
void     BlwClearMemProtPids(void);
void     BlwAddMemProtPid(_In_ ULONG Pid);
BOOLEAN  BlwPidIsMemProtected(_In_ ULONG Pid);
void     BlwClearCredProtPids(void);
void     BlwAddCredProtPid(_In_ ULONG Pid);
BOOLEAN  BlwPidIsCredProtected(_In_ ULONG Pid);

void     BlwRemoveTrackedPid(_In_ ULONG Pid);
// 已封禁主体(情报确认恶意)PID 管理:命中即各回调全维拒绝其行为。护栏:绝不封 PID<=4 /
// 本软件受保护进程 / 凭据保护进程。进程退出时由 BlwRemoveBannedPid 摘除以防 PID 复用误伤。
void     BlwClearBannedPids(void);
BOOLEAN  BlwAddBannedPid(_In_ ULONG Pid);
void     BlwRemoveBannedPid(_In_ ULONG Pid);
BOOLEAN  BlwPidIsBanned(_In_ ULONG Pid);

NTSTATUS BlwWfpStart(_In_ PDEVICE_OBJECT DeviceObject);
NTSTATUS BlwWfpRetryBringUp(void);
// 返回值必须检查:失败(典型 STATUS_DEVICE_BUSY)表示 WFP 仍持有本驱动的 classifyFn,
// 此时绝不能让镜像卸载,否则下一条外发连接就会跳进已释放内存。见 BlwFilterUnload。
_Must_inspect_result_
NTSTATUS BlwUnregisterWfp(void);
// 是否还有任何层的内核 callout 处于已注册状态。callout 依附于网络设备对象,
// 残留一个就绝不能删那个设备对象(否则 WFP 会引用一个已释放的对象 -> 蓝屏)。
BOOLEAN  BlwWfpHasCallouts(void);
void     BlwClearBlockList(void);
void     BlwAddBlockIp(_In_ ULONG IpV4, _In_ USHORT Port);
BOOLEAN  BlwAddBlockIp6(_In_reads_(32) PCWSTR Hex, _In_ USHORT Port);

NTSTATUS BlwInitCommunication(_In_ PDRIVER_OBJECT DriverObject);
void     BlwTearDownCommunication(void);

void     BlwSaveRegistryPath(_In_opt_ PUNICODE_STRING RegistryPath);
void     BlwLoadPolicyFromRegistry(void);
#define BLW_POLICY_DIRTY_PATHS      0x0001
#define BLW_POLICY_DIRTY_FILEHARD   0x0002
#define BLW_POLICY_DIRTY_NOLOAD     0x0004
#define BLW_POLICY_DIRTY_EXECBLOCK  0x0008
#define BLW_POLICY_DIRTY_REGKEYS    0x0010
#define BLW_POLICY_DIRTY_REGHARD    0x0020
#define BLW_POLICY_DIRTY_CMDHARD    0x0040
#define BLW_POLICY_DIRTY_GUARDDIR   0x0080
#define BLW_POLICY_DIRTY_READGUARD        0x0200  // ReadGuard(窃密防护条目)
#define BLW_POLICY_DIRTY_READGUARD_READER 0x0400  // ReadGuardReaders(全局读者)
#define BLW_POLICY_DIRTY_GUARDWRITER 0x0100  // GuardWriters(可信写入者:必须和目录一起跨重启,

NTSTATUS BlwStartPolicyPersist(void);
void     BlwStopPolicyPersist(void);
void     BlwMarkPolicyDirty(_In_ LONG DirtyBits);        // 标脏(可在 PASSIVE_LEVEL 调用)

void     BlwMarkDeadEntryDrop(_In_ LONG DirtyBit);
void     BlwPersistDeadEntryDrops(void);

void     BlwSetServiceImagePath(_In_ PCWSTR Path, _In_ USHORT Length);
void     BlwPersistServiceImagePath(void);

NTSTATUS BlwCleanupReadFile(_In_ PCWSTR Path, _In_ ULONG64 Offset,
                            _Out_writes_bytes_(BufLen) PVOID Buffer, _In_ ULONG BufLen,
                            _Out_ PULONG BytesRead);
NTSTATUS BlwCleanupForceDelete(_In_ PCWSTR Path);

// 单次 BLW_CMD_QUARANTINE_READ 的读取上限,不让用户态左右内核分页池的分配大小。
// 用户态按偏移分块循环读取,上限只影响循环次数。
#define BLW_CLEANUP_READ_MAX  (1024UL * 1024UL)

NTSTATUS BlwStartHashWorker(void);
void     BlwStopHashWorker(void);
void     BlwEnqueueHashScan(_In_ ULONG Pid);
void     BlwClearKnownBad(void);
void     BlwAddKnownBadHex(_In_ PCWSTR Hex, _In_ USHORT Length);

NTSTATUS BlwStartEventQueue(void);
void     BlwStopEventQueue(void);

void BlwReportEvent(
    _In_ ULONG Type,
    _In_ ULONG ActorPid,
    _In_ ULONG ParentPid,
    _In_opt_ PCUNICODE_STRING TargetPath,
    _In_opt_ PCUNICODE_STRING ImagePath,
    _In_ ULONG RemoteIpV4,
    _In_ USHORT RemotePort);
