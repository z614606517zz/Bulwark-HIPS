#pragma once

// 驱动产生的事件类型。用户态在 DriverEventSource.cpp 里逐项映射到 bulwark::EventType
// (cpp/shared/include/bulwark/models/Enums.h),两边数值不要求一致。
typedef enum _BLW_EVENT_TYPE {
    BlwEventProcessCreate = 0,
    BlwEventProcessTerminate = 1,
    BlwEventFileDelete = 2,
    BlwEventFileRename = 3,
    BlwEventRegistrySetValue = 4,
    BlwEventRegistryDeleteValue = 5,
    BlwEventRegistryDeleteKey = 6,
    BlwEventSelfProtect = 7,
    BlwEventNetworkConnect = 8,
    BlwEventImageLoad = 9,
    BlwEventRemoteThread = 10,
    BlwEventMemoryProtect = 11,   // 反注入:已剥离对高价值进程的写内存/远程线程权限
    BlwEventImageBlocked = 12,    // 已阻断「禁止加载名单」中的模块被加载(白加黑 DLL 侧载)
    BlwEventFileModify = 13,
    BlwEventCommandBlocked = 14,
    BlwEventRegistryHiveDump = 15,
    BlwEventBootSectorBlocked = 16,
    BlwEventTokenAttack = 17,
    BlwEventGuardDirBlocked = 18,
    // 19 与 20 已退役,不得复用:历史审计记录里可能仍存着这两个数值。

    // 注册表硬拦必须与普通观测使用不同事件号，服务端才能准确决定是否跳过补偿处置。
    BlwEventRegistrySetValueBlocked = 21,
    BlwEventRegistryDeleteValueBlocked = 22,
    BlwEventRegistryDeleteKeyBlocked = 23,
    // 整棵恢复 / 替换注册表键(RegRestoreKey / RegReplaceKey):一次改掉整个子树,不经逐值回调。
    BlwEventRegistryRestore = 24,
    BlwEventRegistryRestoreBlocked = 25,
    // 已剥离对 LSASS 的读 / 写内存权限(凭据转储尝试)。同一主体 60 秒内只报一次。
    BlwEventCredDumpBlocked = 26,
    // 防护生效(可信服务在线)时有人要卸载本驱动,已拒绝。ActorPid 为发起卸载的进程。
    BlwEventDriverUnloadBlocked = 27,
    // 非系统组件要启动本产品界面,已拒绝创建。ActorPid 为创建者,ImagePath 为界面映像。
    BlwEventUiLaunchBlocked = 28,
    // 窃密防护:非指定程序打开浏览器 / 通讯 / 钱包等敏感数据,已拒绝。ImagePath 为主体映像,
    // TargetPath 为被打开的文件。同一主体 60 秒内只报一次。
    BlwEventSensitiveReadBlocked = 29,
    BlwEventNetworkConnect6 = 30,
    BlwEventThreadContextAccess = 31,
    BlwEventMappedWrite = 32,
} BLW_EVENT_TYPE;

// 进程创建事件的 RemotePort 位:新进程映像文件在创建那一刻的异常。
#define BLW_IMAGE_DELETE_PENDING 0x0001  // 映像文件已处于删除挂起(进程幽灵化)
#define BLW_IMAGE_TRANSACTED     0x0002  // 映像来自未提交的 NTFS 事务(进程替身 Doppelgänging)
#define BLW_IMAGE_WRITABLE       0x0004  // 映像文件对象带写权限(Herpaderping:映射后改写文件)

typedef enum _BLW_VERDICT {
    BlwVerdictAllow = 0,
    BlwVerdictBlock = 1,
} BLW_VERDICT;

#define BLW_MAX_PATH 520   // 路径最大字符数(宽字符)

typedef struct _BLW_EVENT_MESSAGE {
    ULONG64       EventId;          // 事件序号(驱动内自增)
    ULONG         Type;
    ULONG         ActorPid;         // 发起进程 PID
    ULONG         ParentPid;        // 父进程 PID(文件/注册表事件为 0)
    USHORT        ImagePathLength;  // ImagePath 实际字符数(文件事件可为 0)
    WCHAR         ImagePath[BLW_MAX_PATH];  // 进程映像路径(进程事件)
    USHORT        TargetPathLength; // TargetPath 实际字符数
    WCHAR         TargetPath[BLW_MAX_PATH]; // 操作目标(文件事件为被操作文件路径)
    ULONG         RemoteIpV4;       // 网络事件:远端 IPv4(主机字节序),0 表示非网络事件;
                                    // 注册表事件:REG_DWORD 值;进程创建事件:真正调用创建的进程 PID
    USHORT        RemotePort;       // 网络事件:远端端口;注册表事件:值类型;进程创建事件:BLW_IMAGE_* 位
} BLW_EVENT_MESSAGE, *PBLW_EVENT_MESSAGE;

typedef struct _BLW_VERDICT_REPLY {
    ULONG64       EventId;          // 对应事件序号
    ULONG         Verdict;
} BLW_VERDICT_REPLY, *PBLW_VERDICT_REPLY;

#define BLW_CMD_CLEAR_PATHS    1   // 清空受保护文件路径列表
#define BLW_CMD_ADD_PATH       2   // 追加一条受保护文件路径(子串,大小写不敏感)
#define BLW_CMD_CLEAR_REGKEYS  3   // 清空受保护注册表键列表
#define BLW_CMD_ADD_REGKEY     4   // 追加一条受保护注册表键(子串,大小写不敏感)
#define BLW_CMD_CLEAR_PIDS     5   // 清空受保护进程 PID 列表(自我保护)
#define BLW_CMD_ADD_PID        6   // 追加一个受保护进程 PID(自我保护)
#define BLW_CMD_CLEAR_BLOCKIP  7   // 清空网络黑名单
#define BLW_CMD_ADD_BLOCKIP    8   // 追加一条网络黑名单(IPv4 + 端口,端口0表示任意)
#define BLW_CMD_HANDSHAKE      9   // 协议握手:校验内核/用户态结构体布局一致
#define BLW_CMD_CLEAR_REGHARD  10  // 清空「内核硬拦截」注册表名单
#define BLW_CMD_ADD_REGHARD    11  // 追加一条「内核硬拦截」注册表项(精确子串,key 或 key\value)
                                   //   命中即内核本地拒绝写入。条目必须精确,\Services 这类宽热键会拦死系统。
#define BLW_CMD_CLEAR_FILEHARD 12  // 清空「内核硬拦截」文件名单
#define BLW_CMD_ADD_FILEHARD   13
#define BLW_CMD_CLEAR_MEMPROT  14  // 清空「内存防护(反注入)」目标 PID 列表
#define BLW_CMD_ADD_MEMPROT    15
#define BLW_CMD_CLEAR_NOLOAD   16  // 清空「禁止加载」模块名单
#define BLW_CMD_ADD_NOLOAD     17
#define BLW_CMD_SET_FILETELEMETRY 18
#define BLW_CMD_QUARANTINE_READ 19
#define BLW_CMD_FORCE_DELETE   20
#define BLW_CMD_KILL_PID       21
#define BLW_CMD_CLEAR_EXECBLOCK 22 // 清空「禁止执行」名单(执行前拦截)。
#define BLW_CMD_ADD_EXECBLOCK  23
#define BLW_CMD_CLEAR_CREDPROT 24  // 清空「凭据保护(反转储)」目标 PID 列表。
#define BLW_CMD_ADD_CREDPROT   25

#define BLW_CMD_CLEAR_BANNED   26  // 清空「已封禁主体」PID 集。
#define BLW_CMD_ADD_BANNED     27

#define BLW_CMD_CLEAR_SELFGUARD 28 // 清空「自保护足迹」路径子串集。
#define BLW_CMD_ADD_SELFGUARD  29

#define BLW_CMD_CLEAR_CMDBLOCK 30  // 清空「命令行硬拦」名单。
#define BLW_CMD_ADD_CMDBLOCK   31

#define BLW_CMD_CLEAR_KNOWNBAD 32
#define BLW_CMD_ADD_KNOWNBAD   33

#define BLW_CMD_DEL_PATH       34  // 删除一条受保护文件路径
#define BLW_CMD_DEL_FILEHARD   35  // 删除一条文件硬拦项
#define BLW_CMD_DEL_NOLOAD     36  // 删除一条「禁止加载」模块项
#define BLW_CMD_DEL_EXECBLOCK  37  // 删除一条「禁止执行」映像项
#define BLW_CMD_DEL_REGHARD    38  // 删除一条注册表硬拦项
#define BLW_CMD_DEL_CMDBLOCK   39  // 删除一条命令行硬拦模式

#define BLW_CMD_SET_BOOTGUARD  40

#define BLW_CMD_CLEAR_GUARDDIR    41  // 清空「受保护目录」名单(运行期;不擦磁盘基线)
#define BLW_CMD_ADD_GUARDDIR      42  // 追加受保护对象(去盘符；尾 '\'=目录，否则=完整文件)
#define BLW_CMD_DEL_GUARDDIR      43  // 精确删除一条受保护目录(整串比较;删掉即标脏写回)
#define BLW_CMD_CLEAR_GUARDWRITER 44  // 清空「可信写入者」名单
#define BLW_CMD_ADD_GUARDWRITER   45
#define BLW_CMD_DEL_GUARDWRITER   46  // 精确删除一条可信写入者(整串比较;删掉即标脏写回)

// 命令号 47..51 与 53 已退役(原收容笼),不得复用。

#define BLW_CMD_QUERY_WFP_STATS 52

// 命令号 54..57 已退役,不得复用。

// 只读查询,旧驱动对它回 STATUS_INVALID_PARAMETER,服务据此判定「不支持」,无需升协议版本。
#define BLW_CMD_QUERY_EVENT_STATS 58

// 窃密防护。条目格式 "数据片段|读者;读者"(去盘符):数据片段在目标路径任意位置出现即受保护;
// 读者片段从系统卷 \Program Files\、\Program Files (x86)\ 或某用户 AppData\Local\、AppData\Roaming\
// 之后开始比,以 '\' 结尾表示该目录下的程序,否则必须是完整的程序路径。
// 全局读者是去盘符的完整程序路径或以 '\' 结尾的目录,对所有条目放行。
#define BLW_CMD_CLEAR_READGUARD        59
#define BLW_CMD_ADD_READGUARD          60
#define BLW_CMD_DEL_READGUARD          61
#define BLW_CMD_CLEAR_READGUARD_READER 62
#define BLW_CMD_ADD_READGUARD_READER   63
#define BLW_CMD_DEL_READGUARD_READER   64
#define BLW_CMD_ADD_BLOCKIP6           65 // Path contains 32 hexadecimal digits, BlockPort is host order

#define BLW_READGUARD_SEP         L'|'
#define BLW_READGUARD_READER_SEP  L';'

#define BLW_CMD_TOKEN_SEP  L'+'

// 协议版本。握手结构体、事件号或命令号有增改时必须升版本:新旧混跑会在握手时被两侧的长度或版本校验拦下,
// 降级为不拦截,避免旧服务把不认识的事件号当成别的事件处理。
#define BLW_PROTOCOL_VERSION   14

// 内核能力位图(BLW_HANDSHAKE_REPLY.Capabilities):驱动在握手时直接声明编译进了哪些能力。
// 不能用「下发命令是否成功」反推能力:驱动会正当拒绝非法参数,各命令对非法参数的处理也不统一。
#define BLW_CAP_CMD_HARDBLOCK  0x00000001UL  // 命令行硬拦
#define BLW_CAP_BANNED         0x00000002UL  // 已封禁主体全维拦截
#define BLW_CAP_SELFGUARD      0x00000004UL  // 自保护足迹
#define BLW_CAP_EXECBLOCK      0x00000008UL  // 执行前拦截(恶意映像禁止启动)
#define BLW_CAP_CRED_PROTECT   0x00000010UL  // 凭据反转储(lsass 防读)
#define BLW_CAP_MEM_PROTECT    0x00000020UL  // 内存防护(反注入)
#define BLW_CAP_FILE_TELEMETRY 0x00000040UL  // 文件行为遥测(勒索时序聚合)
#define BLW_CAP_GUARD_DIR      0x00000080UL  // 受保护目录(写入前拦截)
#define BLW_CAP_BOOTGUARD_FIXED_ONLY 0x00000100UL  // 引导区防护只管固定磁盘,可移动介质放行
#define BLW_CAP_READ_GUARD     0x00000200UL  // 窃密防护(敏感数据只许指定程序打开)

// 本驱动实际实现的能力集合(编译期常量),新增能力时在此补一位。
// 语义是「已编译进驱动」,不保证运行时初始化成功;运行期失败(如 WFP 未就绪)另有日志与状态提示。
#define BLW_CAP_IPV6_ENDPOINTS 0x00000400UL
#define BLW_CAP_CURRENT  (BLW_CAP_IPV6_ENDPOINTS | BLW_CAP_CMD_HARDBLOCK | BLW_CAP_BANNED |      \
                          BLW_CAP_SELFGUARD     | BLW_CAP_EXECBLOCK |   \
                          BLW_CAP_CRED_PROTECT  | BLW_CAP_MEM_PROTECT | \
                          BLW_CAP_FILE_TELEMETRY| BLW_CAP_GUARD_DIR |   \
                          BLW_CAP_BOOTGUARD_FIXED_ONLY | BLW_CAP_READ_GUARD)

typedef struct _BLW_HANDSHAKE_REPLY {
    ULONG ProtocolVersion;       // = BLW_PROTOCOL_VERSION
    ULONG EventMessageSize;      // = sizeof(BLW_EVENT_MESSAGE)
    ULONG ConfigMessageSize;     // = sizeof(BLW_CONFIG_MESSAGE)
    ULONG VerdictReplySize;      // = sizeof(BLW_VERDICT_REPLY)
    ULONG Capabilities;          // = BLW_CAP_CURRENT(BLW_CAP_* 位或)
} BLW_HANDSHAKE_REPLY, *PBLW_HANDSHAKE_REPLY;

typedef struct _BLW_FILEOP_REPLY {
    LONG Status;                 // 0 = 成功;否则为失败的 NTSTATUS
} BLW_FILEOP_REPLY, *PBLW_FILEOP_REPLY;
#define BLW_WFP_STAGE_NONE          0  // 没有失败记录(从未尝试,或最近一次成功)
#define BLW_WFP_STAGE_NO_DEVICE     1  // 没有设备对象(注册 callout 的前提)
#define BLW_WFP_STAGE_CALLOUT_REG   2
#define BLW_WFP_STAGE_ENGINE_OPEN   3  // FwpmEngineOpen(BFE 未就绪时最常见)
#define BLW_WFP_STAGE_TXN_BEGIN     4
#define BLW_WFP_STAGE_SUBLAYER_ADD  5
#define BLW_WFP_STAGE_CALLOUT_ADD   6  // FwpmCalloutAdd(管理层 callout)
#define BLW_WFP_STAGE_FILTER_ADD    7
#define BLW_WFP_STAGE_TXN_COMMIT    8

typedef struct _BLW_WFP_STATS_REPLY {
    ULONG Registered;
    ULONG LayerCount;        // 已挂上的层数
    ULONG64 ClassifyCalls;   // classify 被调用总次数(0 = 回调从未进入,问题在注册侧)
    ULONG64 RightsCleared;
    ULONG64 ContainBlocks;   // 已废弃(原收容笼分支计数),恒为 0;保留以维持应答布局
    ULONG64 BannedBlocks;    // 封禁分支下发 FWP_ACTION_BLOCK 的次数
    ULONG64 IpBlocks;
    ULONG BringUpAttempts;   // 拉起被尝试过的次数(含 BFE 订阅回调触发的那些)
    ULONG LastStage;         // 最近一次失败的阶段:BLW_WFP_STAGE_*
    LONG  LastStatus;        // 最近一次失败的 NTSTATUS(0 = 无失败记录)
    ULONG BfeSubscribed;     // 1 = BFE 状态订阅已建立(失败时还有机会被自动补挂)
    // 失败的层(kBlwWfpLayers 下标),只对逐层循环的阶段有意义,否则为 0xFFFFFFFF。
    ULONG LastLayer;
} BLW_WFP_STATS_REPLY, *PBLW_WFP_STATS_REPLY;

// 驱动加载以来的累计值。Queued = Delivered + 各类丢弃 + 仍在队列中的条数。
typedef struct _BLW_EVENT_STATS_REPLY {
    ULONG64 Queued;
    ULONG64 Delivered;
    ULONG64 DroppedQueueFull;    // 队列满或分配失败,未能入队
    ULONG64 DroppedNoClient;     // 出队时服务已断开
    ULONG64 DroppedSendFailed;   // 发送出错(超时以外的失败)
    ULONG64 SendWaits;           // 服务暂无挂起读取、发送线程等待后重试的次数
} BLW_EVENT_STATS_REPLY, *PBLW_EVENT_STATS_REPLY;


typedef struct _BLW_CONFIG_MESSAGE {
    ULONG         Command;          // BLW_CMD_*
    ULONG         Pid;              // 受保护进程 PID(用于 ADD_PID)
    ULONG         BlockIpV4;        // 网络黑名单 IPv4(主机字节序,用于 ADD_BLOCKIP)
    USHORT        BlockPort;        // 网络黑名单端口(0=任意,用于 ADD_BLOCKIP)
    USHORT        PathLength;       // Path 实际字符数
    WCHAR         Path[BLW_MAX_PATH];
} BLW_CONFIG_MESSAGE, *PBLW_CONFIG_MESSAGE;

#define BLW_PORT_NAME L"\\BulwarkPort"
