#pragma once
#include <stdint.h>

#define BLW_AMSI_PIPE_NAME      L"\\\\.\\pipe\\Bulwark.Amsi"

#define BLW_AMSI_MAGIC          0x534D4142u
#define BLW_AMSI_VERSION        1u

#define BLW_AMSI_ENC_UNKNOWN    0u
#define BLW_AMSI_ENC_UTF16LE    1u
#define BLW_AMSI_ENC_UTF8       2u

// 单次送检的内容上限;超出部分不送检。
// 这条路径同步阻塞脚本宿主,不宜再调大。
#define BLW_AMSI_MAX_CONTENT    (256u * 1024u)

#define BLW_AMSI_MAX_NAME       2048u

#define BLW_AMSI_MAX_REASON     1024u

#define BLW_AMSI_VERDICT_ALLOW  0u
#define BLW_AMSI_VERDICT_BLOCK  1u

#pragma pack(push, 4)

typedef struct _BLW_AMSI_REQUEST {
    uint32_t magic;
    uint32_t version;
    uint32_t structSize;        // sizeof(BLW_AMSI_REQUEST),防结构漂移
    uint32_t hostPid;
    uint32_t encoding;
    uint32_t appNameBytes;      // 紧随头部的 UTF-16LE 字节数
    uint32_t contentNameBytes;  // 其后的 UTF-16LE 字节数
    uint32_t contentBytes;      // 其后的原始内容字节数(<= BLW_AMSI_MAX_CONTENT)
    uint64_t session;           // AMSI 会话号(0 = 不属于任何会话)
} BLW_AMSI_REQUEST;

typedef struct _BLW_AMSI_REPLY {
    uint32_t magic;
    uint32_t version;
    uint32_t structSize;        // sizeof(BLW_AMSI_REPLY)
    uint32_t verdict;
    uint32_t reasonBytes;       // 紧随头部的 UTF-16LE 字节数(可为 0)
    uint32_t reserved;          // 填 0(保持 8 字节对齐,留给后续扩展)
} BLW_AMSI_REPLY;

#pragma pack(pop)
