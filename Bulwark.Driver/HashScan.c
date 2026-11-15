#include "Driver.h"

typedef struct _BLW_SHA256_CTX {
    ULONG   state[8];
    ULONG64 bitlen;
    UCHAR   data[64];
    ULONG   datalen;
} BLW_SHA256_CTX;

#define BLW_ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define BLW_SHR(x,n)  ((x) >> (n))
#define BLW_CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define BLW_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BLW_EP0(x)  (BLW_ROTR(x,2)  ^ BLW_ROTR(x,13) ^ BLW_ROTR(x,22))
#define BLW_EP1(x)  (BLW_ROTR(x,6)  ^ BLW_ROTR(x,11) ^ BLW_ROTR(x,25))
#define BLW_SIG0(x) (BLW_ROTR(x,7)  ^ BLW_ROTR(x,18) ^ BLW_SHR(x,3))
#define BLW_SIG1(x) (BLW_ROTR(x,17) ^ BLW_ROTR(x,19) ^ BLW_SHR(x,10))

static const ULONG g_Sha256K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void
BlwSha256Init(_Out_ BLW_SHA256_CTX* c)
{
    c->datalen = 0;
    c->bitlen = 0;
    c->state[0] = 0x6a09e667; c->state[1] = 0xbb67ae85;
    c->state[2] = 0x3c6ef372; c->state[3] = 0xa54ff53a;
    c->state[4] = 0x510e527f; c->state[5] = 0x9b05688c;
    c->state[6] = 0x1f83d9ab; c->state[7] = 0x5be0cd19;
}

static void
BlwSha256Transform(_Inout_ BLW_SHA256_CTX* c, _In_reads_(64) const UCHAR* data)
{
    ULONG a, b, d, e, f, g, h, i, j, t1, t2, m[64];
    ULONG cc;

    for (i = 0, j = 0; i < 16; i++, j += 4) {
        m[i] = ((ULONG)data[j] << 24) | ((ULONG)data[j + 1] << 16) |
               ((ULONG)data[j + 2] << 8) | ((ULONG)data[j + 3]);
    }
    for (; i < 64; i++) {
        m[i] = BLW_SIG1(m[i - 2]) + m[i - 7] + BLW_SIG0(m[i - 15]) + m[i - 16];
    }

    a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3];
    e = c->state[4]; f = c->state[5]; g = c->state[6]; h = c->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + BLW_EP1(e) + BLW_CH(e, f, g) + g_Sha256K[i] + m[i];
        t2 = BLW_EP0(a) + BLW_MAJ(a, b, cc);
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }

    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

static void
BlwSha256Update(_Inout_ BLW_SHA256_CTX* c, _In_reads_(len) const UCHAR* data, _In_ ULONG len)
{
    ULONG offset = 0;

    if (c->datalen != 0) {
        ULONG need = 64 - c->datalen;
        if (len < need) {
            RtlCopyMemory(&c->data[c->datalen], data, len);
            c->datalen += len;
            return;
        }
        RtlCopyMemory(&c->data[c->datalen], data, need);
        BlwSha256Transform(c, c->data);
        c->bitlen += 512;
        c->datalen = 0;
        offset = need;
    }

    while (offset + 64 <= len) {
        BlwSha256Transform(c, &data[offset]);
        c->bitlen += 512;
        offset += 64;
    }

    if (offset < len) {
        c->datalen = len - offset;
        RtlCopyMemory(c->data, &data[offset], c->datalen);
    }
}

static void
BlwSha256Final(_Inout_ BLW_SHA256_CTX* c, _Out_writes_(32) UCHAR* hash)
{
    ULONG i = c->datalen;

    if (c->datalen < 56) {
        c->data[i++] = 0x80;
        while (i < 56) c->data[i++] = 0x00;
    } else {
        c->data[i++] = 0x80;
        while (i < 64) c->data[i++] = 0x00;
        BlwSha256Transform(c, c->data);
        RtlZeroMemory(c->data, 56);
    }

    c->bitlen += (ULONG64)c->datalen * 8;
    c->data[63] = (UCHAR)(c->bitlen);
    c->data[62] = (UCHAR)(c->bitlen >> 8);
    c->data[61] = (UCHAR)(c->bitlen >> 16);
    c->data[60] = (UCHAR)(c->bitlen >> 24);
    c->data[59] = (UCHAR)(c->bitlen >> 32);
    c->data[58] = (UCHAR)(c->bitlen >> 40);
    c->data[57] = (UCHAR)(c->bitlen >> 48);
    c->data[56] = (UCHAR)(c->bitlen >> 56);
    BlwSha256Transform(c, c->data);

    for (i = 0; i < 4; i++) {
        hash[i]      = (UCHAR)((c->state[0] >> (24 - i * 8)) & 0xff);
        hash[i + 4]  = (UCHAR)((c->state[1] >> (24 - i * 8)) & 0xff);
        hash[i + 8]  = (UCHAR)((c->state[2] >> (24 - i * 8)) & 0xff);
        hash[i + 12] = (UCHAR)((c->state[3] >> (24 - i * 8)) & 0xff);
        hash[i + 16] = (UCHAR)((c->state[4] >> (24 - i * 8)) & 0xff);
        hash[i + 20] = (UCHAR)((c->state[5] >> (24 - i * 8)) & 0xff);
        hash[i + 24] = (UCHAR)((c->state[6] >> (24 - i * 8)) & 0xff);
        hash[i + 28] = (UCHAR)((c->state[7] >> (24 - i * 8)) & 0xff);
    }
}

static UCHAR
BlwHexVal(_In_ WCHAR c)
{
    if (c >= L'0' && c <= L'9') return (UCHAR)(c - L'0');
    if (c >= L'a' && c <= L'f') return (UCHAR)(10 + c - L'a');
    if (c >= L'A' && c <= L'F') return (UCHAR)(10 + c - L'A');
    return 0xFF;
}

void
BlwClearKnownBad(void)
{
    BlwLockExclusive(&g_Blw.KnownBadLock);
    RtlZeroMemory(g_Blw.KnownBadHashes, sizeof(g_Blw.KnownBadHashes));
    InterlockedExchange(&g_Blw.KnownBadCount, 0);
    BlwUnlock(&g_Blw.KnownBadLock);
}

void
BlwAddKnownBadHex(_In_ PCWSTR Hex, _In_ USHORT Length)
{
    UCHAR digest[32];
    USHORT i;

    if (Hex == NULL || Length != 64) {
        return;
    }

    for (i = 0; i < 32; i++) {
        UCHAR hi = BlwHexVal(Hex[i * 2]);
        UCHAR lo = BlwHexVal(Hex[i * 2 + 1]);
        if (hi == 0xFF || lo == 0xFF) {
            return;
        }
        digest[i] = (UCHAR)((hi << 4) | lo);
    }

    BlwLockExclusive(&g_Blw.KnownBadLock);
    if (g_Blw.KnownBadCount < BLW_MAX_HASHES) {
        BOOLEAN dup = FALSE;
        LONG n = g_Blw.KnownBadCount, k;
        for (k = 0; k < n; k++) {
            if (RtlEqualMemory(g_Blw.KnownBadHashes[k], digest, 32)) {
                dup = TRUE;
                break;
            }
        }
        if (!dup) {
            RtlCopyMemory(g_Blw.KnownBadHashes[g_Blw.KnownBadCount], digest, 32);
            InterlockedIncrement(&g_Blw.KnownBadCount);
        }
    }
    BlwUnlock(&g_Blw.KnownBadLock);
}

static BOOLEAN
BlwIsKnownBad(_In_reads_(32) const UCHAR* digest)
{
    BOOLEAN hit = FALSE;
    LONG n, i;

    BlwLockShared(&g_Blw.KnownBadLock);
    n = g_Blw.KnownBadCount;
    for (i = 0; i < n; i++) {
        if (RtlEqualMemory(g_Blw.KnownBadHashes[i], digest, 32)) {
            hit = TRUE;
            break;
        }
    }
    BlwUnlock(&g_Blw.KnownBadLock);
    return hit;
}

#define BLW_HASH_CHUNK    (64 * 1024)
#define BLW_HASH_MAX_SIZE (128ULL * 1024 * 1024)   // 超过 128MB 不哈希(极少是恶意样本)

// 同一程序反复启动不必每次整文件重算。缓存的是摘要而不是「干净」结论,每次仍拿当前名单比对,
// 名单增删不需要让缓存失效。只有哈希 worker 一个线程访问,不加锁。
#define BLW_HASH_CACHE_SLOTS 256
C_ASSERT((BLW_HASH_CACHE_SLOTS & (BLW_HASH_CACHE_SLOTS - 1)) == 0);

typedef struct _BLW_HASH_CACHE_ENTRY {
    LONGLONG FileId;
    LONGLONG ChangeTime;
    LONGLONG Size;
    ULONG    PathHash;
    BOOLEAN  Valid;
    UCHAR    Digest[32];
} BLW_HASH_CACHE_ENTRY;

static BLW_HASH_CACHE_ENTRY g_HashCache[BLW_HASH_CACHE_SLOTS];

static ULONG
BlwPathHash(_In_ PCUNICODE_STRING Path)
{
    ULONG h = 2166136261u;
    USHORT i;
    const USHORT n = (USHORT)(Path->Length / sizeof(WCHAR));

    for (i = 0; i < n; i++) {
        h ^= BlwUpcaseChar(Path->Buffer[i]);
        h *= 16777619u;
    }
    return h;
}

// PASSIVE_LEVEL(worker 线程)。buf 由调用方提供,是 worker 复用的 BLW_HASH_CHUNK 读缓冲。
static NTSTATUS
BlwComputeFileSha256(
    _In_ PUNICODE_STRING NtPath,
    _Out_writes_(32) UCHAR* OutDigest,
    _In_reads_bytes_(BLW_HASH_CHUNK) PUCHAR buf)
{
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    NTSTATUS status;
    BLW_SHA256_CTX ctx;
    ULONG64 total = 0;
    FILE_STANDARD_INFORMATION stdInfo = { 0 };
    FILE_BASIC_INFORMATION basicInfo = { 0 };
    FILE_INTERNAL_INFORMATION idInfo = { 0 };
    BLW_HASH_CACHE_ENTRY* slot = NULL;
    ULONG pathHash = 0;

    RtlZeroMemory(OutDigest, 32);

    if (NtPath == NULL || NtPath->Buffer == NULL || NtPath->Length == 0 || buf == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    InitializeObjectAttributes(&oa, NtPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwCreateFile(&hFile, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL, 0);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (NT_SUCCESS(ZwQueryInformationFile(hFile, &iosb, &stdInfo, sizeof(stdInfo),
                                          FileStandardInformation))) {
        if ((ULONG64)stdInfo.EndOfFile.QuadPart > BLW_HASH_MAX_SIZE) {
            ZwClose(hFile);
            return STATUS_FILE_TOO_LARGE;
        }
        if (NT_SUCCESS(ZwQueryInformationFile(hFile, &iosb, &idInfo, sizeof(idInfo),
                                              FileInternalInformation)) &&
            NT_SUCCESS(ZwQueryInformationFile(hFile, &iosb, &basicInfo, sizeof(basicInfo),
                                              FileBasicInformation))) {
            pathHash = BlwPathHash(NtPath);
            slot = &g_HashCache[((ULONG)idInfo.IndexNumber.QuadPart ^ pathHash) &
                                (BLW_HASH_CACHE_SLOTS - 1)];
            if (slot->Valid && slot->FileId == idInfo.IndexNumber.QuadPart &&
                slot->ChangeTime == basicInfo.ChangeTime.QuadPart &&
                slot->Size == stdInfo.EndOfFile.QuadPart && slot->PathHash == pathHash) {
                RtlCopyMemory(OutDigest, slot->Digest, 32);
                ZwClose(hFile);
                return STATUS_SUCCESS;
            }
        }
    }

    BlwSha256Init(&ctx);
    for (;;) {
        RtlZeroMemory(&iosb, sizeof(iosb));
        status = ZwReadFile(hFile, NULL, NULL, NULL, &iosb,
            buf, BLW_HASH_CHUNK, NULL, NULL);
        if (!NT_SUCCESS(status) || iosb.Information == 0) {
            if (status == STATUS_END_OF_FILE) {
                status = STATUS_SUCCESS;
            }
            break;
        }
        BlwSha256Update(&ctx, buf, (ULONG)iosb.Information);
        total += iosb.Information;
        if (total > BLW_HASH_MAX_SIZE) {
            status = STATUS_FILE_TOO_LARGE;
            break;
        }
    }

    if (NT_SUCCESS(status)) {
        BlwSha256Final(&ctx, OutDigest);
        if (slot != NULL) {
            slot->FileId = idInfo.IndexNumber.QuadPart;
            slot->ChangeTime = basicInfo.ChangeTime.QuadPart;
            slot->Size = stdInfo.EndOfFile.QuadPart;
            slot->PathHash = pathHash;
            RtlCopyMemory(slot->Digest, OutDigest, 32);
            slot->Valid = TRUE;
        }
    }

    ZwClose(hFile);
    return status;
}

static void
BlwReportHashHit(_In_ ULONG pid, _In_ PUNICODE_STRING image)
{
    // 两个路径字段都填,兼容用户态取任一字段。
    BlwReportEvent(BlwEventImageBlocked, pid, 0, image, image, 0, 0);
}

static void
BlwProcessHashScan(_In_ ULONG pid, _In_ PUCHAR buf)
{
    PEPROCESS proc = NULL;
    PUNICODE_STRING imageName = NULL;
    NTSTATUS status;
    UCHAR digest[32];

    if (pid <= 4) {
        return;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
    if (!NT_SUCCESS(status) || proc == NULL) {
        return;
    }

    status = SeLocateProcessImageName(proc, &imageName);
    if (NT_SUCCESS(status) && imageName != NULL &&
        imageName->Buffer != NULL && imageName->Length > 0) {

        if (NT_SUCCESS(BlwComputeFileSha256(imageName, digest, buf))
            && BlwIsKnownBad(digest)) {
            KdPrint(("[Bulwark] HashScan: known-bad match, banning + terminating PID %u.\n", pid));
            BlwAddBannedPid(pid);
            BlwReportHashHit(pid, imageName);
            (void)BlwKillProcessById(pid);
        }
    }

    if (imageName != NULL) {
        ExFreePool(imageName);
    }
    ObDereferenceObject(proc);
}

static VOID
BlwHashWorkerThread(_In_ PVOID Context)
{
    PUCHAR buf;

    UNREFERENCED_PARAMETER(Context);

    buf = (PUCHAR)BlwAllocPool(PagedPool, BLW_HASH_CHUNK, BLW_TAG);
    if (buf == NULL) {
        KdPrint(("[Bulwark] Hash worker: read buffer alloc failed, scanning disabled.\n"));
        PsTerminateSystemThread(STATUS_SUCCESS);
        return;
    }

    for (;;) {
        KeWaitForSingleObject(&g_Blw.HashRingEvent, Executive, KernelMode, FALSE, NULL);

        for (;;) {
            LONG pid = 0;
            KIRQL oldIrql;
            BOOLEAN haveItem = FALSE;

            KeAcquireSpinLock(&g_Blw.HashRingLock, &oldIrql);
            if (g_Blw.HashRingTail != g_Blw.HashRingHead) {
                pid = g_Blw.HashRing[g_Blw.HashRingTail];
                g_Blw.HashRingTail = (g_Blw.HashRingTail + 1) & BLW_HASH_QUEUE_MASK;
                haveItem = TRUE;
            }
            KeReleaseSpinLock(&g_Blw.HashRingLock, oldIrql);

            if (!haveItem) {
                break;
            }
            BlwProcessHashScan((ULONG)pid, buf);
        }

        if (InterlockedCompareExchange(&g_Blw.HashWorkerStop, 0, 0) != 0) {
            break;
        }
    }

    ExFreePoolWithTag(buf, BLW_TAG);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

void
BlwEnqueueHashScan(_In_ ULONG Pid)
{
    KIRQL oldIrql;
    LONG nextHead;
    BOOLEAN queued = FALSE;

    if (g_Blw.HashWorkerThread == NULL) {
        return;
    }

    KeAcquireSpinLock(&g_Blw.HashRingLock, &oldIrql);
    nextHead = (g_Blw.HashRingHead + 1) & BLW_HASH_QUEUE_MASK;
    if (nextHead != g_Blw.HashRingTail) {
        g_Blw.HashRing[g_Blw.HashRingHead] = (LONG)Pid;
        g_Blw.HashRingHead = nextHead;
        queued = TRUE;
    }
    KeReleaseSpinLock(&g_Blw.HashRingLock, oldIrql);

    if (queued) {
        KeSetEvent(&g_Blw.HashRingEvent, IO_NO_INCREMENT, FALSE);
    }
    // 环满则丢弃:漏扫不致命(下次启动仍会被扫),不能阻塞进程创建。
}

NTSTATUS
BlwStartHashWorker(void)
{
    HANDLE threadHandle = NULL;
    NTSTATUS status;

    g_Blw.HashRingHead = 0;
    g_Blw.HashRingTail = 0;
    g_Blw.HashWorkerStop = 0;
    KeInitializeSpinLock(&g_Blw.HashRingLock);
    KeInitializeEvent(&g_Blw.HashRingEvent, SynchronizationEvent, FALSE);

    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS,
        NULL, NULL, NULL, BlwHashWorkerThread, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, *PsThreadType,
        KernelMode, (PVOID*)&g_Blw.HashWorkerThread, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] ObReferenceObjectByHandle(hash) failed 0x%08X; stopping worker.\n",
                 status));
        g_Blw.HashWorkerThread = NULL;
        InterlockedExchange(&g_Blw.HashWorkerStop, 1);
        KeSetEvent(&g_Blw.HashRingEvent, IO_NO_INCREMENT, FALSE);
        (void)ZwWaitForSingleObject(threadHandle, FALSE, NULL);
        ZwClose(threadHandle);
        return status;
    }
    ZwClose(threadHandle);

    KdPrint(("[Bulwark] Hash scan worker started.\n"));
    return STATUS_SUCCESS;
}

void
BlwStopHashWorker(void)
{
    InterlockedExchange(&g_Blw.HashWorkerStop, 1);
    KeSetEvent(&g_Blw.HashRingEvent, IO_NO_INCREMENT, FALSE);

    if (g_Blw.HashWorkerThread != NULL) {
        KeWaitForSingleObject(g_Blw.HashWorkerThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_Blw.HashWorkerThread);
        g_Blw.HashWorkerThread = NULL;
    }
    KdPrint(("[Bulwark] Hash scan worker stopped.\n"));
}
