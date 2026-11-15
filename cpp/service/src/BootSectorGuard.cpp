#include "bulwark/service/BootSectorGuard.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTimer>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#endif

namespace bulwark::service {

namespace {

constexpr int kTickMs = 60 * 1000;

constexpr int kMaxDrives = 16;

QString sha1Hex(const QByteArray& b) {
    return QString::fromLatin1(QCryptographicHash::hash(b, QCryptographicHash::Sha1).toHex());
}

}

BootSectorGuard::BootSectorGuard(QObject* parent) : EventSource(parent) {}

BootSectorGuard::~BootSectorGuard() { stop(); }

QString BootSectorGuard::baselineFilePath(int driveNumber) const {
    return programDataDir() + QStringLiteral("/bootguard/physicaldrive%1.bin").arg(driveNumber);
}

#ifdef _WIN32

bool BootSectorGuard::readHead(const QString& devicePath, QByteArray& out,
                              quint32& sectorSize) const {
    // 必须带 FILE_SHARE_WRITE:裸盘句柄几乎总是已被卷管理器、分区管理器以写方式打开。
    const HANDLE h = ::CreateFileW(reinterpret_cast<const wchar_t*>(devicePath.utf16()),
                                   GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;

    // 取物理扇区大小:裸盘 I/O 必须按扇区对齐,4Kn 磁盘上拿 512 去读会直接失败。
    sectorSize = 512;
    {
        DISK_GEOMETRY g{};
        DWORD ret = 0;
        if (::DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY, nullptr, 0, &g, sizeof(g), &ret,
                              nullptr) && g.BytesPerSector > 0) {
            sectorSize = g.BytesPerSector;
        }
    }

    out.resize(kHeadBytes);
    DWORD read = 0;
    const BOOL ok = ::ReadFile(h, out.data(), static_cast<DWORD>(kHeadBytes), &read, nullptr);
    ::CloseHandle(h);

    if (!ok || read < static_cast<DWORD>(sectorSize)) {
        out.clear();
        return false;
    }
    out.resize(static_cast<int>(read));
    return true;
}

#else

bool BootSectorGuard::readHead(const QString&, QByteArray&, quint32&) const { return false; }

#endif

void BootSectorGuard::loadOrCreateBaselines() {
    QDir().mkpath(QFileInfo(baselineFilePath(0)).absolutePath());

    int found = 0;
    for (int n = 0; n < kMaxDrives; ++n) {
        DriveBaseline b;
        b.driveNumber = n;
        b.devicePath = QStringLiteral("\\\\.\\PhysicalDrive%1").arg(n);

        QByteArray head;
        quint32 sectorSize = 512;
        if (!readHead(b.devicePath, head, sectorSize)) {
            if (n == 0) {
                log_.warning(QStringLiteral(
                    "引导区防护:打不开 %1(需要 SYSTEM / 管理员权限)—— MBR/GPT 基线不可用。"
                    "内核的卷引导区(VBR)前拦截不受影响,仍然生效。").arg(b.devicePath));
            }
            continue;
        }
        ++found;
        b.sectorSize = sectorSize;
        b.head = head;
        if (head.size() > 450)
            b.gpt = static_cast<quint8>(head.at(450)) == 0xEE;

        const QString path = baselineFilePath(n);
        const QByteArray current = b.head;
        bool haveBaseline = false;

        {
            QFile f(path);
            if (f.open(QIODevice::ReadOnly)) {
                const QByteArray saved = f.readAll();
                f.close();
                // 尺寸必须一致才有比对意义(换了扇区大小 / 旧版本留下的短基线 -> 重建)。
                if (saved.size() == current.size()) {
                    b.head = saved;
                    haveBaseline = true;
                    if (current != saved) {
                        log_.warning(QStringLiteral(
                            "引导区防护:磁盘 %1 的当前引导区与已保存基线【不一致】(服务启动时即发现,"
                            "说明改动发生在上次关机/本服务未运行期间)。下面按判据决定是否还原。").arg(n));
                    }
                } else if (!saved.isEmpty()) {
                    log_.info(QStringLiteral("引导区防护:磁盘 %1 的旧基线尺寸不符(%2 vs %3),重建基线。")
                                  .arg(n).arg(saved.size()).arg(current.size()));
                }
            }
        }

        if (!haveBaseline) {
            b.head = current;
            QDir().mkpath(QFileInfo(path).absolutePath());
            QFile w(path);
            if (w.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                w.write(b.head);
                w.close();
                log_.info(QStringLiteral("引导区防护:已为磁盘 %1(%2,扇区 %3B)建立引导区基线快照"
                                         "(前 %4KB,SHA1=%5)。")
                              .arg(n)
                              .arg(b.gpt ? QStringLiteral("GPT") : QStringLiteral("MBR"))
                              .arg(b.sectorSize)
                              .arg(kHeadBytes / 1024)
                              .arg(sha1Hex(b.head).left(12)));
            } else {
                log_.warning(QStringLiteral("引导区防护:无法写入基线文件 %1 —— 本次仅内存比对,"
                                            "跨重启检测不可用。").arg(path));
            }
        }

        drives_.push_back(b);
    }

    available_ = found > 0;
}

void BootSectorGuard::start() {
    if (started_)
        return;
    started_ = true;

    loadOrCreateBaselines();
    if (!available_) {
        log_.warning(QStringLiteral("引导区防护:未能枚举到任何可读的物理磁盘,本维度不生效。"));
        return;
    }

    log_.info(QStringLiteral("引导区防护已启动:%1 块磁盘在监视,巡检周期 %2 秒,模式=仅告警(不写物理磁盘)。")
                  .arg(drives_.size()).arg(kTickMs / 1000));

    verifyNow();

    timer_ = new QTimer(this);
    timer_->setInterval(kTickMs);
    connect(timer_, &QTimer::timeout, this, &BootSectorGuard::onTick);
    timer_->start();
}

void BootSectorGuard::stop() {
    if (timer_) {
        timer_->stop();
        timer_->deleteLater();
        timer_ = nullptr;
    }
    started_ = false;
}

void BootSectorGuard::onTick() { verifyNow(); }

int BootSectorGuard::verifyNow() {
    int hits = 0;

    for (DriveBaseline& b : drives_) {
        QByteArray now;
        quint32 sectorSize = b.sectorSize;
        if (!readHead(b.devicePath, now, sectorSize))
            continue;
        if (now.size() != b.head.size())
            continue;
        if (now == b.head)
            continue;

        ++hits;

        const int sec = static_cast<int>(b.sectorSize);
        const bool mbrChanged = ::memcmp(now.constData(), b.head.constData(), sec) != 0;
        const bool tailChanged =
            now.size() > sec &&
            ::memcmp(now.constData() + sec, b.head.constData() + sec,
                     static_cast<size_t>(now.size() - sec)) != 0;

        const bool sigGone = now.size() >= 512 &&
                             !(static_cast<quint8>(now.at(510)) == 0x55 &&
                               static_cast<quint8>(now.at(511)) == 0xAA);
        const bool bootstrapChanged =
            ::memcmp(now.constData(), b.head.constData(), kMbrBootstrapBytes) != 0;
        const bool partTableChanged =
            now.size() >= kMbrPartTableOffset + kMbrPartTableBytes &&
            ::memcmp(now.constData() + kMbrPartTableOffset,
                     b.head.constData() + kMbrPartTableOffset,
                     kMbrPartTableBytes) != 0;

        const QString fp = QStringLiteral("%1|%2").arg(b.driveNumber).arg(sha1Hex(now));
        const bool firstTime = !reported_.contains(fp);
        if (firstTime)
            reported_.insert(fp);

        if (sigGone) {
            const bool restored = false;
            if (firstTime) {
                report(b, QStringLiteral("引导扇区被擦除(0x55AA 结束标记消失)"),
                       QStringLiteral("这是 wiper 类破坏的典型特征:下次开机将无法引导。"
                                      "%1").arg(restored ? QStringLiteral("已从基线原样还原整个引导扇区。")
                                                         : QStringLiteral("当前为仅告警模式,未写物理磁盘;请从可信介质手动修复引导。")),
                       restored, 100);
            }
        } else if (bootstrapChanged && !partTableChanged) {
            const bool restored = false;
            if (firstTime) {
                report(b, QStringLiteral("MBR 引导代码被篡改(分区表未动)"),
                       QStringLiteral("引导代码被改而分区表完好 —— 这是 bootkit / 引导型勒索"
                                      "(Petya 类)的特征,正当的分区操作不会这样。"
                                      "%1").arg(restored ? QStringLiteral("已只还原前 440 字节引导代码,分区表与磁盘签名一字未动。")
                                                         : QStringLiteral("当前为仅告警模式,未写物理磁盘。")),
                       restored, 100);
            }
        } else if (firstTime) {
            report(b, b.gpt ? QStringLiteral("GPT 分区表 / 引导区发生变化")
                            : QStringLiteral("MBR 分区表发生变化"),
                   QStringLiteral("变化涉及分区表%1,可能是正当操作(装双系统 / 修复引导 / 重新分区),"
                                  "也可能是攻击。【未自动还原】—— 还原分区表会丢数据。"
                                  "若确认是你自己做的,删除基线文件 %2 后本告警即消失(服务会按当前内容重建基线)。")
                       .arg(tailChanged && !mbrChanged ? QStringLiteral("(仅 GPT 区域)") : QString())
                       .arg(QDir::toNativeSeparators(baselineFilePath(b.driveNumber))),
                   false, 70);
        }
    }

    return hits;
}

void BootSectorGuard::report(const DriveBaseline& b, const QString& what, const QString& detail,
                            bool restored, int score) {
    const QString target =
        QStringLiteral("%1 [%2 引导区]").arg(b.devicePath,
                                             b.gpt ? QStringLiteral("GPT") : QStringLiteral("MBR"));

    log_.critical(QStringLiteral("引导区防护:%1 —— %2 (%3)").arg(what, target, detail));

    bulwark::SecurityEvent e;
    e.type = bulwark::EventType::FileWrite;
    e.actorPid = 0;
    e.actorPath = b.devicePath;
    e.target = target;
    e.detail = detail;
    e.userModeObserved = true;
    e.riskScore = score;
    e.hasThreatIndicator = score >= 100;
    e.techniques << QStringLiteral("T1542.003");
    e.riskReasons << what;
    e.addEvidence(QStringLiteral("BootSectorGuard"),
                  score >= 100 ? bulwark::EvidenceKind::HardIndicator
                               : bulwark::EvidenceKind::SoftSignal,
                  QStringLiteral("%1:%2").arg(what, detail), score, false);
    if (restored) {
        e.addEvidence(QStringLiteral("BootSectorGuard"), bulwark::EvidenceKind::Decision,
                      QStringLiteral("已从金库基线原样写回,引导区已恢复可引导状态。"), 0,
                      false);
    }

    emit eventProduced(e);
}

}
