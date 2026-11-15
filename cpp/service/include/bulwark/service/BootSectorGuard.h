#pragma once
#include "bulwark/service/EventSource.h"
#include "bulwark/service/Logger.h"

#include <QByteArray>
#include <QHash>
#include <QSet>
#include <QString>

class QTimer;

namespace bulwark::service {

class BootSectorGuard : public EventSource {
    Q_OBJECT
public:
    explicit BootSectorGuard(QObject* parent = nullptr);
    ~BootSectorGuard() override;

    void start() override;
    void stop() override;
    bool isAvailable() const override { return available_; }

    int verifyNow();

private slots:
    void onTick();

private:
    struct DriveBaseline {
        int        driveNumber = 0;
        QString    devicePath;
        quint32    sectorSize = 512;
        QByteArray head;
        bool       gpt = false;
    };

    static constexpr int kHeadBytes = 64 * 1024;
    static constexpr int kMbrBootstrapBytes = 440;
    static constexpr int kMbrPartTableOffset = 446;
    static constexpr int kMbrPartTableBytes = 64;

    bool    readHead(const QString& devicePath, QByteArray& out, quint32& sectorSize) const;
    QString baselineFilePath(int driveNumber) const;
    void    loadOrCreateBaselines();
    void    report(const DriveBaseline& b, const QString& what, const QString& detail,
                   bool restored, int score);

    QVector<DriveBaseline> drives_;
    QTimer* timer_ = nullptr;
    bool    available_ = false;
    bool    started_ = false;
    QSet<QString> reported_;

    Logger log_{QStringLiteral("bulwark.service.BootGuard")};
};

}
