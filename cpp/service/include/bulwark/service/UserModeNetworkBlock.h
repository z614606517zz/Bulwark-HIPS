#pragma once
#include "bulwark/service/Logger.h"

#include <QHash>
#include <QMutex>
#include <QString>
#include <QStringList>

#include <cstdint>

namespace bulwark::service {

class UserModeNetworkBlock {
public:
    explicit UserModeNetworkBlock(int maxEntries = 256);
    ~UserModeNetworkBlock();

    bool open();
    bool isOpen() const;

    bool blockIp(const QString& ip, quint16 port = 0);

    int unblockIp(const QString& ip, quint16 port = 0);
    int clearAll();

    QStringList blockedList() const;

private:
    struct Entry {
        QString ip;
        quint16 port = 0;
        quint64 filterId = 0;
        QString since;
    };

    static QString keyOf(const QString& ip, quint16 port);
    bool addFilterLocked(Entry& e);
    bool deleteFilterLocked(Entry& e);
    void removeLegacyManifest() const;

    mutable QMutex mx_;
    QHash<QString, Entry> entries_;
    void* engine_ = nullptr;
    int maxEntries_ = 256;
    Logger log_{QStringLiteral("bulwark.service.NetBlock")};
};

}
