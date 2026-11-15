#pragma once
#include <QString>
#include <QSet>
#include <QMutex>

namespace bulwark::service {

class FirstSeenStore {
public:
    FirstSeenStore();
    bool markAndCheckFirstSeen(const QString& hash);

private:
    void load();
    void compactLocked();

    static constexpr int kMaxEntries = 200000;

    QString path_;
    QSet<QString> seen_;
    QMutex lock_;
};

}
