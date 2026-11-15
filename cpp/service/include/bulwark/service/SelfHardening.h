#pragma once
#include <QString>
#include <QStringList>

#include <functional>

namespace bulwark::service {

class SelfHardening {
public:
    // applied/skipped 是可读短句,直接进日志;没做到的项必须写进 skipped(各 Windows 版本支持度不同)。
    struct Report {
        QStringList applied;
        QStringList skipped;
    };

    static Report hardenCurrentProcess(bool guiProcess);

    static QStringList auditOwnToken(bool serviceProcess);

    using DegradedHandler = std::function<void(const QStringList& reasons)>;
    static bool selfCheck(bool serviceProcess, const DegradedHandler& onDegraded);
};

}
