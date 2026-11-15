#pragma once
#include <QList>
#include <QString>
#include <functional>
#include "bulwark/models/ProcessEntry.h"

// 在跑进程快照,进程管理页的数据源。只读:风险分只用于排序与着色,不触发任何自动处置。
// 首次快照要逐个验签(可能数秒),必须在后台线程调用,不要在 IPC / 事件裁决线程上调。
namespace bulwark::service::monitoring {

class ProcessEnumerator {
public:
    struct Options {
        bool includeCommandLine = true;
        bool resolveOrigin = true;
        bool verifySignature = true;
    };

    static QList<bulwark::ProcessEntry> snapshot(
        const Options& opt = Options{},
        const std::function<bool(int)>& isProtectedSelf = nullptr,
        const std::function<bool(const QString&)>& isTrustedImage = nullptr);
};

}
