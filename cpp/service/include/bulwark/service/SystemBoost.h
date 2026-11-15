#pragma once
#include <QtGlobal>
#include <functional>

namespace bulwark::service {

struct SystemBoostReport {
    int processesTrimmed = 0;
    int processesTotal = 0;
    qint64 freedBytes = 0;
    qint64 inUseBefore = 0;
    qint64 inUseAfter = 0;
    qint64 totalPhysical = 0;
    int loadBefore = 0;
    int loadAfter = 0;
};

class SystemBoost {
public:
    // shouldSkip(pid) 为 true 的进程不修剪(用来跳过本产品自身组件),可为空;打不开的进程静默跳过。
    // 内部会等约 0.6 秒让页挪到待命列表,应在后台线程调用,不要占用 IPC/事件裁决线程。
    static SystemBoostReport run(const std::function<bool(int)>& shouldSkip = nullptr);
};

}
