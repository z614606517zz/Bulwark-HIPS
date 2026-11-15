#pragma once
#include <QString>

#include <functional>

class QObject;
class QWidget;

namespace bulwark::ui::bootstrap {

bool backendReachable(int timeoutMs = 300);

bool ensureUiAutoStart();

// 后台服务启动结果。startBackend() 不弹窗、可放在工作线程;
// ensureBackendRunning() 在 UI 线程上按结果给出提示弹窗。
enum class BackendStartOutcome {
    AlreadyRunning,   // 服务本来就在跑
    Started,          // 本次拉起成功
    Missing,          // 找不到 bulwark_service.exe
    Refused,          // 用户拒绝了 UAC 提权
    Failed,           // 拉起进程失败或等待就绪超时
};

// 注册(如缺失)并启动后台服务、加载内核驱动,等待服务就绪。detail 里带回 bootstrap-status 摘要。
BackendStartOutcome startBackend(int waitMs, QString* detail = nullptr);

// 在工作线程执行 startBackend,结果回到 guard 所在线程;guard 已销毁则丢弃这次回调。
void startBackendAsync(QObject* guard, std::function<void(BackendStartOutcome, const QString&)> done);

bool ensureBackendRunning(QWidget* parent = nullptr);

}
