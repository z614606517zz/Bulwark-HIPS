#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>

#include <atomic>

namespace bulwark::service::yarahelper {

// bulwark_yarac.exe 的启动方式(编译与扫描共用):挂起创建,先放进 Job 再放行 ——
// 限内存、只许一个进程、未处理异常直接终止、Job 句柄一关连带结束;低于正常优先级,
// 只继承显式交出的管道句柄。

struct ExitResult {
    bool started = false;
    bool timedOut = false;
    bool cancelled = false;
    unsigned long exitCode = 0;
    unsigned long error = 0;
};

// 跑到退出为止。cancelEvent(可空)置位时提前结束。
ExitResult runToExit(const QString& exe, const QStringList& args, int timeoutSeconds, int memoryLimitMb,
                     void* cancelEvent);

// 常驻的辅助进程:经标准输入 / 输出按行收发。只在一个线程里用。
class LineChannel {
public:
    enum class Read { Line, Exited, TimedOut, Cancelled };

    LineChannel() = default;
    ~LineChannel();
    LineChannel(const LineChannel&) = delete;
    LineChannel& operator=(const LineChannel&) = delete;

    bool start(const QString& exe, const QStringList& args, int memoryLimitMb, QString* error);
    // graceful:先关输入管道让它自己退出,等不到再结束;否则立即结束。
    void stop(bool graceful);
    bool running() const { return process_ != nullptr; }

    bool writeLine(const QByteArray& line);
    // 等到一整行、进程退出、超时,或 keepGoing 变 false。
    Read readLine(QByteArray* line, int timeoutMs, const std::atomic<bool>& keepGoing);

private:
    void* job_ = nullptr;
    void* process_ = nullptr;
    void* in_ = nullptr;
    void* out_ = nullptr;
    QByteArray pending_;
};

}
