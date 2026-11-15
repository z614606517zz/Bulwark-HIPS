#pragma once

// 读文件开头一小段给勒索行为监视器,用来分辨「改写之后还是好文件」和「已经成了乱码」。
// 读盘放在自己的线程里:某次读取卡住(坏盘、别的驱动挂起)时调用方最多等 timeoutMs,
// 那次读取返回之前一律回答「这会儿读不到」(Busy,调用方稍后再问),不拖住事件队列。

#include "bulwark/engine/FileContentClassifier.h"

#include <QString>

#include <memory>
#include <thread>

namespace bulwark::service {

class FileContentProbe {
public:
    explicit FileContentProbe(int timeoutMs = 150);
    ~FileContentProbe();
    FileContentProbe(const FileContentProbe&) = delete;
    FileContentProbe& operator=(const FileContentProbe&) = delete;

    // 同一时刻只服务一个调用方;超时、或上一次读取还没返回时回答 Busy。
    bulwark::engine::FileContentSample sample(const QString& path);

    // 在调用线程上直接读,不设超时。只读本地盘上的普通文件;以完全共享的方式只读打开,
    // 不跟随重解析点,不碰云端占位文件(一读就会触发下载)。
    static bulwark::engine::FileContentSample readHead(const QString& path);

private:
    struct Shared;
    static void run(std::shared_ptr<Shared> shared);

    std::shared_ptr<Shared> shared_;
    std::thread worker_;
    int timeoutMs_;
};

}
