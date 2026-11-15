#pragma once
#include <QHash>
#include <QMutex>
#include <QString>
#include <QStringList>
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

// 关联「(联网 / 取远端)→ 落地可执行体 → 运行它」。
// 写入方签名健康或装在 Program Files / 系统目录(且不是脚本宿主)视为正常安装 / 更新链,只记软分;
// 浏览器下载后由用户双击运行同理(落地者是签名浏览器)。
class DownloaderBehaviorMonitor {
public:
    struct Result {
        int score = 0;
        bool hardSignal = false;
        QStringList reasons;
    };

    Result observe(const SecurityEvent& e);

private:
    struct Drop {
        qint64 atMs = 0;
        int writerPid = 0;
        QString writerInstance;
        QString writerPath;
        bool writerTrusted = false;
        bool writerIsScriptHost = false;
        bool writerFetchedRemote = false;
        bool inDropZone = false;
    };

    void evict(qint64 nowMs);

    QHash<QString, qint64> networkActive_;
    QHash<QString, Drop> drops_;
    QMutex gate_;
};

}
