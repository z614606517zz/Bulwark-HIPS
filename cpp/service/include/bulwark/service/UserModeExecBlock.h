#pragma once
#include "bulwark/service/Logger.h"

#include <QHash>
#include <QMutex>
#include <QObject>
#include <QString>
#include <QStringList>

class QTimer;

namespace bulwark::service {

class UserModeExecBlock : public QObject {
    Q_OBJECT
public:
    explicit UserModeExecBlock(int maxEntries = 256, QObject* parent = nullptr);
    ~UserModeExecBlock() override;

    int replay();

    bool blockExecPath(const QString& needle);
    bool blockModuleLoad(const QString& needle);
    bool clearExecBlock();
    bool clearModuleNoLoad();
    QStringList persistedExecBlockList() const;
    QStringList persistedModuleNoLoadList() const;

    // 隔离/取哈希/删除之前必须先放开句柄。放开的条目转为待重新武装:文件还在会重试加锁,已移走则
    // 等同路径再出现时自动重新钉住。absPath 为空表示全部挂起。返回被放开的句柄数。
    int suspendForRemediation(const QString& absPath);

    // 整体待机/唤醒(退出界面即停止防护)。与 suspendForRemediation 不同,必须连重试定时器一起停,
    // 否则 rearmPending() 最多 30 秒后会重新锁上。待机不清名单、不动落盘清单。
    void setSuspended(bool suspended);
    bool isSuspended() const { return suspended_; }

    int armedCount() const;
    int pendingCount() const;

private slots:
    void rearmPending();

private:
    struct Entry {
        QString needle;
        QStringList resolved;
        QList<void*> handles;
        bool inExec = false;
        bool inModule = false;
        QString since;
    };

    bool addEntry(const QString& needle, bool exec);
    bool armLocked(Entry& e);
    void releaseLocked(Entry& e);
    bool clearListLocked(bool exec);
    QStringList resolveNeedle(const QString& needle) const;
    bool isRefusedPath(const QString& absPath) const;
    void save() const;
    QString manifestPath() const;

    mutable QMutex mx_;
    QHash<QString, Entry> entries_;
    int maxEntries_ = 256;
    bool suspended_ = false;
    QTimer* rearm_ = nullptr;
    Logger log_{QStringLiteral("bulwark.service.ExecBlock")};
};

}
