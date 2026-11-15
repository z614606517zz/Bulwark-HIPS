#pragma once
#include <QString>
#include <QStringList>
#include <QDateTime>
#include <QJsonObject>
#include "bulwark/models/Enums.h"

namespace bulwark {

struct ProcessEntry {
    int pid = 0;
    int parentPid = 0;
    QString name;
    QString imagePath;
    QString commandLine;
    QString parentName;
    QString userName;
    QDateTime startTimeUtc;
    quint64 creationFileTime = 0; // GetProcessTimes 的原始 FILETIME，供处置请求防 PID 复用
    qint64 workingSetBytes = 0;
    int threadCount = 0;
    int sessionId = 0;
    bool is64Bit = true;
    bool elevated = false;
    bool isSigned = false;
    bool signatureMismatch = false;
    QString publisher;
    QString fileDescription;
    QString sha256;

    ProcessOriginKind originKind = ProcessOriginKind::Unknown;
    QString originService;
    QString originServiceDisplay;
    QString originTask;
    QString originDetail;

    bool isCritical = false;      // 关键系统进程:结束会蓝屏,UI 必须禁用「结束」
    bool isProtectedSelf = false;
    bool isTrusted = false;
    int riskScore = 0;
    QStringList riskReasons;

    QString originLabel() const;

    QJsonObject toJson() const;
    static ProcessEntry fromJson(const QJsonObject& o);
};

}
