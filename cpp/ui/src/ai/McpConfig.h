#pragma once
#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

struct McpServerConfig {
    enum class Transport { Stdio, Http };

    QString id;
    QString name;
    bool enabled = true;
    Transport transport = Transport::Stdio;

    QString command;
    QStringList args;
    QStringList env;
    QString cwd;

    QString url;
    QStringList headers;

    bool autoApprove = false;

    bool isStdio() const { return transport == Transport::Stdio; }
    QString validationError() const;
    QString summary() const;
    // 影响「连接本身」的全部字段。变了就必须重启连接;只改名字 / 开关 / 自动批准则不必。
    QString fingerprint() const;

    QJsonObject toJson() const;
    static McpServerConfig fromJson(const QJsonObject& o);
};

namespace mcpcfg {

QList<McpServerConfig> load();
void save(const QList<McpServerConfig>& servers);

QList<McpServerConfig> parseImport(const QString& json, QString* error);

}
