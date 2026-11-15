#pragma once
#include <QString>

namespace bulwark::service {

enum class LogLevel { Trace, Debug, Information, Warning, Error, Critical };

QString programDataDir();
QString logFilePath();
void startFileLog();
void stopFileLog();
void writeCrashLog(const QString& phase, const QString& detail);

class Logger {
public:
    explicit Logger(const QString& category);

    bool isEnabled(LogLevel level) const { return level >= minLevel_; }
    void write(LogLevel level, const QString& msg) const;
    void error(const QString& msg, const QString& detail = QString()) const;

    void trace(const QString& m) const { write(LogLevel::Trace, m); }
    void debug(const QString& m) const { write(LogLevel::Debug, m); }
    void info(const QString& m) const { write(LogLevel::Information, m); }
    void warning(const QString& m) const { write(LogLevel::Warning, m); }
    void critical(const QString& m) const { write(LogLevel::Critical, m); }

private:
    QString category_;
    LogLevel minLevel_ = LogLevel::Information;
};

}
