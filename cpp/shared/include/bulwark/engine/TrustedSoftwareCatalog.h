#pragma once
#include <QDateTime>
#include <QList>
#include <QRecursiveMutex>
#include <QSet>
#include <QString>
#include <QStringList>

#include <optional>

namespace bulwark::engine {

struct TrustedApp {
    enum class Scope { Exe, Vendor };
    QString id;
    QString name;
    QString vendor;
    QString category;
    QStringList exes;
    QStringList publishers;
    QString note;
    Scope scope = Scope::Exe;
    bool builtin = false;
    bool enabled = true;
};

class TrustedSoftwareCatalog
{
public:
    static TrustedSoftwareCatalog& instance();

    bool load(const QString& path = QString());
    bool save(const QString& path = QString()) const;
    QString filePath() const;

    QList<TrustedApp> apps() const { QMutexLocker lk(&mu_); return apps_; }
    QStringList categories() const;

    std::optional<TrustedApp> match(const QString& imagePath, const QString& publisher);

    bool upsert(const TrustedApp& app, QString* error = nullptr);
    bool remove(const QString& id, QString* error = nullptr);
    bool setEnabled(const QString& id, bool on, QString* error = nullptr);

    void resetToBuiltin();

    static QString userPath(const QString& id);

private:
    TrustedSoftwareCatalog();
    mutable QRecursiveMutex mu_;
    QList<TrustedApp> apps_;
    QString path_;
    QDateTime loadedMtime_;
};

}
