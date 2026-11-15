#pragma once
#include <QObject>
#include <QString>
#include <QVariantMap>

#include <functional>

namespace nav {
inline constexpr const char* Dashboard   = "dashboard";
inline constexpr const char* Events      = "events";
inline constexpr const char* Timeline    = "timeline";
inline constexpr const char* Boost       = "boost";
inline constexpr const char* Processes   = "processes";
inline constexpr const char* Rules       = "rules";
inline constexpr const char* Trust       = "trust";
inline constexpr const char* SoftwareCatalog = "softlib";
inline constexpr const char* Quarantine  = "quarantine";
inline constexpr const char* Persistence = "persistence";
inline constexpr const char* Hardening   = "hardening";
inline constexpr const char* YaraRules   = "yararules";
inline constexpr const char* Settings    = "settings";
}

class NavHub : public QObject
{
    Q_OBJECT
public:
    static NavHub* instance();

    void request(const QString& key, const QVariantMap& args) { emit requested(key, args); }
    void deliver(const QString& key, const QVariantMap& args) { emit delivered(key, args); }
    void setBadge(const QString& key, int count) { emit badgeChanged(key, count); }

signals:
    void requested(const QString& key, const QVariantMap& args);
    void delivered(const QString& key, const QVariantMap& args);
    void badgeChanged(const QString& key, int count);

private:
    using QObject::QObject;
};

namespace nav {

inline void go(const QString& key, const QVariantMap& args = {})
{
    NavHub::instance()->request(key, args);
}

inline void onArrive(QObject* context, const QString& key, std::function<void(const QVariantMap&)> fn)
{
    QObject::connect(NavHub::instance(), &NavHub::delivered, context,
                     [key, fn = std::move(fn)](const QString& k, const QVariantMap& args) {
                         if (k == key && fn)
                             fn(args);
                     });
}

}
