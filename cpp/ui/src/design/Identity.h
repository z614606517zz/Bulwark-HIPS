#pragma once
#include "Nav.h"
#include "design/Theme.h"

#include <QColor>
#include <QString>

namespace identity {

inline QColor page(const QString& key)
{
    const auto is = [&key](const char* k) { return key == QLatin1String(k); };
    if (is(nav::Events))                              return theme::cyan();
    if (is(nav::Timeline) || is(nav::Persistence))    return theme::periwinkle();
    if (is(nav::Quarantine))                          return theme::purple();
    if (is(nav::Boost))                               return theme::pink();
    if (is(nav::Hardening))                           return theme::cyan();
    if (is(nav::Rules))                               return theme::violet();
    if (is(nav::Trust) || is(nav::SoftwareCatalog))   return theme::olive();
    if (is(nav::YaraRules))                           return theme::accentAlt();
    return theme::accent();
}

inline QColor page(const char* key) { return page(QString::fromLatin1(key)); }

inline QColor settingsSection(const QString& key)
{
    const auto is = [&key](const char* k) { return key == QLatin1String(k); };
    if (is("dims"))     return theme::olive();
    if (is("decision")) return page(nav::Rules);
    if (is("intel"))    return theme::cyan();
    if (is("ai"))       return theme::accentAlt();
    if (is("mcp"))      return theme::purple();
    if (is("share"))    return theme::pink();
    if (is("about"))    return theme::periwinkle();
    return theme::accent();
}

enum class Kind {
    Neutral,
    Process,
    Injection,
    Module,
    File,
    Registry,
    Network,
    Protection, // the 自我保护 dimension — never a record (see below)
    Service,
    Task,
};

inline QColor kind(Kind k)
{
    switch (k) {
    case Kind::Process:    return theme::textSecondary();
    case Kind::Protection: return theme::accent();
    case Kind::Injection:  return theme::purple();
    case Kind::Service:    return theme::purple();
    case Kind::Module:     return theme::periwinkle();
    case Kind::File:       return theme::olive();
    case Kind::Registry:   return theme::violet();
    case Kind::Network:    return theme::cyan();
    case Kind::Task:       return theme::pink();
    case Kind::Neutral:    break;
    }
    return theme::textSecondary();
}

inline QColor sequence(int i)
{
    const QColor hues[] = {theme::cyan(),   theme::purple(), theme::olive(),
                           theme::periwinkle(), theme::pink(), theme::violet()};
    constexpr int n = int(sizeof(hues) / sizeof(hues[0]));
    return hues[((i % n) + n) % n];
}

}
