#include "design/Sticker.h"
#include "design/Motion.h"
#include "design/Skin.h"
#include "design/SvgPath.h"
#include "design/Theme.h"

#include <QFontMetricsF>
#include <QHash>
#include <QPainter>
#include <QPainterPath>
#include <QRegularExpression>
#include <QTimer>
#include <QVariantAnimation>
#include <QtMath>

#include <cmath>

namespace sticker {
namespace {

QColor hexc(const char* h) { return QColor::fromString(QLatin1StringView(h)); }

Qt::PenJoinStyle join() { return theme::mecha() ? Qt::MiterJoin : Qt::RoundJoin; }

// 贴纸图标:设计稿里的 24×24 SVG 片段,原样解析
struct Item {
    QPainterPath path;
    QColor fill;
    QColor stroke;
    qreal width = -1.0;   // <0 = 用调用方给的笔宽
    bool noStroke = false;
};

const char* const kMechaIcons[][2] = {
    {"dash", R"(<path d="M3 5l2-2h6v8H3zM13 3h6l2 2v6h-8zM3 13h8v8H5l-2-2zM13 13h8v6l-2 2h-6z" fill="#2EE6F0"/>)"},
    {"events", R"(<path d="M5 3h14v18H5z" fill="#F5F4F1"/><path d="M8 7.5h8M8 11h8M8 14.5h5"/><path d="M15 17.5l1.5 1.5 3-3" stroke="#FF7A1A"/>)"},
    {"timeline", R"(<path d="M3 12h18"/><polygon points="6.5,8.5 10,12 6.5,15.5 3,12" fill="#2EE6F0"/><polygon points="12,8.5 15.5,12 12,15.5 8.5,12" fill="#FFD23F"/><polygon points="17.5,8.5 21,12 17.5,15.5 14,12" fill="#FF3D4E"/>)"},
    {"boost", R"(<path d="M13 2 4 14h7l-1 8 9-12h-7z" fill="#FFD23F"/>)"},
    {"proc", R"(<rect x="6" y="6" width="12" height="12" fill="#8DB0FF"/><rect x="9.5" y="9.5" width="5" height="5" fill="#2F6BFF"/><path d="M9 2.5v3M15 2.5v3M9 18.5v3M15 18.5v3M2.5 9h3M2.5 15h3M18.5 9h3M18.5 15h3"/>)"},
    {"rules", R"(<path d="M4 6h16M4 12h16M4 18h16"/><rect x="6.5" y="3.5" width="5" height="5" fill="#2EE6F0"/><rect x="13" y="9.5" width="5" height="5" fill="#FF3D4E"/><rect x="4.5" y="15.5" width="5" height="5" fill="#FFD23F"/>)"},
    {"trust", R"(<path d="M12 21.5s8-3.8 8-10V5l-8-3-8 3v6.5c0 6.2 8 10 8 10z" fill="#2F6BFF"/><path d="m8.5 11.5 2.5 2.5 4.5-5" stroke="#FFFFFF" stroke-width="2.6"/>)"},
    {"catalog", R"(<path d="M3.5 7.5 12 3l8.5 4.5v9L12 21l-8.5-4.5z" fill="#FFB37A"/><path d="M3.5 7.5 12 12l8.5-4.5M12 12v9"/>)"},
    {"quar", R"(<path d="M7 3h10v4l2 2v12H5V9l2-2z" fill="#FFD23F"/><path d="M8.5 12.5h7v6h-7z" fill="#0B1020"/><path d="M10.5 14.5l3 3M13.5 14.5l-3 3" stroke="#FFD23F" stroke-width="1.6"/>)"},
    {"auto", R"(<polygon points="12,2 20.5,7 20.5,17 12,22 3.5,17 3.5,7" fill="#9CFF57"/><path d="M12 7v5"/><path d="M8.8 9.5a4.5 4.5 0 1 0 6.4 0"/>)"},
    {"harden", R"(<path d="M5 21V9h2V6h3v3h4V6h3v3h2v12z" fill="#8DB0FF"/><path d="M10 21v-4h4v4" fill="#0B1020"/>)"},
    {"yara", R"(<path d="M6 2.5h9l4 4v15H6z" fill="#F5F4F1"/><path d="M15 2.5v4h4"/><path d="M9 12.5h7M9 16h7M9 19.5h4"/><path d="M3 9h18" stroke="#2EE6F0" stroke-width="2.4"/>)"},
    {"ai", R"(<polygon points="12,2 14.4,9.6 22,12 14.4,14.4 12,22 9.6,14.4 2,12 9.6,9.6" fill="#A77BFF"/>)"},
    {"settings", R"(<path d="M10.3 2.5h3.4l.6 2.6 1.9.8 2.3-1.4 2.4 2.4-1.4 2.3.8 1.9 2.6.6v3.4l-2.6.6-.8 1.9 1.4 2.3-2.4 2.4-2.3-1.4-1.9.8-.6 2.6h-3.4l-.6-2.6-1.9-.8-2.3 1.4-2.4-2.4 1.4-2.3-.8-1.9-2.6-.6v-3.4l2.6-.6.8-1.9-1.4-2.3 2.4-2.4 2.3 1.4 1.9-.8z" fill="#C3CDE2"/><circle cx="12" cy="12" r="3.3" fill="#0B1020"/>)"},
    {"globe", R"(<circle cx="12" cy="12" r="9" fill="#8DB0FF"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>)"},
    {"file", R"(<path d="M14 2.5H5v19h14v-14z" fill="#F5F4F1"/><path d="M14 2.5v5h5"/>)"},
    {"reg", R"(<rect x="3" y="3" width="8" height="8" fill="#FFD23F"/><rect x="13" y="13" width="8" height="8" fill="#8DB0FF"/><path d="M7 11v5h6M17 13V8h-6"/>)"},
    {"x", R"(<path d="M17 7 7 17M7 7l10 10"/>)"},
    {"minus", R"(<path d="M6 12h12"/>)"},
    {"square", R"(<rect x="6" y="6" width="12" height="12"/>)"},
    {"check", R"(<path d="M19 7 9.5 16.5 5 12"/>)"},
    {"clock", R"(<circle cx="12" cy="12" r="9" fill="#F5F4F1"/><path d="M12 7v5l3.5 2"/>)"},
    {"copy", R"(<rect x="9" y="9" width="12" height="12" fill="#F5F4F1"/><path d="M5 15H3V3h12v2"/>)"},
    {"folder", R"(<path d="M2.5 5h7l2 2.5h10V20h-19z" fill="#FFB37A"/>)"},
    {"tree", R"(<path d="M6 3v12"/><rect x="15" y="3" width="6" height="6" fill="#FFD23F"/><rect x="3" y="15" width="6" height="6" fill="#FFD23F"/><path d="M18 9v3a6 6 0 0 1-6 6H9"/>)"},
    {"eye", R"(<path d="M1.5 12S5.5 4.5 12 4.5 22.5 12 22.5 12 18.5 19.5 12 19.5 1.5 12 1.5 12z" fill="#F5F4F1"/><circle cx="12" cy="12" r="3.4" fill="#2F6BFF"/>)"},
    {"pin", R"(<path d="M12 17v5M5 17h14v-2l-3-2V6h1V2H7v4h1v7l-3 2z" fill="#FF7A1A"/>)"},
    {"mouse", R"(<rect x="6" y="2.5" width="12" height="19" rx="6" fill="#F5F4F1"/><path d="M12 6.5v4"/>)"},
    {"move", R"(<path d="M5 9l-3 3 3 3M9 5l3-3 3 3M15 19l-3 3-3-3M19 9l3 3-3 3M2 12h20M12 2v20"/>)"},
    {"bell", R"(<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" fill="#FFD23F"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/>)"},
    {"gamepad", R"(<path d="M6 6h12l4 6v6H2v-6z" fill="#A77BFF"/><path d="M6 12h4M8 10v4M15 13h.01M18 11h.01"/>)"},
    {"search", R"(<circle cx="11" cy="11" r="7" fill="#F5F4F1"/><path d="m20.5 20.5-4.5-4.5"/>)"},
    {"wifi", R"(<path d="M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M2 9a15 15 0 0 1 20 0M12 20h.01"/>)"},
    {"volume", R"(<path d="M11 5 6 9H2v6h4l5 4z" fill="#F5F4F1"/><path d="M15.5 8.5a5 5 0 0 1 0 7M19 5a10 10 0 0 1 0 14"/>)"},
    {"down", R"(<path d="M12 4v15M18.5 12.5 12 19l-6.5-6.5"/>)"},
    {"up", R"(<path d="M12 20V5M5.5 11.5 12 5l6.5 6.5"/>)"},
    {"external", R"(<path d="M18 13v8H3V6h8M15 3h6v6M10 14 21 3"/>)"},
    {"terminal", R"(<rect x="2.5" y="4" width="19" height="16" fill="#141C36"/><path d="m6.5 9 3 3-3 3M12 15h5" stroke="#2EE6F0"/>)"},
    {"refresh", R"(<path d="M21 12a9 9 0 0 1-15.5 6.2L3 16M3 12a9 9 0 0 1 15.5-6.2L21 8M21 3v5h-5M3 21v-5h5"/>)"},
    {"scissors", R"(<circle cx="6" cy="6" r="3" fill="#FFD23F"/><circle cx="6" cy="18" r="3" fill="#FFD23F"/><path d="M20 4 8.1 15.9M14.5 14.5 20 20M8.1 8.1 12 12"/>)"},
    {"hide", R"(<path d="M2 12s4-7 10-7c2 0 3.8.7 5.3 1.7M22 12s-4 7-10 7c-2 0-3.8-.7-5.3-1.7M3 3l18 18"/>)"},
    {"target", R"(<circle cx="12" cy="12" r="9" fill="#FF3D4E"/><circle cx="12" cy="12" r="5" fill="#F5F4F1"/><circle cx="12" cy="12" r="1.8" fill="#0B1020"/>)"},
    {"rocket", R"(<path d="M12 2c4 2 6 6 6 11l-3 3H9l-3-3c0-5 2-9 6-11z" fill="#F5F4F1"/><circle cx="12" cy="9.5" r="2.2" fill="#2EE6F0"/><path d="M9 16l-2 5 5-3 5 3-2-5" fill="#FF7A1A"/>)"},
};

const char* const kKawaiiIcons[][2] = {
    {"dash", R"(<rect x="3" y="3" width="8" height="8" rx="2.5" fill="#12A58A"/><rect x="13" y="3" width="8" height="8" rx="2.5" fill="#FBF7EF"/><rect x="3" y="13" width="8" height="8" rx="2.5" fill="#FBF7EF"/><rect x="13" y="13" width="8" height="8" rx="2.5" fill="#F2B32B"/>)"},
    {"events", R"(<path d="M5 3h14v17.5l-2.3-1.5-2.4 1.5L12 19l-2.3 1.5L7.3 19 5 20.5z" fill="#FFFDF8"/><path d="M8.5 8h7M8.5 11.5h7M8.5 15h4"/>)"},
    {"timeline", R"(<path d="M3 12h18"/><circle cx="6.5" cy="12" r="2.6" fill="#12A58A"/><circle cx="12" cy="12" r="2.6" fill="#F2B32B"/><circle cx="17.5" cy="12" r="2.6" fill="#E8452C"/>)"},
    {"boost", R"(<path d="M13 2 4 14h7l-1 8 9-12h-7z" fill="#F2B32B"/>)"},
    {"proc", R"(<rect x="6" y="6" width="12" height="12" rx="3" fill="#CFE0FC"/><rect x="9.5" y="9.5" width="5" height="5" rx="1.5" fill="#2F6FE0"/><path d="M9 2.5v3M15 2.5v3M9 18.5v3M15 18.5v3M2.5 9h3M2.5 15h3M18.5 9h3M18.5 15h3"/>)"},
    {"rules", R"(<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="9" cy="6" r="2.6" fill="#12A58A"/><circle cx="15.5" cy="12" r="2.6" fill="#E8452C"/><circle cx="7" cy="18" r="2.6" fill="#F2B32B"/>)"},
    {"trust", R"(<path d="M12 21.5s8-3.8 8-10V5l-8-3-8 3v6.5c0 6.2 8 10 8 10z" fill="#12A58A"/><path d="M12 15.2c-2.8-1.9-4-3.4-3.2-4.7.8-1.1 2.3-.9 3.2.3.9-1.2 2.4-1.4 3.2-.3.8 1.3-.4 2.8-3.2 4.7z" fill="#fff" stroke="none"/>)"},
    {"catalog", R"(<path d="M3.5 7.5 12 3l8.5 4.5v9L12 21l-8.5-4.5z" fill="#D9B98A"/><path d="M3.5 7.5 12 12l8.5-4.5M12 12v9M7.8 5.2l8.4 4.6"/>)"},
    {"quar", R"(<rect x="6.5" y="2.5" width="11" height="4" rx="1.6" fill="#8A8378"/><path d="M7.5 6.5h9v2a3.5 3.5 0 0 1 1.5 2.9V19a2.5 2.5 0 0 1-2.5 2.5h-7A2.5 2.5 0 0 1 6 19v-7.6a3.5 3.5 0 0 1 1.5-2.9z" fill="#FCE7B0"/><circle cx="12" cy="15" r="2.6" fill="#E8452C"/>)"},
    {"auto", R"(<circle cx="12" cy="12" r="9" fill="#C7F0D6"/><path d="M12 6.5V12"/><path d="M8.4 8.8a5 5 0 1 0 7.2 0"/>)"},
    {"harden", R"(<path d="M5 21V9.5a1.5 1.5 0 0 1 1.5-1.5h1.1V6.2a1.2 1.2 0 0 1 2.4 0V8h4V6.2a1.2 1.2 0 0 1 2.4 0V8h1.1A1.5 1.5 0 0 1 19 9.5V21z" fill="#F9CDC3"/><path d="M10 21v-3.6a2 2 0 0 1 4 0V21" fill="#FBF7EF"/>)"},
    {"yara", R"(<path d="M15 2.5H7.5A1.5 1.5 0 0 0 6 4v16a1.5 1.5 0 0 0 1.5 1.5h10A1.5 1.5 0 0 0 19 20V6.5z" fill="#FFFDF8"/><path d="M15 2.5v4h4"/><path d="M9 12.5h7M9 16h7M9 19.5h4"/><path d="M3 9h18" stroke="#12A58A" stroke-width="2.4"/>)"},
    {"ai", R"(<path d="M12 2.5 13.9 9a2 2 0 0 0 1.2 1.2l6.4 1.8-6.4 1.9a2 2 0 0 0-1.2 1.2L12 21.5l-1.9-6.4A2 2 0 0 0 8.9 14L2.5 12l6.4-1.8A2 2 0 0 0 10.1 9z" fill="#E0D7FB"/>)"},
    {"settings", R"(<path d="M10.3 2.5h3.4l.6 2.6 1.9.8 2.3-1.4 2.4 2.4-1.4 2.3.8 1.9 2.6.6v3.4l-2.6.6-.8 1.9 1.4 2.3-2.4 2.4-2.3-1.4-1.9.8-.6 2.6h-3.4l-.6-2.6-1.9-.8-2.3 1.4-2.4-2.4 1.4-2.3-.8-1.9-2.6-.6v-3.4l2.6-.6.8-1.9-1.4-2.3 2.4-2.4 2.3 1.4 1.9-.8z" fill="#E7DCC8"/><circle cx="12" cy="12" r="3.3" fill="#FBF7EF"/>)"},
    {"globe", R"(<circle cx="12" cy="12" r="9" fill="#CFE0FC"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>)"},
    {"file", R"(<path d="M14 2.5H6.5A1.5 1.5 0 0 0 5 4v16a1.5 1.5 0 0 0 1.5 1.5h11A1.5 1.5 0 0 0 19 20V7.5z" fill="#FFFDF8"/><path d="M14 2.5v5h5"/>)"},
    {"reg", R"(<rect x="3" y="3" width="8" height="8" rx="2" fill="#FCE7B0"/><rect x="13" y="13" width="8" height="8" rx="2" fill="#CFE0FC"/><path d="M7 11v3a2 2 0 0 0 2 2h4M17 13v-3a2 2 0 0 0-2-2h-4"/>)"},
    {"x", R"(<path d="M17 7 7 17M7 7l10 10"/>)"},
    {"minus", R"(<path d="M6 12h12"/>)"},
    {"square", R"(<rect x="6" y="6" width="12" height="12" rx="3.5"/>)"},
    {"check", R"(<path d="M19 7 9.5 16.5 5 12"/>)"},
    {"clock", R"(<circle cx="12" cy="12" r="9" fill="#FBF7EF"/><path d="M12 7v5l3.5 2"/>)"},
    {"copy", R"(<rect x="9" y="9" width="12" height="12" rx="3" fill="#FBF7EF"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>)"},
    {"folder", R"(<path d="M2.5 6.5A1.5 1.5 0 0 1 4 5h5l2 2.5h9A1.5 1.5 0 0 1 21.5 9v9.5A1.5 1.5 0 0 1 20 20H4a1.5 1.5 0 0 1-1.5-1.5z" fill="#F2C75C"/>)"},
    {"tree", R"(<path d="M6 3v12"/><circle cx="18" cy="6" r="3" fill="#FCE7B0"/><circle cx="6" cy="18" r="3" fill="#FCE7B0"/><path d="M18 9a9 9 0 0 1-9 9"/>)"},
    {"eye", R"(<path d="M1.5 12S5.5 4.5 12 4.5 22.5 12 22.5 12 18.5 19.5 12 19.5 1.5 12 1.5 12z" fill="#FBF7EF"/><circle cx="12" cy="12" r="3.4" fill="#2E2B27"/><circle cx="10.8" cy="10.8" r="1.1" fill="#fff" stroke="none"/>)"},
    {"pin", R"(<path d="M12 17v5M5 17h14v-1.8a2 2 0 0 0-1.1-1.8l-1.8-.9A2 2 0 0 1 15 10.8V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.8a2 2 0 0 1-1.1 1.8l-1.8.9A2 2 0 0 0 5 15.2Z" fill="#F9CDC3"/>)"},
    {"mouse", R"(<rect x="6" y="2.5" width="12" height="19" rx="6" fill="#FBF7EF"/><path d="M12 6.5v4"/>)"},
    {"move", R"(<path d="M5 9l-3 3 3 3M9 5l3-3 3 3M15 19l-3 3-3-3M19 9l3 3-3 3M2 12h20M12 2v20"/>)"},
    {"bell", R"(<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" fill="#FCE7B0"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/>)"},
    {"gamepad", R"(<rect x="2" y="6" width="20" height="12" rx="6" fill="#E0D7FB"/><path d="M6 12h4M8 10v4M15 13h.01M18 11h.01"/>)"},
    {"search", R"(<circle cx="11" cy="11" r="7" fill="#FBF7EF"/><path d="m20.5 20.5-4.5-4.5"/>)"},
    {"wifi", R"(<path d="M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M2 9a15 15 0 0 1 20 0M12 20h.01"/>)"},
    {"volume", R"(<path d="M11 5 6 9H2v6h4l5 4z" fill="#FBF7EF"/><path d="M15.5 8.5a5 5 0 0 1 0 7M19 5a10 10 0 0 1 0 14"/>)"},
    {"down", R"(<path d="M12 4v15M18.5 12.5 12 19l-6.5-6.5"/>)"},
    {"up", R"(<path d="M12 20V5M5.5 11.5 12 5l6.5 6.5"/>)"},
    {"external", R"(<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14 21 3"/>)"},
    {"terminal", R"(<rect x="2.5" y="4" width="19" height="16" rx="3.5" fill="#2E2B27"/><path d="m6.5 9 3 3-3 3M12 15h5" stroke="#FBF7EF"/>)"},
    {"refresh", R"(<path d="M21 12a9 9 0 0 1-15.5 6.2L3 16M3 12a9 9 0 0 1 15.5-6.2L21 8M21 3v5h-5M3 21v-5h5"/>)"},
    {"scissors", R"(<circle cx="6" cy="6" r="3" fill="#F9CDC3"/><circle cx="6" cy="18" r="3" fill="#F9CDC3"/><path d="M20 4 8.1 15.9M14.5 14.5 20 20M8.1 8.1 12 12"/>)"},
    {"hide", R"(<path d="M2 12s4-7 10-7c2 0 3.8.7 5.3 1.7M22 12s-4 7-10 7c-2 0-3.8-.7-5.3-1.7M3 3l18 18"/>)"},
    {"target", R"(<circle cx="12" cy="12" r="9" fill="#E8452C"/><circle cx="12" cy="12" r="5" fill="#FBF7EF"/><circle cx="12" cy="12" r="1.8" fill="#2E2B27"/>)"},
    {"rocket", R"(<path d="M12 2c4 2 6 6 6 11l-3 3H9l-3-3c0-5 2-9 6-11z" fill="#FBF7EF"/><circle cx="12" cy="9.5" r="2.2" fill="#12A58A"/><path d="M9 16l-2 5 5-3 5 3-2-5" fill="#F9CDC3"/>)"},
    {"heart", R"(<path d="M12 20.5C5 16 2.5 12.4 3.6 9 4.6 6 8.6 5.2 12 8.6c3.4-3.4 7.4-2.6 8.4.4 1.1 3.4-1.4 7-8.4 11.5z" fill="#F9CDC3"/>)"},
    {"star", R"(<path d="m12 2.8 2.6 5.6 6.1.7-4.5 4.2 1.2 6.1L12 16.4l-5.4 3 1.2-6.1-4.5-4.2 6.1-.7z" fill="#FCE7B0"/>)"},
};

QColor recolor(const QString& raw)
{
    static const QHash<QString, QString> mecha = {
        {"#2EE6F0", "#FFA23A"}, {"#FFD23F", "#FFCF33"}, {"#FF3D4E", "#E5383B"}, {"#8DB0FF", "#DEDAD2"},
        {"#2F6BFF", "#FF6A13"}, {"#FFB37A", "#FFC08A"}, {"#A77BFF", "#FFCF33"}, {"#9CFF57", "#FFA23A"},
        {"#F5F4F1", "#FFFFFF"}, {"#C3CDE2", "#D4D1CA"}, {"#141C36", "#1A1916"}, {"#0B1020", "#181714"},
        {"#FF7A1A", "#FF6A13"},
    };
    static const QHash<QString, QString> kawaii = {
        {"#12A58A", "#7FE3C6"}, {"#F2B32B", "#FFD96B"}, {"#E8452C", "#FF8E8E"}, {"#FBF7EF", "#FFFDF9"},
        {"#CFE0FC", "#DDEEFF"}, {"#2F6FE0", "#8FC4FF"}, {"#D9B98A", "#FFD4B5"}, {"#FCE7B0", "#FFF0BF"},
        {"#E0D7FB", "#E8E0FF"}, {"#C7F0D6", "#CDF5E8"}, {"#8A8378", "#E1C9D6"}, {"#FFFDF8", "#FFFFFF"},
        {"#E7DCC8", "#FFE0EA"}, {"#F2C75C", "#FFD978"}, {"#F9CDC3", "#FFC9D8"}, {"#2E2B27", "#4E4166"},
        {"#1F1D1A", "#5B4036"},
    };
    // 金刚的键帽是铬银色的:浅色填充再提亮一档,和键帽本身分得开;点缀色换成机身的红 / 蓝 / 琥珀 / 能量蓝。
    static const QHash<QString, QString> titan = {
        {"#2EE6F0", "#35D4FF"}, {"#FFD23F", "#FFC12E"}, {"#FF3D4E", "#FF3D4C"}, {"#8DB0FF", "#8FB0FF"},
        {"#2F6BFF", "#4C7DF0"}, {"#FFB37A", "#F2A65A"}, {"#A77BFF", "#8F7CFF"}, {"#9CFF57", "#3BE0A4"},
        {"#F5F4F1", "#F4F7FA"}, {"#C3CDE2", "#9AA6B8"}, {"#141C36", "#060A11"}, {"#0B1020", "#05070C"},
        {"#FF7A1A", "#D3232B"},
    };
    const QString key = raw.toUpper();
    if (key == QLatin1String("#FFF"))
        return QColor(0xFF, 0xFF, 0xFF);
    const auto& map = theme::titan() ? titan : (theme::mecha() ? mecha : kawaii);
    const auto it = map.constFind(key);
    return QColor::fromString(it == map.constEnd() ? raw : it.value());
}

qreal num(const QHash<QString, QString>& a, const char* k, qreal def = 0.0)
{
    const auto it = a.constFind(QLatin1String(k));
    return it == a.constEnd() ? def : it.value().toDouble();
}

QList<Item> parse(const char* snippet)
{
    static const QRegularExpression elRe(QStringLiteral(R"(<(path|rect|circle|ellipse|polygon)\b([^>]*)/>)"));
    static const QRegularExpression atRe(QStringLiteral(R"re(([a-zA-Z-]+)="([^"]*)")re"));
    QList<Item> items;
    const QString s = QString::fromLatin1(snippet);
    auto it = elRe.globalMatch(s);
    while (it.hasNext()) {
        const auto m = it.next();
        const QString tag = m.captured(1);
        QHash<QString, QString> a;
        auto at = atRe.globalMatch(m.captured(2));
        while (at.hasNext()) {
            const auto am = at.next();
            a.insert(am.captured(1), am.captured(2));
        }
        Item item;
        if (tag == QLatin1String("path")) {
            item.path = svg::path(a.value(QStringLiteral("d")));
        } else if (tag == QLatin1String("rect")) {
            const QRectF r(num(a, "x"), num(a, "y"), num(a, "width"), num(a, "height"));
            const qreal rx = num(a, "rx");
            if (rx > 0)
                item.path.addRoundedRect(r, rx, rx);
            else
                item.path.addRect(r);
        } else if (tag == QLatin1String("circle")) {
            const qreal r = num(a, "r");
            item.path.addEllipse(QPointF(num(a, "cx"), num(a, "cy")), r, r);
        } else if (tag == QLatin1String("ellipse")) {
            item.path.addEllipse(QPointF(num(a, "cx"), num(a, "cy")), num(a, "rx"), num(a, "ry"));
        } else {
            item.path.addPolygon(svg::points(a.value(QStringLiteral("points"))));
            item.path.closeSubpath();
        }
        const QString fill = a.value(QStringLiteral("fill"));
        if (fill == QLatin1String("currentColor"))
            item.fill = theme::ink();
        else if (!fill.isEmpty() && fill != QLatin1String("none"))
            item.fill = recolor(fill);
        const QString st = a.value(QStringLiteral("stroke"));
        if (st == QLatin1String("none"))
            item.noStroke = true;
        else if (!st.isEmpty())
            item.stroke = recolor(st);
        if (a.contains(QStringLiteral("stroke-width")))
            item.width = num(a, "stroke-width");
        items << item;
    }
    return items;
}

const QList<Item>* lookup(const QString& name)
{
    // 解析结果已经按皮肤着好色,每套皮肤各缓存一份。
    static QHash<QString, QList<Item>> cache[3];
    const int k = int(theme::skin());
    auto& c = cache[k];
    if (const auto it = c.constFind(name); it != c.constEnd())
        return &it.value();
    const char* src = nullptr;
    const auto find = [&](const auto& table) {
        for (const auto& row : table)
            if (name == QLatin1String(row[0]))
                return row[1];
        return static_cast<const char*>(nullptr);
    };
    src = theme::mecha() ? find(kMechaIcons) : find(kKawaiiIcons);
    if (!src)
        src = find(kMechaIcons);
    if (!src)
        return nullptr;
    return &c.insert(name, parse(src)).value();
}

// 七段数码管的段位
const char* segmentsFor(QChar ch)
{
    switch (ch.unicode()) {
    case '0': return "abcdef";
    case '1': return "bc";
    case '2': return "abged";
    case '3': return "abgcd";
    case '4': return "fgbc";
    case '5': return "afgcd";
    case '6': return "afgedc";
    case '7': return "abc";
    case '8': return "abcdefg";
    case '9': return "abcfgd";
    case '-': return "g";
    default:  return "";
    }
}

}

QRectF bodyRect(const QRectF& area, bool shadow)
{
    const QPointF so = shadow ? theme::shadowOffset() : QPointF();
    const qreal hw = theme::inkWidth() / 2.0;
    return area.adjusted(hw, hw, -hw - so.x(), -hw - so.y());
}

QRectF panel(QPainter& p, const QRectF& area, const QColor& fill, qreal corner, bool shadow, const QColor& rim)
{
    const QRectF body = bodyRect(area, shadow);
    if (body.width() < 2 || body.height() < 2)
        return body;
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    if (shadow)
        p.fillPath(theme::panelPath(body.translated(theme::shadowOffset()), corner), theme::pal().shadow);
    const QPainterPath path = theme::panelPath(body, corner);
    p.fillPath(path, fill);
    p.strokePath(path, QPen(rim.isValid() ? rim : theme::ink(), theme::inkWidth(), Qt::SolidLine, Qt::FlatCap, join()));
    if (theme::titan()) {
        // 暗色面板上硬投影几乎看不见,在上沿描一道受光线来表现厚度(两头让开切角)。
        const qreal c = qMin(corner, qMin(body.width(), body.height()) / 2.0) + 1.5;
        const qreal y = body.top() + theme::inkWidth() / 2.0 + 0.8;
        if (body.width() > 2.0 * c + 4.0) {
            p.setPen(QPen(QColor(255, 255, 255, 26), 1.0));
            p.drawLine(QPointF(body.left() + c, y), QPointF(body.right() - c, y));
        }
    }
    p.restore();
    return body;
}

void hazard(QPainter& p, const QRectF& r, const QColor& a, const QColor& b, qreal stripe, qreal offset)
{
    if (r.width() <= 0 || r.height() <= 0)
        return;
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setClipRect(r, Qt::IntersectClip);
    p.fillRect(r, b);
    const qreal h = r.height();
    const qreal period = stripe * 2;
    const qreal shift = std::fmod(std::fmod(offset, period) + period, period);
    QPainterPath stripes;
    for (qreal x = r.left() - h - period * 2 + shift; x < r.right() + stripe; x += period) {
        QPolygonF poly;
        poly << QPointF(x, r.bottom()) << QPointF(x + stripe, r.bottom()) << QPointF(x + stripe + h, r.top())
             << QPointF(x + h, r.top());
        stripes.addPolygon(poly);
        stripes.closeSubpath();
    }
    p.fillPath(stripes, a);
    p.restore();
}

void lamp(QPainter& p, const QRectF& r, const QColor& c, bool lit)
{
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    const QColor fill = lit ? c : theme::pal().border;
    const qreal w = qMax<qreal>(1.6, theme::inkWidth() * 0.9);
    if (theme::mecha()) {
        const QRectF b = r.adjusted(w / 2 + 2, w / 2, -w / 2 - 2, -w / 2);
        QTransform t;
        t.translate(b.center().x(), b.center().y());
        t.shear(-0.21, 0);
        t.translate(-b.center().x(), -b.center().y());
        QPainterPath path;
        path.addRect(b);
        path = t.map(path);
        p.fillPath(path, fill);
        p.strokePath(path, QPen(theme::ink(), w, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));
    } else {
        const qreal d = qMin(r.width(), r.height()) - w;
        const QRectF b(r.center().x() - d / 2, r.center().y() - d / 2, d, d);
        p.setPen(QPen(theme::ink(), w));
        p.setBrush(fill);
        p.drawEllipse(b);
        p.setPen(Qt::NoPen);
        p.setBrush(QColor(255, 255, 255, 150));
        p.drawEllipse(QRectF(b.left() + d * 0.22, b.top() + d * 0.2, d * 0.28, d * 0.28));
    }
    p.restore();
}

QFont headFont(qreal pt, int weight)
{
    QFont f;
    f.setFamilies({QStringLiteral("Microsoft YaHei UI"), QStringLiteral("Noto Sans SC")});
    f.setPointSizeF(pt);
    f.setWeight(QFont::Weight(weight));
    return f;
}

QFont labelFont(qreal pt)
{
    QFont f;
    if (theme::mecha())
        f.setFamilies({QStringLiteral("Bahnschrift SemiBold SemiConden"), QStringLiteral("Bahnschrift"),
                       QStringLiteral("Microsoft YaHei UI")});
    else
        f.setFamilies({QStringLiteral("Comic Sans MS"), QStringLiteral("Microsoft YaHei UI")});
    f.setPointSizeF(pt);
    f.setWeight(QFont::Bold);
    return f;
}

QSizeF stampSize(const QString& text, qreal px)
{
    QFont f = headFont(9);
    f.setPixelSize(qMax(8, qRound(px)));
    f.setLetterSpacing(QFont::AbsoluteSpacing, px * 0.12);
    const QFontMetricsF fm(f);
    return QSizeF(fm.horizontalAdvance(text) + px * 1.3, px * 1.55);
}

void stamp(QPainter& p, const QPointF& center, const QString& text, const QColor& c, qreal angle, qreal px)
{
    QFont f = headFont(9);
    f.setPixelSize(qMax(8, qRound(px)));
    f.setLetterSpacing(QFont::AbsoluteSpacing, px * 0.12);
    const QSizeF sz = stampSize(text, px);
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    p.translate(center);
    p.rotate(angle);
    const QRectF r(-sz.width() / 2, -sz.height() / 2, sz.width(), sz.height());
    const qreal bw = qMax<qreal>(2.0, px * 0.14);
    QPainterPath path;
    if (theme::mecha())
        path = theme::panelPath(r, px * 0.35);
    else
        path.addRoundedRect(r, sz.height() / 2, sz.height() / 2);
    // 浅色皮肤的钢印垫一层半透明白,像盖在纸上;金刚的卡片是暗的,白垫子会变成一块灰斑,改垫屏幕色。
    p.fillPath(path, theme::titan() ? theme::tint(theme::pal().screen, 0.6) : QColor(255, 255, 255, 150));
    p.strokePath(path, QPen(c, bw, Qt::SolidLine, Qt::FlatCap, join()));
    if (!theme::mecha()) {
        QPainterPath inner;
        inner.addRoundedRect(r.adjusted(bw * 1.4, bw * 1.4, -bw * 1.4, -bw * 1.4), sz.height() / 2, sz.height() / 2);
        p.strokePath(inner, QPen(theme::tint(c, 0.45), bw * 0.5));
    }
    p.setFont(f);
    p.setPen(c);
    p.drawText(r.adjusted(0, -px * 0.04, 0, 0), Qt::AlignCenter, text);
    p.restore();
}

qreal dymoWidth(const QString& text, qreal px)
{
    QFont f = headFont(9, 800);
    f.setPixelSize(qMax(8, qRound(px)));
    return QFontMetricsF(f).horizontalAdvance(text) + px * 2.0;
}

void dymo(QPainter& p, const QRectF& r, const QString& text, const QColor& bg, const QColor& fg)
{
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    const qreal px = r.height() * 0.5;
    QPainterPath path;
    if (theme::mecha()) {
        path.addRect(r);
    } else {
        // 卡哇伊:锯齿边的贴纸胶带
        const int n = 6;
        const qreal step = r.height() / n;
        path.moveTo(r.left() + 3, r.top());
        path.lineTo(r.right() - 3, r.top());
        for (int i = 1; i <= n; ++i)
            path.lineTo(r.right() - (i % 2 ? 0 : 3), r.top() + step * i);
        path.lineTo(r.left() + 3, r.bottom());
        for (int i = n - 1; i >= 0; --i)
            path.lineTo(r.left() + (i % 2 ? 0 : 3), r.top() + step * i);
        path.closeSubpath();
    }
    p.fillPath(path, bg);
    if (theme::mecha()) {
        p.fillRect(QRectF(r.left() + px * 0.55, r.top() + r.height() * 0.24, 3, r.height() * 0.52), theme::tint(fg, 0.7));
    } else {
        p.save();
        p.setClipPath(path);
        p.setPen(Qt::NoPen);
        p.setBrush(QColor(255, 255, 255, 170));
        for (qreal y = r.top() + 4; y < r.bottom(); y += 9)
            for (qreal x = r.left() + 5 + (int(y) % 2) * 4; x < r.right(); x += 9)
                p.drawEllipse(QPointF(x, y), 1.6, 1.6);
        p.restore();
    }
    QFont f = headFont(9, 800);
    f.setPixelSize(qMax(8, qRound(px)));
    p.setFont(f);
    p.setPen(fg);
    p.drawText(r.adjusted(theme::mecha() ? px * 1.2 : px * 0.6, 0, -px * 0.6, 0), Qt::AlignVCenter | Qt::AlignLeft, text);
    p.restore();
}

namespace {

QPainterPath textPath(const QString& text, qreal px)
{
    QFont f = headFont(10);
    f.setPixelSize(qMax(6, qRound(px)));
    f.setLetterSpacing(QFont::AbsoluteSpacing, px * (theme::mecha() ? 0.03 : 0.04));
    QPainterPath t;
    t.addText(0, 0, f, text);
    if (theme::mecha()) {
        QTransform sk(1, 0, std::tan(qDegreesToRadians(-9.0)), 1, 0, 0);
        t = sk.map(t);
    }
    return t;
}

qreal padFor(qreal px) { return px * 0.26; }

}

QSizeF stickerTextSize(const QString& text, qreal px)
{
    const QRectF b = textPath(text, px).boundingRect();
    const qreal pad = padFor(px);
    return QSizeF(b.width() + pad * 2 + px * 0.1, b.height() + pad * 2 + px * 0.12);
}

void stickerText(QPainter& p, const QPointF& topLeft, const QString& text, qreal px, const QColor& fillC, bool shadow)
{
    TextStyle s;
    s.fill = fillC;
    s.shadow = shadow;
    stickerText(p, topLeft, text, px, s);
}

void stickerText(QPainter& p, const QPointF& topLeft, const QString& text, qreal px, const TextStyle& style)
{
    QPainterPath t = textPath(text, px);
    const QRectF b = t.boundingRect();
    const qreal pad = padFor(px);
    t.translate(topLeft.x() + pad - b.left(), topLeft.y() + pad - b.top());
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    const auto layer = [&](const QPainterPath& path, const QColor& c, qreal w) {
        QPen pen(c, w, Qt::SolidLine, Qt::RoundCap, theme::mecha() ? Qt::MiterJoin : Qt::RoundJoin);
        pen.setMiterLimit(2.0);
        p.strokePath(path, pen);
        p.fillPath(path, c);
    };
    const auto pick = [](const QColor& c, const QColor& def) { return c.isValid() ? c : def; };
    if (theme::mecha()) {
        if (style.shadow)
            layer(t.translated(px * 0.08, px * 0.08), pick(style.shade, theme::pal().accent), px * 0.3);
        layer(t, pick(style.out, theme::ink()), px * 0.3);
        layer(t, pick(style.mid, theme::pal().structure), px * 0.16);
        layer(t, pick(style.fill, QColor(0xFF, 0xFF, 0xFF)), px * 0.02);
    } else {
        if (style.shadow)
            layer(t.translated(0, px * 0.09), pick(style.shade, QColor(214, 150, 170, 115)), px * 0.36);
        layer(t, pick(style.out, theme::ink()), px * 0.3);
        layer(t, pick(style.mid, QColor(0xFF, 0xFF, 0xFF)), px * 0.17);
        layer(t, pick(style.fill, hexc("#FFB8CB")), px * 0.05);
    }
    p.restore();
}

TextStyle screenTextStyle()
{
    TextStyle s;
    const theme::Palette& P = theme::pal();
    if (theme::mecha()) {
        s.fill = P.glow;
        s.mid = P.ink;
        s.out = P.glow;
        s.shade = P.structure;
    } else {
        s.fill = P.glow;
        s.mid = QColor(0xFF, 0xFF, 0xFF);
        s.out = P.ink;
        s.shade = QColor(0x2E, 0x24, 0x40);
    }
    return s;
}

void sevenSeg(QPainter& p, const QRectF& r, const QString& digits, const QColor& on, const QColor& off,
              int redLast, const QColor& red, qreal glow)
{
    const int n = int(digits.size());
    if (n == 0)
        return;
    const qreal gap = r.width() * 0.04;
    const qreal dw = (r.width() - gap * (n - 1)) / n;
    const qreal dh = r.height();
    const qreal t = qMax<qreal>(2.0, dw * 0.17);
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    const qreal skew = theme::mecha() ? -0.08 : 0.0;
    for (int i = 0; i < n; ++i) {
        const qreal x0 = r.left() + i * (dw + gap);
        const qreal y0 = r.top();
        const QString lit = QString::fromLatin1(segmentsFor(digits[i]));
        const QColor col = (redLast > 0 && i >= n - redLast && red.isValid()) ? red : on;
        const auto seg = [&](char s) -> QPolygonF {
            const qreal L = x0 + t * 0.5, R = x0 + dw - t * 0.5;
            const qreal T = y0 + t * 0.5, M = y0 + dh / 2, B = y0 + dh - t * 0.5;
            const qreal h = t / 2, in = 0.6;
            const auto horiz = [&](qreal y) {
                return QPolygonF({QPointF(L + in, y), QPointF(L + h + in, y - h), QPointF(R - h - in, y - h),
                                  QPointF(R - in, y), QPointF(R - h - in, y + h), QPointF(L + h + in, y + h)});
            };
            const auto vert = [&](qreal x, qreal ya, qreal yb) {
                return QPolygonF({QPointF(x, ya + in), QPointF(x + h, ya + h + in), QPointF(x + h, yb - h - in),
                                  QPointF(x, yb - in), QPointF(x - h, yb - h - in), QPointF(x - h, ya + h + in)});
            };
            switch (s) {
            case 'a': return horiz(T);
            case 'g': return horiz(M);
            case 'd': return horiz(B);
            case 'f': return vert(L, T, M);
            case 'b': return vert(R, T, M);
            case 'e': return vert(L, M, B);
            case 'c': return vert(R, M, B);
            default:  return {};
            }
        };
        QTransform sk;
        sk.translate(x0 + dw / 2, y0 + dh / 2);
        sk.shear(skew, 0);
        sk.translate(-(x0 + dw / 2), -(y0 + dh / 2));
        for (const char s : {'a', 'b', 'c', 'd', 'e', 'f', 'g'}) {
            QPainterPath path;
            path.addPolygon(sk.map(seg(s)));
            path.closeSubpath();
            if (!lit.contains(QLatin1Char(s))) {
                p.fillPath(path, off);
                continue;
            }
            if (glow > 0.01) {
                // 数值刚变化:亮段外圈泛光、本体更亮,随后褪回常亮。
                p.strokePath(path, QPen(theme::tint(col, 0.55 * glow), t * 0.9, Qt::SolidLine, Qt::RoundCap,
                                        Qt::RoundJoin));
                p.fillPath(path, col.lighter(100 + int(45 * glow)));
            } else {
                p.fillPath(path, col);
            }
        }
    }
    p.restore();
}

bool hasIcon(const QString& name) { return lookup(name) != nullptr; }

void icon(QPainter& p, const QString& name, const QRectF& r, qreal strokeWidth)
{
    const QList<Item>* items = lookup(name);
    if (!items)
        return;
    const qreal s = qMin(r.width(), r.height()) / 24.0;
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    p.translate(r.center().x() - 12 * s, r.center().y() - 12 * s);
    p.scale(s, s);
    const QColor ink = theme::ink();
    for (const Item& it : *items) {
        if (it.fill.isValid())
            p.fillPath(it.path, it.fill);
        if (!it.noStroke)
            p.strokePath(it.path, QPen(it.stroke.isValid() ? it.stroke : ink, it.width > 0 ? it.width : strokeWidth,
                                       Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    }
    p.restore();
}

QPolygonF hexagon(const QPointF& c, qreal r)
{
    QPolygonF out;
    for (int i = 0; i < 6; ++i) {
        const qreal a = M_PI / 3.0 * i - M_PI / 2.0;
        out << QPointF(c.x() + r * std::cos(a), c.y() + r * std::sin(a));
    }
    return out;
}

}

StickerText::StickerText(const QString& text, qreal px, QWidget* parent)
    : QWidget(parent), m_text(text), m_px(px)
{
    setAttribute(Qt::WA_TranslucentBackground);
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
}

void StickerText::setText(const QString& text)
{
    if (text == m_text)
        return;
    m_text = text;
    updateGeometry();
    update();
}

void StickerText::setFill(const QColor& c)
{
    m_style.fill = c;
    update();
}

void StickerText::setShadow(bool on)
{
    m_style.shadow = on;
    update();
}

void StickerText::setTextStyle(const sticker::TextStyle& style)
{
    m_style = style;
    update();
}

QSize StickerText::sizeHint() const
{
    return sticker::stickerTextSize(m_text, m_px).toSize() + QSize(2, 2);
}

void StickerText::pop()
{
    if (!motion::enabled() || !motion::onScreen(this))
        return;
    if (!m_pop) {
        m_pop = new QVariantAnimation(this);
        m_pop->setStartValue(0.0);
        m_pop->setEndValue(1.0);
        connect(m_pop, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
            m_popT = v.toReal();
            update();
        });
    }
    m_pop->stop();
    m_pop->setDuration(420);
    m_pop->start();
}

void StickerText::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    if (m_popT < 1.0) {
        const qreal s = 0.6 + 0.4 * motion::outBack(m_popT);
        const QPointF c = QRectF(rect()).center();
        p.translate(c);
        p.scale(s, s);
        p.translate(-c);
        p.setOpacity(qMin<qreal>(1.0, 0.25 + m_popT * 2.5));
    }
    sticker::stickerText(p, QPointF(0, 0), m_text, m_px, m_style);
}

SevenSegCounter::SevenSegCounter(int digits, int digitW, int digitH, QWidget* parent)
    : QWidget(parent), m_digits(digits), m_dw(digitW), m_dh(digitH)
{
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
}

void SevenSegCounter::setValue(qint64 v)
{
    if (v == m_value)
        return;
    const qint64 from = m_shown;
    m_value = v;
    if (!motion::enabled() || !motion::onScreen(this)) {
        if (m_roll)
            m_roll->stop();
        m_shown = v;
        update();
        return;
    }
    if (!m_roll) {
        m_roll = new QVariantAnimation(this);
        m_roll->setEasingCurve(QEasingCurve::OutCubic);
        connect(m_roll, &QVariantAnimation::valueChanged, this, [this](const QVariant& x) {
            m_shown = qint64(std::llround(x.toDouble()));
            update();
        });
        m_flashAnim = new QVariantAnimation(this);
        m_flashAnim->setStartValue(1.0);
        m_flashAnim->setEndValue(0.0);
        m_flashAnim->setEasingCurve(QEasingCurve::InQuad);
        connect(m_flashAnim, &QVariantAnimation::valueChanged, this, [this](const QVariant& x) {
            m_flash = x.toReal();
            update();
        });
    }
    // 跳得越多滚得越久,但不至于让人等。
    const double magnitude = std::log10(double(qAbs(v - from)) + 1.0);
    m_roll->stop();
    m_roll->setDuration(qBound(320, 260 + int(magnitude * 160.0), 760));
    m_roll->setStartValue(double(from));
    m_roll->setEndValue(double(v));
    m_roll->start();
    m_flashAnim->stop();
    m_flashAnim->setDuration(m_roll->duration() + 520);
    m_flashAnim->start();
}

void SevenSegCounter::setRedLast(bool on)
{
    m_redLast = on;
    update();
}

void SevenSegCounter::setColor(const QColor& c)
{
    m_color = c;
    update();
}

namespace {

// 金刚数码管的字形(设计稿 seg7):字宽 0.56h、笔粗 0.13h、字距 0.24h,矩形笔段。
struct TitanSeg {
    qreal w, t, gap;
    explicit TitanSeg(qreal h)
        : w(qRound(h * 0.56)), t(qMax<qreal>(2.0, qRound(h * 0.13))), gap(qRound(h * 0.24)) {}
};

// 切角板:上两角切 c,下两角切 s。
QPainterPath titanPlate(const QRectF& r, qreal c, qreal s)
{
    QPainterPath path;
    path.moveTo(r.left() + c, r.top());
    path.lineTo(r.right() - c, r.top());
    path.lineTo(r.right(), r.top() + c);
    path.lineTo(r.right(), r.bottom() - s);
    path.lineTo(r.right() - s, r.bottom());
    path.lineTo(r.left() + s, r.bottom());
    path.lineTo(r.left(), r.bottom() - s);
    path.lineTo(r.left(), r.top() + c);
    path.closeSubpath();
    return path;
}

}

QSize SevenSegCounter::sizeHint() const
{
    if (theme::titan()) {
        // 屏框内边距 上 6 / 右 8 / 下 5 / 左 10,字串两侧各留 3px 给斜体。
        const TitanSeg g(m_dh);
        return QSize(qRound(m_digits * (g.w + g.gap) - g.gap) + 24, m_dh + 11);
    }
    return QSize(m_digits * (m_dw + 4) + 14, m_dh + 12);
}

void SevenSegCounter::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    const bool m = theme::mecha();
    const bool t = theme::titan();
    if (t) {
        // 金刚:切角屏框(2px 墨线);笔段整体右斜 7°,暗位 = 本色 9%,亮段外圈泛光。
        const QRectF r(rect());
        p.fillPath(titanPlate(r, 5.0, 2.0), theme::ink());
        p.fillPath(titanPlate(r.adjusted(2, 2, -2, -2), 5.0 - 2.0 * 0.586, 2.0 - 2.0 * 0.586), theme::pal().screen);
        QString text = QString::number(qMax<qint64>(0, m_shown));
        if (text.size() > m_digits)
            text = QString(m_digits, QLatin1Char('9'));
        const QString all = QString(m_digits - int(text.size()), QLatin1Char(' ')) + text;
        const QColor base = m_color.isValid() ? m_color : theme::glow();
        const QColor red(0xFF, 0x4A, 0x4A);
        const TitanSeg g(m_dh);
        const qreal h = m_dh;
        const qreal half = (h - 3.0 * g.t) / 2.0;
        const QTransform sk(1, 0, std::tan(qDegreesToRadians(-7.0)), 1, 13.0, 6.0);
        QPainterPath offPath;
        QPainterPath litPath[2];
        for (int i = 0; i < m_digits; ++i) {
            const qreal x = i * (g.w + g.gap);
            const QString lit = QString::fromLatin1(sticker::segmentsFor(all.at(i)));
            const bool isRed = m_redLast && i == m_digits - 1;
            const auto bar = [&](char s, qreal bx, qreal by, qreal bw, qreal bh) {
                QPainterPath path;
                path.addRect(QRectF(x + bx, by, bw, bh));
                (lit.contains(QLatin1Char(s)) ? litPath[isRed ? 1 : 0] : offPath).addPath(sk.map(path));
            };
            bar('a', g.t, 0.0, g.w - 2.0 * g.t, g.t);
            bar('g', g.t, (h - g.t) / 2.0, g.w - 2.0 * g.t, g.t);
            bar('d', g.t, h - g.t, g.w - 2.0 * g.t, g.t);
            bar('f', 0.0, g.t, g.t, half);
            bar('b', g.w - g.t, g.t, g.t, half);
            bar('e', 0.0, (h + g.t) / 2.0, g.t, half);
            bar('c', g.w - g.t, (h + g.t) / 2.0, g.t, half);
        }
        p.fillPath(offPath, theme::tint(base, 0.09));
        for (int k = 0; k < 2; ++k) {
            if (litPath[k].isEmpty())
                continue;
            const QColor col = k == 1 ? red : base;
            const qreal glow = 1.0 + 1.5 * m_flash;
            p.strokePath(litPath[k], QPen(theme::tint(col, qMin<qreal>(1.0, 0.08 * glow)), 6.0, Qt::SolidLine,
                                          Qt::RoundCap, Qt::RoundJoin));
            p.strokePath(litPath[k], QPen(theme::tint(col, qMin<qreal>(1.0, 0.16 * glow)), 3.0, Qt::SolidLine,
                                          Qt::RoundCap, Qt::RoundJoin));
            p.fillPath(litPath[k], m_flash > 0.01 ? col.lighter(100 + int(45 * m_flash)) : col);
        }
        return;
    }
    const QRectF r = QRectF(rect()).adjusted(1, 1, -1, -1);
    const QColor bezel = t ? theme::pal().screen : m ? QColor(0x12, 0x11, 0x0E) : QColor(0xD3, 0xF7, 0xEB);
    QPainterPath frame;
    if (m)
        frame.addRect(r);
    else
        frame.addRoundedRect(r, 8, 8);
    p.fillPath(frame, bezel);
    p.strokePath(frame, QPen(theme::ink(), 2.0));
    QString text = QString::number(qMax<qint64>(0, m_shown));
    if (text.size() > m_digits)
        text = QString(m_digits, QLatin1Char('9'));
    const int lead = m_digits - int(text.size());
    const QColor on = m_color.isValid() ? m_color : (m ? theme::glow() : QColor(0x2E, 0x6B, 0x59));
    const QColor off = t ? QColor(0x1C, 0x27, 0x40) : m ? QColor(0x28, 0x27, 0x24) : QColor(0xBF, 0xEB, 0xDD);
    const QColor red = m ? QColor(0xFF, 0x4A, 0x4A) : QColor(0xF0, 0x60, 0x6C);
    const QRectF dr = r.adjusted(7, 5, -7, -5);
    // 前导暗位画成全暗的「8」,和真数码管一样能看出位数。
    QString all = QString(lead, QLatin1Char(' ')) + text;
    sticker::sevenSeg(p, dr, all, on, off, m_redLast ? 1 : 0, red, m_flash);
}

StampLabel::StampLabel(const QString& text, const QColor& color, qreal angle, qreal px, QWidget* parent)
    : QWidget(parent), m_text(text), m_color(color), m_angle(angle), m_px(px)
{
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    setAttribute(Qt::WA_TransparentForMouseEvents);
}

void StampLabel::setStamp(const QString& text, const QColor& color)
{
    m_text = text;
    m_color = color;
    updateGeometry();
    update();
}

void StampLabel::setOverscan(qreal k)
{
    m_overscan = qMax<qreal>(1.0, k);
    updateGeometry();
    update();
}

void StampLabel::slam(int delayMs, std::function<void()> onImpact, QPointF from)
{
    m_onImpact = std::move(onImpact);
    m_slamFrom = from;
    if (!motion::enabled()) {
        m_slamT = 1.0;
        m_impacted = true;
        update();
        return;
    }
    if (!m_slam) {
        m_slam = new QVariantAnimation(this);
        m_slam->setStartValue(0.0);
        m_slam->setEndValue(1.0);
        m_slam->setDuration(460);
        connect(m_slam, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
            m_slamT = v.toReal();
            if (!m_impacted && m_slamT >= 0.5) {
                m_impacted = true;
                if (m_onImpact)
                    m_onImpact();
            }
            update();
        });
    }
    m_slam->stop();
    m_slamT = 0.0;
    m_impacted = false;
    update();
    QTimer::singleShot(qMax(0, delayMs), this, [this] {
        if (m_slam && m_slamT == 0.0)
            m_slam->start();
    });
}

QSize StampLabel::sizeHint() const
{
    const QSizeF s = sticker::stampSize(m_text, m_px);
    // 旋转后的外接框
    const qreal a = qDegreesToRadians(std::abs(m_angle));
    const qreal w = s.width() * std::cos(a) + s.height() * std::sin(a) + 6;
    const qreal h = s.width() * std::sin(a) + s.height() * std::cos(a) + 6;
    return QSize(int(w * m_overscan), int(h * m_overscan));
}

void StampLabel::paintEvent(QPaintEvent*)
{
    if (m_text.isEmpty() || m_slamT <= 0.0)
        return;
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    const QPointF c = QRectF(rect()).center();
    if (m_slamT >= 1.0) {
        sticker::stamp(p, c, m_text, m_color, m_angle, m_px);
        return;
    }
    // 前半程从 1.55 倍砸下(加速),落地后轻微回弹;落地瞬间一圈冲击波向外散开。
    const qreal t = m_slamT;
    constexpr qreal kHit = 0.5;
    const qreal fall = t < kHit ? motion::inCubic(t / kHit) : 1.0;
    const qreal s = t < kHit ? 1.55 - 0.63 * fall : 0.92 + 0.08 * motion::outBack((t - kHit) / (1.0 - kHit));
    const qreal spin = (1.0 - fall) * 16.0;
    const QPointF drift = m_slamFrom * (1.0 - fall);
    if (t > kHit) {
        const qreal k = (t - kHit) / (1.0 - kHit);
        const QSizeF ss = sticker::stampSize(m_text, m_px) * (1.0 + 0.55 * motion::outCubic(k));
        p.save();
        p.translate(c);
        p.rotate(m_angle);
        p.setPen(QPen(theme::tint(m_color, 0.55 * (1.0 - k)), 2.6 * (1.0 - k) + 0.6));
        p.setBrush(Qt::NoBrush);
        p.drawRoundedRect(QRectF(-ss.width() / 2, -ss.height() / 2, ss.width(), ss.height()), 6, 6);
        p.restore();
    }
    p.save();
    p.setOpacity(qMin<qreal>(1.0, t / 0.22));
    p.translate(c + drift);
    p.scale(s, s);
    p.translate(-c);
    sticker::stamp(p, c, m_text, m_color, m_angle + spin, m_px);
    p.restore();
}

LampWidget::LampWidget(const QColor& c, int w, int h, QWidget* parent)
    : QWidget(parent), m_color(c), m_w(w), m_h(h)
{
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    setAttribute(Qt::WA_TransparentForMouseEvents);
}

void LampWidget::setColor(const QColor& c)
{
    m_color = c;
    update();
}

void LampWidget::setLit(bool lit)
{
    m_lit = lit;
    update();
}

void LampWidget::setBlink(bool on)
{
    on = on && motion::enabled();
    if (on == m_blinkOn)
        return;
    m_blinkOn = on;
    if (on && !m_blink) {
        m_blink = new QTimer(this);
        m_blink->setInterval(520);
        connect(m_blink, &QTimer::timeout, this, [this] {
            m_blinkDark = !m_blinkDark;
            update();
        });
    }
    m_blinkDark = false;
    if (m_blink) {
        if (on && isVisible())
            m_blink->start();
        else
            m_blink->stop();
    }
    update();
}

void LampWidget::showEvent(QShowEvent* e)
{
    QWidget::showEvent(e);
    if (m_blinkOn && m_blink)
        m_blink->start();
}

void LampWidget::hideEvent(QHideEvent* e)
{
    QWidget::hideEvent(e);
    if (m_blink)
        m_blink->stop();
    m_blinkDark = false;
}

void LampWidget::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    sticker::lamp(p, QRectF(1, 1, m_w, m_h), m_color, m_lit && !m_blinkDark);
}
