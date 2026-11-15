#include "design/Skin.h"

#include <QSettings>

#include <cmath>

namespace theme {
namespace {

QColor c(const char* hex) { return QColor::fromString(QLatin1StringView(hex)); }

Palette mechaPalette()
{
    Palette p;
    p.bg = c("#E6E4DF");
    p.surface = c("#F7F6F3");
    p.surfaceTop = c("#FBFAF8");
    p.surfaceAlt = c("#ECEAE5");
    p.surfaceHi = c("#E2DFD8");
    p.raised = c("#FBFAF8");
    p.field = c("#FFFFFF");
    p.border = c("#D4D1CA");
    p.borderStrong = c("#A9A69F");
    p.borderLit = c("#C9C5BD");
    p.text = c("#181714");
    p.textSecondary = c("#4B4A47");
    p.textMuted = c("#75736E");
    p.textDisabled = c("#ADAAA3");
    p.accent = c("#FF6A13");
    p.accentSoft = c("#FFB27A");
    p.accentStrong = c("#FF6A13");
    p.accentDeep = c("#D9520A");
    p.accentAlt = c("#FFA23A");
    p.accentInk = c("#FFFFFF");
    p.brass = c("#FFA23A");
    p.brassDeep = c("#C77712");
    p.success = c("#5A5853");
    p.warning = c("#C28A00");
    p.danger = c("#DC2F33");
    p.info = c("#B8680C");
    p.violet = c("#FF6A13");
    p.purple = c("#C77712");
    p.sky = c("#8C877D");
    p.cyan = c("#FFA23A");
    p.teal = c("#E0861A");
    p.amber = c("#FFCF33");
    p.pink = c("#FF8A5B");
    p.olive = c("#A59A6A");
    p.periwinkle = c("#B5AC9F");
    p.ink = c("#181714");
    p.shadow = c("#181714");
    p.shell = c("#E6E4DF");
    p.structure = c("#33322F");
    p.structureHi = c("#FF8A3D");
    p.fin = c("#FF6A13");
    p.screen = c("#1A1916");
    p.screen2 = c("#252421");
    p.scrText = c("#F1EEE8");
    p.scrText2 = c("#C9C5BD");
    p.scrMuted = c("#8A8880");
    p.glow = c("#FFA23A");
    p.hazardA = c("#FFCF33");
    p.hazardB = c("#181714");
    p.menuSel = c("#FF6A13");
    p.menuSelText = c("#FFFFFF");
    p.blush = c("#FF6A13");
    return p;
}

Palette kawaiiPalette()
{
    Palette p;
    p.bg = c("#FFF1F5");
    p.surface = c("#FFFDF9");
    p.surfaceTop = c("#FFFFFF");
    p.surfaceAlt = c("#FFF0F3");
    p.surfaceHi = c("#FFDCE6");
    p.raised = c("#FFFDF9");
    p.field = c("#FFFFFF");
    p.border = c("#EBD9D6");
    p.borderStrong = c("#D8BEB8");
    p.borderLit = c("#F2DCD8");
    p.text = c("#5B4036");
    p.textSecondary = c("#8A6B5E");
    p.textMuted = c("#A08A82");
    p.textDisabled = c("#CDBDB7");
    p.accent = c("#F78DA9");
    p.accentSoft = c("#FFB8CB");
    p.accentStrong = c("#F78DA9");
    p.accentDeep = c("#E8708F");
    p.accentAlt = c("#B9A6FF");
    p.accentInk = c("#FFFFFF");
    p.brass = c("#FFD96B");
    p.brassDeep = c("#E9AE2C");
    p.success = c("#2F9E7E");
    p.warning = c("#C98A12");
    p.danger = c("#E8505E");
    p.info = c("#8C73EA");
    p.violet = c("#B9A6FF");
    p.purple = c("#D69BEA");
    p.sky = c("#8FC4FF");
    p.cyan = c("#7FE3C6");
    p.teal = c("#6FDDBE");
    p.amber = c("#FFD96B");
    p.pink = c("#FFB8CB");
    p.olive = c("#BFD98A");
    p.periwinkle = c("#A9B8FF");
    p.ink = c("#5B4036");
    p.shadow = c("#F2C4D1");
    p.shell = c("#FFFDF9");
    p.structure = c("#FFB8CB");
    p.structureHi = c("#FFDCE6");
    p.fin = c("#6FDDBE");
    p.screen = c("#4E4166");
    p.screen2 = c("#5F5180");
    p.scrText = c("#F6EEFF");
    p.scrText2 = c("#DCCFF0");
    p.scrMuted = c("#A99BC4");
    p.glow = c("#8FF5D6");
    p.hazardA = c("#FFB3B8");
    p.hazardB = c("#FFFFFF");
    p.menuSel = c("#FFDCE6");
    p.menuSelText = c("#5B4036");
    p.blush = c("#FF96B2");
    return p;
}

// 金刚:机身是装甲红 / 钴蓝 / 铬银,内容区是暗色屏。accent 是亮一档的钴蓝,放在暗面板上当前景也看得清;
// accentDeep 在浅色皮肤里是「深一档、用来写字」的那个色,暗底上要反过来取更亮的蓝。
Palette titanPalette()
{
    Palette p;
    p.bg = c("#090D15");
    p.surface = c("#131A27");
    p.surfaceTop = c("#182132");
    p.surfaceAlt = c("#0E141F");
    p.surfaceHi = c("#1F2A40");
    p.raised = c("#1A2336");
    p.field = c("#0B1018");
    p.border = c("#26314A");
    p.borderStrong = c("#3B4965");
    p.borderLit = c("#586B8F");
    p.text = c("#EAF0FA");
    p.textSecondary = c("#B3C0D6");
    p.textMuted = c("#7D8DA8");
    p.textDisabled = c("#4B5870");
    p.accent = c("#3A74F0");
    p.accentSoft = c("#8FB0FF");
    p.accentStrong = c("#3A74F0");
    p.accentDeep = c("#6E9BFF");
    p.accentAlt = c("#35D4FF");
    p.accentInk = c("#FFFFFF");
    p.brass = c("#FFC12E");
    p.brassDeep = c("#C48600");
    p.success = c("#3BE0A4");
    p.warning = c("#FFB42E");
    p.danger = c("#FF3D4C");
    p.info = c("#6FA8FF");
    p.violet = c("#7C6CFF");
    p.purple = c("#9C5CFF");
    p.sky = c("#6FA8FF");
    p.cyan = c("#35D4FF");
    p.teal = c("#2ED3B7");
    p.amber = c("#FFC12E");
    p.pink = c("#FF7AB8");
    p.olive = c("#8BD96A");
    p.periwinkle = c("#8FA6FF");
    p.ink = c("#05070C");
    p.shadow = c("#000000");
    p.shell = c("#D3232B");
    p.structure = c("#2459D8");
    p.structureHi = c("#5F8DFA");
    p.fin = c("#C6CFDA");
    p.screen = c("#060A11");
    p.screen2 = c("#0C1320");
    p.scrText = c("#DCEBFF");
    p.scrText2 = c("#9FB6D6");
    p.scrMuted = c("#5D7393");
    p.glow = c("#35D4FF");
    p.hazardA = c("#FFC12E");
    p.hazardB = c("#05070C");
    p.menuSel = c("#2459D8");
    p.menuSelText = c("#FFFFFF");
    p.blush = c("#35D4FF");
    return p;
}

Skin g_skin = Skin::Mecha;

Palette& active()
{
    static Palette p = mechaPalette();
    return p;
}

const QString kSkinKey = QStringLiteral("ui/skin");

}

Skin skin() { return g_skin; }
bool mecha() { return g_skin != Skin::Kawaii; }
bool titan() { return g_skin == Skin::Titan; }
const Palette& pal() { return active(); }

void setSkin(Skin s)
{
    g_skin = s;
    switch (s) {
    case Skin::Mecha:  active() = mechaPalette(); break;
    case Skin::Kawaii: active() = kawaiiPalette(); break;
    case Skin::Titan:  active() = titanPalette(); break;
    }
}

QString skinKey(Skin s)
{
    switch (s) {
    case Skin::Kawaii: return QStringLiteral("kawaii");
    case Skin::Titan:  return QStringLiteral("titan");
    case Skin::Mecha:  break;
    }
    return QStringLiteral("mecha");
}

QString skinName(Skin s)
{
    switch (s) {
    case Skin::Kawaii: return QString::fromUtf8("卡哇伊");
    case Skin::Titan:  return QString::fromUtf8("金刚");
    case Skin::Mecha:  break;
    }
    return QString::fromUtf8("机甲");
}

Skin skinFromKey(const QString& key, Skin fallback)
{
    if (key == QLatin1String("kawaii"))
        return Skin::Kawaii;
    if (key == QLatin1String("titan"))
        return Skin::Titan;
    if (key == QLatin1String("mecha"))
        return Skin::Mecha;
    return fallback;
}

Skin savedSkin() { return skinFromKey(QSettings().value(kSkinKey).toString()); }

void saveSkin(Skin s) { QSettings().setValue(kSkinKey, skinKey(s)); }

QPainterPath panelPath(const QRectF& r, qreal size)
{
    QPainterPath path;
    if (g_skin == Skin::Kawaii) {
        const qreal rr = qMin(size * 1.35, qMin(r.width(), r.height()) / 2.0);
        path.addRoundedRect(r, rr, rr);
        return path;
    }
    const qreal lim = qMin(r.width(), r.height()) / 2.0;
    const qreal big = qMin(size, lim);
    const qreal small = qMin(size * 0.3, lim);
    if (g_skin == Skin::Titan) {
        path.moveTo(r.left() + big, r.top());
        path.lineTo(r.right() - big, r.top());
        path.lineTo(r.right(), r.top() + big);
        path.lineTo(r.right(), r.bottom() - small);
        path.lineTo(r.right() - small, r.bottom());
        path.lineTo(r.left() + small, r.bottom());
        path.lineTo(r.left(), r.bottom() - small);
        path.lineTo(r.left(), r.top() + big);
        path.closeSubpath();
        return path;
    }
    path.moveTo(r.left() + big, r.top());
    path.lineTo(r.right() - small, r.top());
    path.lineTo(r.right(), r.top() + small);
    path.lineTo(r.right(), r.bottom() - big);
    path.lineTo(r.right() - big, r.bottom());
    path.lineTo(r.left() + small, r.bottom());
    path.lineTo(r.left(), r.bottom() - small);
    path.lineTo(r.left(), r.top() + big);
    path.closeSubpath();
    return path;
}

qreal inkWidth() { return g_skin == Skin::Kawaii ? 2.2 : 2.0; }

QColor textOn(const QColor& bg)
{
    const auto lin = [](qreal v) { return v <= 0.04045 ? v / 12.92 : std::pow((v + 0.055) / 1.055, 2.4); };
    const qreal l = 0.2126 * lin(bg.redF()) + 0.7152 * lin(bg.greenF()) + 0.0722 * lin(bg.blueF());
    return l > 0.40 ? active().ink : QColor(0xFF, 0xFF, 0xFF);
}

QPointF shadowOffset() { return g_skin == Skin::Kawaii ? QPointF(0, 5) : QPointF(0, 4); }

SkinHub* SkinHub::instance()
{
    static SkinHub* hub = new SkinHub;
    return hub;
}

}
