#include "design/Theme.h"
#include "design/Icons.h"
#include "design/Motion.h"
#include "design/Ripple.h"

#include <QApplication>
#include <QDir>
#include <QEvent>
#include <QFont>
#include <QGuiApplication>
#include <QHash>
#include <QImage>
#include <QPainter>
#include <QPalette>
#include <QPixmap>
#include <QRandomGenerator>
#include <QStyle>
#include <QStyleFactory>
#include <QStyleHints>
#include <QTemporaryDir>
#include <QToolTip>
#include <QWidget>

#include <initializer_list>
#include <memory>
#include <utility>

#ifdef Q_OS_WIN
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <dwmapi.h>
#endif

namespace theme {
namespace {

QString glyphRoot()
{
    static std::unique_ptr<QTemporaryDir> dir;
    static QString path;
    if (dir)
        return path;
    dir = std::make_unique<QTemporaryDir>(QDir::tempPath() + QStringLiteral("/bulwark-ui-XXXXXX"));
    if (dir->isValid())
        path = QDir::fromNativeSeparators(dir->path());
    return path;
}

// 样式表里的箭头 / 勾选图片按皮肤分目录生成:Qt 按 URL 缓存图片,同名文件换色不会生效。
QString glyphDir()
{
    const QString root = glyphRoot();
    if (root.isEmpty())
        return root;
    const QString path = root + QLatin1Char('/') + skinKey(skin());
    if (QDir(path).exists())
        return path;
    QDir().mkpath(path);

    struct Glyph {
        const char* file;
        const char* icon;
        QColor color;
        int px;
        qreal inset;
        qreal pen;
    };
    // 下拉箭头画在输入框里:浅色皮肤用墨色,金刚的输入框是暗的,改用次要文字色。
    const QColor arrow = titan() ? textSecondary() : ink();
    const Glyph glyphs[] = {
        {"chevron-down.png",          "chevron-down", arrow,           36, 2.0, 4.0},
        {"chevron-down-disabled.png", "chevron-down", textDisabled(),  36, 2.0, 4.0},
        {"chevron-up.png",            "chevron-up",   arrow,           36, 2.0, 4.0},
        {"chevron-up-disabled.png",   "chevron-up",   textDisabled(),  36, 2.0, 4.0},
        {"sort-down.png",             "chevron-down", textSecondary(), 36, 2.0, 4.0},
        {"sort-up.png",               "chevron-up",   textSecondary(), 36, 2.0, 4.0},
        {"check.png",                 "check",        mecha() ? accentInk() : ink(), 48, 8.0, 6.0},
        {"clear.png",                 "close",        textMuted(),     32, 8.0, 3.2},
    };
    for (const Glyph& g : glyphs) {
        QImage img(g.px, g.px, QImage::Format_ARGB32_Premultiplied);
        img.fill(Qt::transparent);
        {
            QPainter p(&img);
            AppIcon::draw(p, QString::fromLatin1(g.icon),
                          QRectF(g.inset, g.inset, g.px - 2 * g.inset, g.px - 2 * g.inset),
                          g.color, g.pen);
        }
        img.save(path + QLatin1Char('/') + QLatin1String(g.file), "PNG");
    }
    return path;
}

QPalette makePalette()
{
    QPalette p;
    p.setColor(QPalette::Window, bg());
    p.setColor(QPalette::WindowText, textPrimary());
    p.setColor(QPalette::Base, field());
    p.setColor(QPalette::AlternateBase, surfaceAlt());
    p.setColor(QPalette::ToolTipBase, mecha() ? ink() : raised());
    p.setColor(QPalette::ToolTipText, mecha() ? pal().scrText : textPrimary());
    p.setColor(QPalette::PlaceholderText, textMuted());
    p.setColor(QPalette::Text, textPrimary());
    p.setColor(QPalette::Button, surface());
    p.setColor(QPalette::ButtonText, textPrimary());
    p.setColor(QPalette::BrightText, accentInk());
    p.setColor(QPalette::Light, field());
    p.setColor(QPalette::Midlight, borderLit());
    p.setColor(QPalette::Mid, borderStrong());
    p.setColor(QPalette::Dark, ink());
    p.setColor(QPalette::Shadow, ink());
    p.setColor(QPalette::Highlight, pal().menuSel);
    p.setColor(QPalette::HighlightedText, pal().menuSelText);
    p.setColor(QPalette::Link, accentDeep());
    p.setColor(QPalette::LinkVisited, accentDeep());
#if QT_VERSION >= QT_VERSION_CHECK(6, 6, 0)
    p.setColor(QPalette::Accent, accent());
#endif
    for (const auto role : {QPalette::WindowText, QPalette::Text, QPalette::ButtonText,
                            QPalette::HighlightedText, QPalette::PlaceholderText})
        p.setColor(QPalette::Disabled, role, textDisabled());
    p.setColor(QPalette::Disabled, QPalette::Highlight, surfaceHi());
    return p;
}

#ifdef Q_OS_WIN
COLORREF colorRef(const QColor& c)
{
    return RGB(c.red(), c.green(), c.blue());
}

void applyNativeChrome(QWidget* w)
{
    if (!w->testAttribute(Qt::WA_WState_Created))
        return; // never force a native handle into existence from here
    const HWND hwnd = reinterpret_cast<HWND>(w->winId());
    if (!hwnd)
        return;

    constexpr DWORD kDarkModeLegacy = 19;  // Windows 10 1809-1909
    constexpr DWORD kDarkMode       = 20;
    constexpr DWORD kCorner         = 33;
    constexpr DWORD kBorderColor    = 34;
    constexpr DWORD kCaptionColor   = 35;
    constexpr DWORD kTextColor      = 36;
    constexpr DWORD kRoundSmall     = 3;

    const Qt::WindowType type = w->windowType();
    const bool translucent = w->testAttribute(Qt::WA_TranslucentBackground);

    if (type == Qt::Popup || type == Qt::ToolTip) {
        if (translucent)
            return;
        const DWORD corner = kRoundSmall;
        DwmSetWindowAttribute(hwnd, kCorner, &corner, sizeof(corner));
        const COLORREF rim = colorRef(ink());
        DwmSetWindowAttribute(hwnd, kBorderColor, &rim, sizeof(rim));
        return;
    }
    if (translucent || w->windowFlags().testFlag(Qt::FramelessWindowHint))
        return;

    // 金刚的标题栏是装甲红:最小化 / 关闭等系统按钮要画成浅色才看得清。
    const BOOL dark = titan() ? TRUE : FALSE;
    if (FAILED(DwmSetWindowAttribute(hwnd, kDarkMode, &dark, sizeof(dark))))
        DwmSetWindowAttribute(hwnd, kDarkModeLegacy, &dark, sizeof(dark));
    const COLORREF caption = colorRef(pal().shell);
    DwmSetWindowAttribute(hwnd, kCaptionColor, &caption, sizeof(caption));
    const COLORREF text = colorRef(textPrimary());
    DwmSetWindowAttribute(hwnd, kTextColor, &text, sizeof(text));
    const COLORREF rim = colorRef(ink());
    DwmSetWindowAttribute(hwnd, kBorderColor, &rim, sizeof(rim));
}

class NativeChromeFilter final : public QObject
{
public:
    using QObject::QObject;

protected:
    bool eventFilter(QObject* obj, QEvent* ev) override
    {
        const QEvent::Type t = ev->type();
        if ((t == QEvent::Show || t == QEvent::WinIdChange) && obj->isWidgetType()) {
            auto* w = static_cast<QWidget*>(obj);
            if (w->isWindow())
                applyNativeChrome(w);
        }
        return QObject::eventFilter(obj, ev);
    }
};
#endif

QString bake(QString qss, std::initializer_list<std::pair<const char*, QString>> vars)
{
    for (const auto& [key, value] : vars)
        qss.replace(QStringLiteral("@{") + QLatin1String(key) + QLatin1Char('}'), value);
    return qss;
}

QString hex(const QColor& c) { return c.name(QColor::HexRgb); }
QString px(int v) { return QString::number(v) + QStringLiteral("px"); }

}

QBrush canvasBrush()
{
    static QHash<int, QPixmap> tiles;
    QPixmap& tile = tiles[int(skin())];
    if (tile.isNull()) {
        constexpr int step = 22;
        tile = QPixmap(step, step);
        tile.fill(bg());
        QPainter p(&tile);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setPen(Qt::NoPen);
        p.setBrush(blend(overlay(), bg(), 0.08));
        p.drawEllipse(QPointF(step / 2.0, step / 2.0), 1.0, 1.0);
    }
    return QBrush(tile);
}

QBrush grainBrush()
{
    static QImage tile;
    if (tile.isNull()) {
        constexpr int n = 128;
        tile = QImage(n, n, QImage::Format_ARGB32_Premultiplied);
        QRandomGenerator gen(0x5EED0B1Du);
        for (int y = 0; y < n; ++y) {
            auto* line = reinterpret_cast<QRgb*>(tile.scanLine(y));
            for (int x = 0; x < n; ++x) {
                const quint32 r = gen.generate();
                const int a = int(r % 7u);
                line[x] = qRgba(0, 0, 0, a);
            }
        }
    }
    return QBrush(tile);
}

QString styleSheet()
{
    static const char* const kSheet = R"QSS(
/* ── base ─────────────────────────────────────────────────────────────── */
QLabel { background: transparent; }
QToolTip {
    background-color: @{tipBg};
    color: @{tipText};
    border: 2px solid @{tipRim};
    padding: 6px 9px;
    font-weight: 600;
}

/* ── text roles ───────────────────────────────────────────────────────── */
QLabel[role="display"]   { font-size: 21pt; font-weight: 900; color: @{text}; }
QLabel[role="h1"]        { font-size: 16pt; font-weight: 900; color: @{text}; }
QLabel[role="h2"]        { font-size: 12pt; font-weight: 800; color: @{text}; }
QLabel[role="title"]     { font-size: 10.5pt; font-weight: 700; color: @{text}; }
QLabel[role="secondary"] { color: @{textSecondary}; }
QLabel[role="muted"]     { color: @{textMuted}; font-size: 9pt; }
QLabel[role="caption"]   { color: @{textMuted}; font-size: 9pt; font-weight: 700; }
QLabel[role="eyebrow"]   { color: @{eyebrow}; font-size: 9pt; font-weight: 800; }
QLabel[role="stat"]      { font-size: 22pt; font-weight: 900; color: @{text}; }
QLabel[role="mono"]      { font-family: "Cascadia Mono", "Consolas"; color: @{textSecondary}; }
QLabel[role="link"]      { color: @{link}; font-weight: 700; }
QLabel[role="lead"]      { font-size: 11pt; font-weight: 700; color: @{text}; }

/* ── containers ───────────────────────────────────────────────────────── */
QFrame#Divider { background-color: @{border}; border: none; }
QFrame#Topbar  { background: transparent; border: none; border-bottom: 2px solid @{ink}; }
QScrollArea    { background: transparent; border: none; }
QAbstractScrollArea::corner { background: transparent; border: none; }

/* ── buttons: 键帽 —— 墨线描边 + 加厚的底边,按下时底边变薄、文字下沉 ───── */
QPushButton {
    background-color: @{btn};
    color: @{text};
    border: 2px solid @{ink};
    border-bottom-width: 4px;
    border-radius: @{rBtn};
    padding: 5px 15px 4px 15px;
    font-weight: 700;
    outline: none;
}
QPushButton:hover    { background-color: @{btnHover}; }
QPushButton:pressed  { background-color: @{btnPressed}; border-bottom-width: 2px; padding-top: 7px; }
QPushButton:focus    { border-color: @{focus}; border-bottom-color: @{ink}; }
QPushButton:disabled { color: @{textDisabled}; background-color: @{surfaceAlt}; border-color: @{borderStrong}; }

QPushButton[variant="primary"]          { background-color: @{primary}; color: @{primaryText}; }
QPushButton[variant="primary"]:hover    { background-color: @{primaryHover}; }
QPushButton[variant="primary"]:pressed  { background-color: @{primaryPressed}; }
QPushButton[variant="primary"]:focus    { border-color: @{ink}; }
QPushButton[variant="primary"]:disabled { color: @{textDisabled}; background-color: @{surfaceAlt}; border-color: @{borderStrong}; }

QPushButton[variant="ghost"]          { background-color: transparent; color: @{textSecondary}; }
QPushButton[variant="ghost"]:hover    { background-color: @{btnHover}; color: @{text}; }
QPushButton[variant="ghost"]:pressed  { background-color: @{btnPressed}; }
QPushButton[variant="ghost"]:disabled { background-color: transparent; color: @{textDisabled}; border-color: @{borderStrong}; }

QPushButton[variant="danger"]          { background-color: @{dangerFill}; color: @{dangerText}; }
QPushButton[variant="danger"]:hover    { background-color: @{dangerHover}; }
QPushButton[variant="danger"]:pressed  { background-color: @{dangerFill}; }
QPushButton[variant="danger"]:focus    { border-color: @{ink}; }
QPushButton[variant="danger"]:disabled { background-color: @{surfaceAlt}; color: @{textDisabled}; border-color: @{borderStrong}; }

QPushButton[size="sm"] { padding: 3px 11px 2px 11px; font-size: 9pt; border-bottom-width: 3px; }
QPushButton[size="sm"]:pressed { border-bottom-width: 2px; padding-top: 4px; }

QToolButton         { background: transparent; border: 2px solid transparent; border-radius: @{rCtl}; padding: 3px; color: @{textSecondary}; }
QToolButton:hover   { background-color: @{btnHover}; border-color: @{ink}; }
QToolButton:pressed { background-color: @{btnPressed}; }
QToolButton:focus   { border: 2px solid @{focus}; }
QToolButton#MoreButton::menu-indicator { image: none; width: 0px; }

/* ── inputs ───────────────────────────────────────────────────────────── */
QLineEdit, QComboBox, QAbstractSpinBox, QPlainTextEdit, QTextEdit {
    background-color: @{field};
    color: @{text};
    border: 2px solid @{fieldRim};
    border-radius: @{rCtl};
    padding: 5px 9px;
    selection-background-color: @{selection};
    selection-color: @{text};
}
QLineEdit:focus, QComboBox:focus, QAbstractSpinBox:focus, QPlainTextEdit:focus, QTextEdit:focus {
    border-color: @{focus};
}
QLineEdit:disabled, QComboBox:disabled, QAbstractSpinBox:disabled, QPlainTextEdit:disabled, QTextEdit:disabled {
    color: @{textDisabled}; background-color: @{surfaceAlt}; border-color: @{borderStrong};
}
QPlainTextEdit, QTextEdit { padding: 6px 8px; }
QLineEdit { lineedit-clear-button-icon: url("@{glyphs}/clear.png"); }

/* Drop-down below the field (not the overlaid "menu" popup), so the list
   honours the item rules below. */
QComboBox { combobox-popup: 0; padding: 5px 8px 5px 12px; font-weight: 600; }
QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: center right;
    width: 24px;
    border: none;
    background: transparent;
}
QComboBox::down-arrow          { image: url("@{glyphs}/chevron-down.png"); width: 12px; height: 12px; }
QComboBox::down-arrow:on       { image: url("@{glyphs}/chevron-up.png"); }
QComboBox::down-arrow:disabled { image: url("@{glyphs}/chevron-down-disabled.png"); }
QComboBox QFrame {
    background-color: @{raised};
    border: 2px solid @{ink};
}
QComboBox QAbstractItemView {
    background-color: @{raised};
    color: @{text};
    border: none;
    border-radius: 0px;
    padding: 4px;
    outline: none;
    selection-background-color: @{menuSel};
    selection-color: @{menuSelText};
}
QComboBox QAbstractItemView::item          { min-height: 30px; padding: 0px 10px; border-radius: @{rItem}; }
QComboBox QAbstractItemView::item:hover    { background-color: @{surfaceAlt}; }
QComboBox QAbstractItemView::item:selected { background-color: @{menuSel}; color: @{menuSelText}; }

QAbstractSpinBox { padding-right: 28px; }
QAbstractSpinBox::up-button, QAbstractSpinBox::down-button {
    subcontrol-origin: border;
    width: 22px;
    border: none;
    background: transparent;
}
QAbstractSpinBox::up-button   { subcontrol-position: top right; margin: 3px 3px 0px 0px; }
QAbstractSpinBox::down-button { subcontrol-position: bottom right; margin: 0px 3px 3px 0px; }
QAbstractSpinBox::up-button:hover, QAbstractSpinBox::down-button:hover { background-color: @{surfaceAlt}; }
QAbstractSpinBox::up-arrow   { image: url("@{glyphs}/chevron-up.png"); width: 10px; height: 10px; }
QAbstractSpinBox::down-arrow { image: url("@{glyphs}/chevron-down.png"); width: 10px; height: 10px; }
QAbstractSpinBox::up-arrow:disabled, QAbstractSpinBox::up-arrow:off {
    image: url("@{glyphs}/chevron-up-disabled.png");
}
QAbstractSpinBox::down-arrow:disabled, QAbstractSpinBox::down-arrow:off {
    image: url("@{glyphs}/chevron-down-disabled.png");
}

/* ── check / radio ────────────────────────────────────────────────────── */
QCheckBox, QRadioButton { spacing: 8px; color: @{text}; background: transparent; outline: none; font-weight: 600; }
QCheckBox:disabled, QRadioButton:disabled { color: @{textDisabled}; }
QCheckBox::indicator {
    width: 16px; height: 16px; border-radius: @{rCheck};
    border: 2px solid @{fieldRim}; background-color: @{field};
}
QCheckBox::indicator:hover { background-color: @{surfaceAlt}; }
QCheckBox::indicator:checked {
    background-color: @{checkFill};
    image: url("@{glyphs}/check.png");
}
QCheckBox::indicator:focus            { border-color: @{focus}; }
QCheckBox::indicator:disabled         { background-color: @{surfaceAlt}; border-color: @{borderStrong}; }
QCheckBox::indicator:checked:disabled { background-color: @{surfaceHi}; border-color: @{borderStrong}; }
QRadioButton::indicator {
    width: 16px; height: 16px; border-radius: 10px;
    border: 2px solid @{fieldRim}; background-color: @{field};
}
QRadioButton::indicator:hover { background-color: @{surfaceAlt}; }
QRadioButton::indicator:checked {
    background-color: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5,
        stop:0 @{ink}, stop:0.34 @{ink}, stop:0.42 @{checkFill}, stop:1 @{checkFill});
}

/* ── lists & tables ───────────────────────────────────────────────────── */
QTableView, QListView, QTreeView {
    background-color: @{surface};
    alternate-background-color: @{rowAlt};
    color: @{text};
    border: 2px solid @{ink};
    border-radius: @{rCard};
    padding: 4px;
    gridline-color: @{border};
    outline: none;
    selection-background-color: @{selection};
    selection-color: @{text};
}
QTableView::item, QListView::item, QTreeView::item { border: none; padding: 0px 10px; }
QTableView::item:selected, QListView::item:selected, QTreeView::item:selected {
    background-color: @{selection}; color: @{text};
}
/* Record lists sit inside a card and paint their own rows (design/RecordDelegate). */
QListView#RecordList { background: transparent; border: none; border-radius: 0px; padding: 0px; }
QListView#RecordList::item { padding: 0px; border: none; }
/* The process list / tree sits inside a list card too (pages/ProcessesPage). */
QTreeView#ProcessTree { background: transparent; border: none; border-radius: 0px; padding: 0px 2px; }
QTreeView#ProcessTree::item { padding: 0px 8px; border: none; }
QHeaderView { background: transparent; border: none; }
QHeaderView::section {
    background-color: transparent;
    color: @{text};
    border: none;
    border-bottom: 2px solid @{ink};
    border-right: 1px solid @{border};
    padding: 8px 10px;
    font-size: 9pt;
    font-weight: 800;
}
QHeaderView::section:last, QHeaderView::section:only-one { border-right: none; }
QHeaderView::up-arrow {
    image: url("@{glyphs}/sort-up.png"); width: 10px; height: 10px;
    subcontrol-origin: padding; subcontrol-position: center right;
}
QHeaderView::down-arrow {
    image: url("@{glyphs}/sort-down.png"); width: 10px; height: 10px;
    subcontrol-origin: padding; subcontrol-position: center right;
}
QTableCornerButton::section { background: transparent; border: none; }

/* ── menus ────────────────────────────────────────────────────────────── */
QMenu {
    background-color: @{raised};
    color: @{text};
    border: 2px solid @{ink};
    padding: 5px;
}
QMenu::item           { padding: 7px 26px 7px 12px; border-radius: @{rItem}; background: transparent; font-weight: 600; }
QMenu::item:selected  { background-color: @{menuSel}; color: @{menuSelText}; }
QMenu::item:disabled  { color: @{textDisabled}; }
QMenu::separator      { height: 2px; background: @{border}; margin: 5px 6px; }
QMenu::indicator      { width: 14px; height: 14px; left: 6px; }

/* ── scroll bars ──────────────────────────────────────────────────────── */
QScrollBar:vertical   { background: transparent; width: 12px; margin: 0px; }
QScrollBar:horizontal { background: transparent; height: 12px; margin: 0px; }
QScrollBar::handle:vertical   { background-color: @{scroll}; min-height: 32px; border-radius: @{rScroll}; margin: 2px 2px; }
QScrollBar::handle:horizontal { background-color: @{scroll}; min-width: 32px; border-radius: @{rScroll}; margin: 2px 2px; }
QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover     { background-color: @{scrollHover}; }
QScrollBar::handle:vertical:pressed, QScrollBar::handle:horizontal:pressed { background-color: @{scrollPressed}; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0px; height: 0px; border: none; background: none; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }

/* ── progress ─────────────────────────────────────────────────────────── */
QProgressBar {
    background-color: @{field};
    border: 2px solid @{fieldRim};
    border-radius: @{rCheck};
    min-height: 10px;
    max-height: 12px;
    text-align: center;
}
QProgressBar::chunk { border-radius: 0px; background-color: @{accent}; }

/* ── standard dialogs ─────────────────────────────────────────────────── */
QMessageBox QLabel { color: @{text}; }
QDialogButtonBox QPushButton, QMessageBox QPushButton { min-width: 84px; }
)QSS";

    const bool m = mecha();
    const bool t = titan();
    const Palette& P = pal();
    // 机甲的按钮是装甲白的键帽;金刚的内容区是暗的,按钮改成比面板亮一档的钢蓝键帽,主按钮用机身钴蓝。
    const auto pick = [m, t](const QColor& titanC, const QColor& mechaC, const QColor& kawaiiC) {
        return t ? titanC : (m ? mechaC : kawaiiC);
    };
    return bake(QString::fromUtf8(kSheet), {
        {"tipBg",          hex(m ? P.ink : P.raised)},
        {"tipText",        hex(m ? P.scrText : P.text)},
        {"tipRim",         hex(P.ink)},
        {"text",           hex(P.text)},
        {"textSecondary",  hex(P.textSecondary)},
        {"textMuted",      hex(P.textMuted)},
        {"textDisabled",   hex(P.textDisabled)},
        {"eyebrow",        hex(P.accentDeep)},
        {"link",           hex(P.accentDeep)},
        {"border",         hex(P.border)},
        {"borderStrong",   hex(P.borderStrong)},
        {"surface",        hex(P.surface)},
        {"surfaceAlt",     hex(P.surfaceAlt)},
        {"surfaceHi",      hex(P.surfaceHi)},
        {"raised",         hex(P.raised)},
        {"field",          hex(P.field)},
        {"ink",            hex(P.ink)},
        {"fieldRim",       hex(rim())},
        {"focus",          hex(P.accentDeep)},
        {"accent",         hex(P.accent)},
        {"btn",            hex(pick(QColor(0x22, 0x2C, 0x42), QColor(0xFF, 0xFF, 0xFF), P.surface))},
        {"btnHover",       hex(pick(QColor(0x2C, 0x39, 0x58), QColor(0xF1, 0xEF, 0xEA), P.surfaceAlt))},
        {"btnPressed",     hex(pick(P.surfaceTop, P.bg, P.surfaceHi))},
        {"primary",        hex(pick(P.structure, P.accent, P.accentSoft))},
        {"primaryHover",   hex(pick(QColor(0x2F, 0x68, 0xEC), QColor(0xFF, 0x7D, 0x33), QColor(0xFF, 0xC6, 0xD5)))},
        {"primaryPressed", hex(pick(QColor(0x1C, 0x49, 0xB8), P.accentDeep, P.accent))},
        {"primaryText",    hex(m ? P.accentInk : P.ink)},
        {"dangerFill",     hex(pick(QColor(0xC5, 0x22, 0x2E), QColor(0xE5, 0x38, 0x3B), QColor(0xFF, 0x8E, 0x8E)))},
        {"dangerHover",    hex(pick(QColor(0xDD, 0x2C, 0x39), QColor(0xEC, 0x4E, 0x51), QColor(0xFF, 0x9F, 0x9F)))},
        {"dangerText",     hex(QColor(0xFF, 0xFF, 0xFF))},
        {"selection",      hex(blend(P.accent, P.surface, m ? 0.20 : 0.28))},
        {"rowAlt",         hex(blend(overlay(), P.surface, 0.025))},
        {"menuSel",        hex(P.menuSel)},
        {"menuSelText",    hex(P.menuSelText)},
        {"checkFill",      hex(m ? P.accent : P.cyan)},
        {"scroll",         hex(m ? P.borderStrong : P.accentSoft)},
        {"scrollHover",    hex(pick(P.borderLit, QColor(0x83, 0x82, 0x7F), P.accent))},
        {"scrollPressed",  hex(pick(P.accentDeep, P.success, P.accentDeep))},
        {"rBtn",           px(m ? 3 : 15)},
        {"rCtl",           px(m ? 3 : 13)},
        {"rCard",          px(m ? 4 : 18)},
        {"rItem",          px(m ? 2 : 10)},
        {"rCheck",         px(m ? 2 : 6)},
        {"rScroll",        px(m ? 2 : 4)},
        {"glyphs",         glyphDir()},
    });
}

void apply(QApplication& app)
{
    static bool once = false;
    if (!once) {
        if (QStyle* fusion = QStyleFactory::create(QStringLiteral("Fusion")))
            app.setStyle(fusion);
    }
#if QT_VERSION >= QT_VERSION_CHECK(6, 8, 0)
    QGuiApplication::styleHints()->setColorScheme(Qt::ColorScheme::Light);
#endif

    const QPalette palette = makePalette();
    app.setPalette(palette);
    QToolTip::setPalette(palette);

    QFont f;
    f.setFamilies({QStringLiteral("Segoe UI"), QStringLiteral("Microsoft YaHei UI")});
    f.setPointSizeF(10.0);
    f.setStyleStrategy(QFont::PreferAntialias);
    app.setFont(f);

    app.setStyleSheet(styleSheet());

    if (once)
        return;
    once = true;

    for (const Qt::UIEffect effect : {Qt::UI_AnimateMenu, Qt::UI_FadeMenu, Qt::UI_AnimateCombo,
                                      Qt::UI_AnimateTooltip, Qt::UI_FadeTooltip})
        QApplication::setEffectEnabled(effect, motion::enabled());

    ui::installRipples(app);

#ifdef Q_OS_WIN
    app.installEventFilter(new NativeChromeFilter(&app));
#endif
}

}
