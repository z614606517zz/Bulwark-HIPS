#pragma once
#include <QColor>
#include <QDialog>
#include <QPoint>
#include <QString>

#include <functional>

class BannerHost;
class GlowCard;
class IconTile;
class QHBoxLayout;
class QLabel;
class QPropertyAnimation;
class QVariantAnimation;
class QPushButton;
class QToolButton;
class QVBoxLayout;
namespace motion { class Ticker; }

class Sheet : public QDialog
{
    Q_OBJECT
public:
    explicit Sheet(QWidget* parent = nullptr);

    void done(int result) override;

    void setHeader(const QString& icon, const QColor& tone, const QString& title,
                   const QString& subtitle = QString());
    void setEyebrow(const QString& text, const QColor& color);
    // 卡片顶部换成警示斑马带(颜色 = 风险),眉标签贴在带子上。
    void setHazard(const QColor& color);
    // 小垒站在卡片右上角的边沿上,表情 = 这张弹窗的语气。
    void setMascot(int mood);
    void setPulse(bool on);
    void setTitle(const QString& title);
    void setSubtitle(const QString& subtitle);
    void setGlow(const QColor& color);
    void setSheetWidth(int width);
    // ✕ button + Esc. Off for sheets that must be answered with a button.
    void setClosable(bool closable);
    bool isClosable() const { return m_closable; }
    void setCloseButtonVisible(bool visible);
    QLabel* titleLabel() const { return m_title; }

    enum class Placement { CenterOnParent, BottomRight };
    void setPlacement(Placement placement) { m_placement = placement; }
    Placement placement() const { return m_placement; }

    void refit();

    QVBoxLayout* body() const { return m_body; }
    QHBoxLayout* footer() const { return m_footer; }
    void addFooterLeft(QWidget* w);
    QPushButton* addButton(const QString& text, const char* variant, std::function<void()> fn = {});
    BannerHost* banners() const { return m_banners; }
    GlowCard* card() const { return m_card; }

    static int screenHeightFor(const QWidget* anchor, qreal fraction);

protected:
    void showEvent(QShowEvent* e) override;
    void hideEvent(QHideEvent* e) override;
    void resizeEvent(QResizeEvent* e) override;
    void keyPressEvent(QKeyEvent* e) override;
    void mousePressEvent(QMouseEvent* e) override;
    void mouseMoveEvent(QMouseEvent* e) override;
    void mouseReleaseEvent(QMouseEvent* e) override;

private:
    void placeOnScreen();
    void fitHeight();
    void syncDecor();
    QPoint travel() const;
    void startEnter();
    void settleEnter();
    void syncPulse();
    void playExit();
    QPoint mascotRest() const;
    void dropMascot();

    GlowCard* m_card = nullptr;
    QWidget* m_eyebrowRow = nullptr;
    QWidget* m_strip = nullptr;
    QLabel* m_eyebrow = nullptr;
    IconTile* m_tile = nullptr;
    QLabel* m_title = nullptr;
    QLabel* m_subtitle = nullptr;
    QToolButton* m_close = nullptr;
    BannerHost* m_banners = nullptr;
    QVBoxLayout* m_body = nullptr;
    QHBoxLayout* m_footer = nullptr;
    QWidget* m_footerHost = nullptr;
    int m_footerLeft = 0;
    Placement m_placement = Placement::CenterOnParent;
    bool m_closable = true;
    bool m_placed = false;
    bool m_dragging = false;
    QPoint m_dragOffset;

    QPropertyAnimation* m_fade = nullptr;
    QPropertyAnimation* m_move = nullptr;
    QVariantAnimation* m_pulse = nullptr;
    QPoint m_restPos;
    bool m_entering = false;
    bool m_pulseWanted = false;
    QColor m_hazard;
    QWidget* m_mascot = nullptr;
    QPropertyAnimation* m_mascotDrop = nullptr;
    bool m_mascotPending = false;
    motion::Ticker* m_march = nullptr;
};
