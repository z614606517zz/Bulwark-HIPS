#pragma once
#include <QColor>
#include <QIcon>
#include <QPixmap>
#include <QSize>
#include <QString>
#include <QWidget>

class QPainter;
class QPainterPath;

class AppIcon : public QWidget
{
    Q_OBJECT
public:
    explicit AppIcon(const QString& name = QString(), QWidget* parent = nullptr);

    void setName(const QString& name);
    QString name() const { return m_name; }

    void setColor(const QColor& c);
    QColor color() const { return m_color; }

    void setPx(int px);
    int px() const { return m_px; }

    QSize sizeHint() const override { return {m_px, m_px}; }

    static void draw(QPainter& p, const QString& name, const QRectF& rect,
                     const QColor& color, qreal penWidth = 1.7);

    static QPixmap pixmap(const QString& name, const QColor& color, int px,
                          qreal penWidth = 1.7);
    static QIcon icon(const QString& name, const QColor& color, int px);

    static QPainterPath shieldPath();

    static void drawBadge(QPainter& p, const QRectF& rect);
    static QIcon appBadge();

protected:
    void paintEvent(QPaintEvent*) override;

private:
    QString m_name;
    QColor m_color;
    int m_px = 20;
};
