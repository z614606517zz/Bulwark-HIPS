#pragma once
#include <QColor>
#include <QList>
#include <QVariant>
#include <QWidget>

class QButtonGroup;
class QHBoxLayout;
class SegmentButton;

class Segmented : public QWidget
{
    Q_OBJECT
public:
    explicit Segmented(QWidget* parent = nullptr);

    int addSegment(const QString& text, const QVariant& data = QVariant());
    int count() const { return int(m_buttons.size()); }

    void setText(int index, const QString& text);
    void setCount(int index, int count);
    void setAccent(int index, const QColor& color);

    int currentIndex() const;
    QVariant currentData() const;
    QVariant data(int index) const;
    int indexOfData(const QVariant& data) const;
    void setCurrentIndex(int index);

    void setCompact(bool compact);
    bool isCompact() const { return m_compact; }

    void setIdentity(const QColor& hue);
    QColor identity() const { return m_identity; }

signals:
    void currentChanged(int index);

protected:
    void paintEvent(QPaintEvent*) override;

private:
    friend class SegmentButton;
    void step(int from, int delta);
    void syncFocus();

    QButtonGroup* m_group = nullptr;
    QHBoxLayout* m_row = nullptr;
    QList<SegmentButton*> m_buttons;
    bool m_compact = false;
    QColor m_identity;
};
