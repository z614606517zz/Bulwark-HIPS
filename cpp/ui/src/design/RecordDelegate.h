#pragma once
#include <QColor>
#include <QListView>
#include <QRect>
#include <QStyledItemDelegate>

#include <functional>

class QTimer;

class RecordDelegate : public QStyledItemDelegate
{
public:
    explicit RecordDelegate(QObject* parent = nullptr);

    static constexpr int kRowH = 60;
    static constexpr int kHeaderH = 38;
    static constexpr int kStickyH = 32;

    void setRail(bool on) { m_rail = on; }
    bool rail() const { return m_rail; }
    void setCollapsible(bool on) { m_collapsible = on; }
    bool collapsible() const { return m_collapsible; }
    void setCollapsedProbe(std::function<bool(const QString&)> probe) { m_isCollapsed = std::move(probe); }
    void setIdentity(const QColor& hue) { m_identity = hue; }
    QColor identity() const { return m_identity; }
    void setCheckable(bool on) { m_checkable = on; }
    bool checkable() const { return m_checkable; }

    void paint(QPainter* p, const QStyleOptionViewItem& opt, const QModelIndex& idx) const override;
    QSize sizeHint(const QStyleOptionViewItem& opt, const QModelIndex& idx) const override;

    void paintHeader(QPainter* p, const QRect& band, const QModelIndex& header, bool pinned) const;

private:
    void paintRecord(QPainter* p, const QStyleOptionViewItem& opt, const QModelIndex& idx) const;

    bool m_rail = false;
    bool m_collapsible = false;
    bool m_checkable = false;
    QColor m_identity;
    std::function<bool(const QString&)> m_isCollapsed;
};

class RecordListView : public QListView
{
    Q_OBJECT
public:
    explicit RecordListView(QWidget* parent = nullptr);

    RecordDelegate* recordDelegate() const { return m_delegate; }
    void setStickyHeaders(bool on);

signals:
    void headerClicked(const QString& group);

public:
    void settleLayout() { executeDelayedItemsLayout(); }
    void setBottomInset(int px);
    void keyboardSearch(const QString& search) override;

protected:
    void paintEvent(QPaintEvent* e) override;
    void mousePressEvent(QMouseEvent* e) override;
    void mouseDoubleClickEvent(QMouseEvent* e) override;
    void scrollContentsBy(int dx, int dy) override;

private:
    QModelIndex headerFor(const QModelIndex& idx) const;

    RecordDelegate* m_delegate = nullptr;
    QTimer* m_clock = nullptr;
    int m_bottomInset = 0;
    bool m_sticky = false;
    mutable QRect m_stickyRect;
    mutable QString m_stickyGroup;
};
