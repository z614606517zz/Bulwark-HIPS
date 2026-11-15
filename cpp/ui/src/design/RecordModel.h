#pragma once
#include <QAbstractListModel>
#include <QColor>
#include <QDateTime>
#include <QHash>
#include <QList>
#include <QPair>
#include <QSet>
#include <QSortFilterProxyModel>
#include <QStringList>
#include <QVariant>

#include <functional>
#include <utility>

namespace rec {
enum Role : int {
    Subtitle = Qt::UserRole + 1,
    SubtitleMono,
    Icon,
    IconColor,
    Score,
    ScoreColor,
    Pill,
    PillColor,
    Meta,
    Time,
    Chips,
    Dim,
    Header,
    Group,
    GroupCount,
    GroupColor,
    GroupNote,
    Accent,
    Key,
    Leading,
    ChipColors,
    PillSolid,
};
}

struct RecordView {
    QString icon;
    QColor iconColor;
    QString title;
    QString subtitle;
    bool subtitleMono = false;
    QString score;
    QColor scoreColor;
    QString pill;
    QColor pillColor;
    bool pillSolid = false;   // 实心标签:金刚里「没拦住」是唯一实心的琥珀标签
    QString meta;
    QDateTime time;
    QStringList chips;
    QList<QColor> chipColors;
    bool dim = false;
    QColor accent;
    QString tooltip;
    QString haystack;
    QVariant key;

    bool header = false;
    QString group;
    int groupCount = 0;
    QColor groupColor;
    QString groupNote;
};

class RecordModel : public QAbstractListModel
{
public:
    explicit RecordModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    Qt::ItemFlags flags(const QModelIndex& index) const override;

    void reset(QList<RecordView> rows);
    void insertTop(QList<RecordView> rows);
    void removeAt(int row);
    void removeTail(int n);
    void setRow(int row, RecordView v);

    int size() const { return int(m_rows.size()); }
    const RecordView& at(int row) const { return m_rows.at(row); }
    bool isHeader(int row) const { return row >= 0 && row < m_rows.size() && m_rows.at(row).header; }
    bool hasHeaders() const { return !m_spans.isEmpty(); }
    QPair<int, int> groupSpan(int headerRow) const { return m_spans.value(headerRow, {1, 0}); }
    int recordCount() const { return m_records; }
    int rowOfKey(const QVariant& key) const;

private:
    static void normalize(RecordView& v);
    void rebuildIndex();

    QList<RecordView> m_rows;
    QHash<int, QPair<int, int>> m_spans;
    int m_records = 0;
};

class RecordFilter : public QSortFilterProxyModel
{
public:
    explicit RecordFilter(QObject* parent = nullptr);

    void setRecords(RecordModel* model);
    RecordModel* records() const { return m_model; }

    void setPredicate(std::function<bool(int sourceRow)> pred);
    // Whitespace-separated terms, all must appear (case-insensitive).
    void setSearch(const QString& text);
    QString search() const { return m_search; }
    void setCollapsed(const QString& group, bool collapsed);
    bool isCollapsed(const QString& group) const { return m_collapsed.contains(group); }
    QSet<QString> collapsedGroups() const { return m_collapsed; }

    void refresh();

    bool matches(int sourceRow) const;
    int matchedRecords() const;
    int totalRecords() const;

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;

private:
    RecordModel* m_model = nullptr;
    std::function<bool(int)> m_pred;
    QString m_search;
    QStringList m_terms;
    QSet<QString> m_collapsed;
};

template <class T>
class RecordStore
{
public:
    using ViewFn = std::function<RecordView(const T&)>;

    RecordStore(RecordModel* model, ViewFn view) : m_model(model), m_view(std::move(view)) {}

    void reset(const QList<T>& items)
    {
        m_grouped = false;
        m_items = items;
        m_rowToItem.clear();
        QList<RecordView> rows;
        rows.reserve(items.size());
        for (const T& it : items)
            rows.append(m_view(it));
        m_model->reset(std::move(rows));
    }

    void prependMany(const QList<T>& newestFirst)
    {
        if (newestFirst.isEmpty() || m_grouped)
            return;
        QList<RecordView> rows;
        rows.reserve(newestFirst.size());
        for (const T& it : newestFirst)
            rows.append(m_view(it));
        for (qsizetype i = newestFirst.size() - 1; i >= 0; --i)
            m_items.prepend(newestFirst[i]);
        m_model->insertTop(std::move(rows));
    }

    void prepend(const T& item) { prependMany(QList<T>{item}); }

    void removeAt(int itemIndex)
    {
        if (m_grouped || itemIndex < 0 || itemIndex >= m_items.size())
            return;
        m_items.removeAt(itemIndex);
        m_model->removeAt(itemIndex);
    }

    void trim(int maxItems)
    {
        if (m_grouped)
            return;
        const int n = int(m_items.size()) - maxItems;
        if (n <= 0)
            return;
        m_items.remove(maxItems, n);
        m_model->removeTail(n);
    }

    void resetGrouped(const QList<T>& items, const std::function<QString(const T&)>& groupOf,
                      const std::function<RecordView(const QString& group, const QList<const T*>& members)>& header,
                      const QStringList& order = QStringList())
    {
        m_grouped = true;
        m_items = items;
        QStringList groups = order;
        QHash<QString, QList<int>> buckets;
        for (int i = 0; i < m_items.size(); ++i) {
            const QString g = groupOf(m_items[i]);
            if (!groups.contains(g))
                groups.append(g);
            buckets[g].append(i);
        }
        QList<RecordView> rows;
        m_rowToItem.clear();
        for (const QString& g : std::as_const(groups)) {
            const auto it = buckets.constFind(g);
            if (it == buckets.constEnd() || it->isEmpty())
                continue;
            QList<const T*> members;
            for (int i : *it)
                members.append(&m_items[i]);
            RecordView h = header(g, members);
            h.header = true;
            h.group = g;
            h.groupCount = int(it->size());
            rows.append(h);
            m_rowToItem.append(-1);
            for (int i : *it) {
                RecordView v = m_view(m_items[i]);
                v.group = g;
                rows.append(v);
                m_rowToItem.append(i);
            }
        }
        m_model->reset(std::move(rows));
    }

    void update(int itemIndex, const T& item)
    {
        if (itemIndex < 0 || itemIndex >= m_items.size())
            return;
        m_items[itemIndex] = item;
        const int row = rowOfItem(itemIndex);
        if (row < 0)
            return;
        RecordView v = m_view(item);
        if (m_grouped)
            v.group = m_model->at(row).group;
        m_model->setRow(row, std::move(v));
    }

    int itemIndex(int sourceRow) const
    {
        if (!m_grouped)
            return (sourceRow >= 0 && sourceRow < m_items.size()) ? sourceRow : -1;
        return (sourceRow >= 0 && sourceRow < m_rowToItem.size()) ? m_rowToItem[sourceRow] : -1;
    }
    int rowOfItem(int itemIndex) const
    {
        if (!m_grouped)
            return (itemIndex >= 0 && itemIndex < m_items.size()) ? itemIndex : -1;
        return int(m_rowToItem.indexOf(itemIndex));
    }
    const T* itemAt(int sourceRow) const
    {
        const int i = itemIndex(sourceRow);
        return i >= 0 ? &m_items[i] : nullptr;
    }
    const QList<T>& items() const { return m_items; }
    int size() const { return int(m_items.size()); }
    bool isEmpty() const { return m_items.isEmpty(); }
    RecordModel* model() const { return m_model; }

private:
    RecordModel* m_model;
    ViewFn m_view;
    QList<T> m_items;
    QList<int> m_rowToItem;
    bool m_grouped = false;
};
