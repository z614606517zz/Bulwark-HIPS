#pragma once
#include "design/GlowCard.h"
#include "design/RecordModel.h"

#include <QList>
#include <QPersistentModelIndex>
#include <QPointer>
#include <QVariant>
#include <QWidget>

#include <functional>

class EmptyState;
class FilterChip;
class Inspector;
class QAbstractItemView;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QMenu;
class QPushButton;
class QToolButton;
class QVariantAnimation;
class QVBoxLayout;
class RecordListView;
class Segmented;

class BatchBar : public GlowCard
{
    Q_OBJECT
public:
    explicit BatchBar(QWidget* parent = nullptr);
    void setCount(int selected, int listed);
    QPushButton* addAction(const QString& icon, const QString& text, const char* variant,
                           std::function<void()> fn);
    bool hasActions() const { return !m_buttons.isEmpty(); }
    void setCheckMode(bool on);

signals:
    void clearRequested();
    void selectAllRequested(bool select);

private:
    QLabel* m_count = nullptr;
    QPushButton* m_all = nullptr;
    QHBoxLayout* m_row = nullptr;
    QToolButton* m_close = nullptr;
    QList<QPushButton*> m_buttons;
    bool m_allSelected = false;
};

class ListShell : public QWidget
{
    Q_OBJECT
public:
    explicit ListShell(QWidget* parent = nullptr);

    Segmented* segments() const { return m_segments; }
    FilterChip* addChip(const QString& label);
    void addFilterWidget(QWidget* w);
    QLineEdit* searchBox() const { return m_search; }
    QLabel* matchLabel() const { return m_match; }
    void setMatch(int shown, int total);
    void addTop(QWidget* w);
    void addAboveList(QWidget* w);
    // 列表右边并排一列(检查器浮层仍只盖列表)。不调用就不动布局。
    void addSide(QWidget* w);
    // 搜索框定宽靠最左、紧跟条目数(全部显示时按 countFormat),右端放 trailing。
    void setLeadingBar(int searchWidth, const QString& countFormat, QWidget* trailing);

    void setView(QAbstractItemView* view);
    QAbstractItemView* view() const { return m_view; }
    Inspector* inspector() const { return m_inspector; }
    bool isInspectorOpen() const { return m_open; }
    void setInspectorOpen(bool open);
    EmptyState* emptyState() const { return m_empty; }
    void setEmptyVisible(bool visible);
    BatchBar* batchBar() const { return m_batch; }
    void setBatchVisible(bool visible);
    void showNewItems(int n, const QString& text = QString());

    virtual void setIdentity(const QColor& hue);
    QColor identity() const { return m_identity; }

signals:
    void newItemsClicked();
    void inspectorClosed();
    void escapePressed();

protected:
    void keyPressEvent(QKeyEvent* e) override;
    bool eventFilter(QObject* watched, QEvent* e) override;
    void showEvent(QShowEvent* e) override;
    void syncSegmentsVisible();

private:
    void layoutContent();
    void positionOverlays();

    QVBoxLayout* m_top = nullptr;
    QHBoxLayout* m_bar = nullptr;
    QHBoxLayout* m_chips = nullptr;
    QVBoxLayout* m_above = nullptr;
    Segmented* m_segments = nullptr;
    QLineEdit* m_search = nullptr;
    QLabel* m_match = nullptr;
    QString m_countFormat;
    QHBoxLayout* m_body = nullptr;

    QWidget* m_content = nullptr;
    GlowCard* m_card = nullptr;
    QVBoxLayout* m_cardLayout = nullptr;
    QAbstractItemView* m_view = nullptr;
    Inspector* m_inspector = nullptr;
    QWidget* m_scrim = nullptr;
    EmptyState* m_empty = nullptr;
    BatchBar* m_batch = nullptr;
    QPushButton* m_newPill = nullptr;
    QVariantAnimation* m_anim = nullptr;
    qreal m_progress = 0.0;
    bool m_open = false;
    bool m_batchShown = false;
    QColor m_identity;
};

class RecordBrowser : public ListShell
{
    Q_OBJECT
public:
    enum class Empty { None, Disconnected, Loading, NoData, NoMatch };

    explicit RecordBrowser(QWidget* parent = nullptr);

    RecordModel* model() const { return m_model; }
    RecordFilter* filter() const { return m_filter; }
    RecordListView* list() const { return m_list; }

    void setGrouped(bool grouped, bool collapsible = false, bool rail = false);
    void setMultiSelect(bool on);
    void setCheckMode(bool on);
    bool checkMode() const { return m_checkMode; }
    void setLiveTop(bool on) { m_liveTop = on; }
    void setIdentity(const QColor& hue) override;

    void setPredicate(std::function<bool(int sourceRow)> pred);
    void setInspectorBuilder(std::function<void(Inspector*, int sourceRow)> build);
    void setActivateHandler(std::function<void(int sourceRow)> fn);
    void setContextMenuBuilder(std::function<void(QMenu*, const QList<int>& sourceRows)> fn);
    void setClearFilters(std::function<void()> fn) { m_clearFilters = std::move(fn); }

    void setConnected(bool connected);
    void setNeedsConnection(bool on) { m_needsConnection = on; refreshEmpty(); }
    void setLoading(bool loading);
    void setDisconnectedText(const QString& body);
    void setNoDataContent(const QString& icon, const QString& title, const QString& body,
                          const QString& actionText = QString(), std::function<void()> action = {});
    Empty emptyKind() const { return m_emptyKind; }

    void refilter();
    QList<int> selectedSourceRows() const;
    int currentSourceRow() const;
    QVariant currentKey() const;
    bool selectKey(const QVariant& key, bool openInspector = true, bool reveal = true);
    void rebuildInspector();
    void clearSelection();

signals:
    void currentRowChanged(int sourceRow);
    void selectionCountChanged(int n);
    void checkModeChanged(bool on);

private:
    void updateCounts();
    void refreshEmpty();
    int syncBatch();
    bool restoreSelection(const QList<QVariant>& keys, const QVariant& current);
    void onCurrentChanged(const QModelIndex& current);
    void showInspectorFor(int sourceRow);
    void showContextMenu(const QPoint& pos);

    RecordModel* m_model = nullptr;
    RecordFilter* m_filter = nullptr;
    RecordListView* m_list = nullptr;

    std::function<void(Inspector*, int)> m_buildInspector;
    std::function<void(int)> m_activate;
    std::function<void(QMenu*, const QList<int>&)> m_contextMenu;
    std::function<void()> m_clearFilters;
    std::function<void()> m_noDataAction;

    bool m_connected = false;
    bool m_needsConnection = true;
    bool m_loading = false;
    bool m_liveTop = false;
    Empty m_emptyKind = Empty::None;
    QString m_disconnectedBody;
    QString m_noDataIcon, m_noDataTitle, m_noDataBody, m_noDataActionText;

    bool m_multi = false;
    bool m_checkMode = false;

    QVariant m_keptKey;
    QList<QVariant> m_keptKeys;
    bool m_keptInspector = false;
    int m_keptScroll = 0;
    QPersistentModelIndex m_anchor;
    int m_anchorY = 0;
    bool m_anchoring = false;
    bool m_selecting = false;
    int m_newCount = 0;
};
