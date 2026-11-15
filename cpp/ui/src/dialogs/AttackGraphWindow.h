#pragma once
#include <QDialog>
#include <QHash>
#include <QPoint>
#include <QPointF>
#include <QRectF>
#include <QUuid>
#include <QWidget>

#include "bulwark/models/AttackGraph.h"

class ElidingLabel;
class Inspector;
class IpcClient;
class QScrollArea;
class QSplitter;
class QToolButton;

class AttackGraphCanvas : public QWidget
{
    Q_OBJECT
public:
    explicit AttackGraphCanvas(QWidget* parent = nullptr);

    void setGraph(const bulwark::AttackGraph& graph);
    void setMessage(const QString& text);
    void setScale(qreal s);
    qreal scaleFactor() const { return m_scale; }
    QSizeF logicalSize() const { return m_logicalSize; }
    void setViewportSize(const QSize& size);
    void clearSelection();

signals:
    void nodeSelected(int index);
    void edgeSelected(int index);
    void scaleChanged(qreal scale);
    void panRequested(const QPoint& delta);

protected:
    void paintEvent(QPaintEvent* e) override;
    void mousePressEvent(QMouseEvent* e) override;
    void mouseMoveEvent(QMouseEvent* e) override;
    void mouseReleaseEvent(QMouseEvent* e) override;
    void wheelEvent(QWheelEvent* e) override;

private:
    void relayout();
    void syncSize();
    QPointF origin() const;
    QPointF toLogical(const QPointF& widgetPos) const;
    int nodeAt(const QPointF& logical) const;
    int edgeAt(const QPointF& logical) const;

    bulwark::AttackGraph m_graph;
    QHash<QString, int> m_indexById;
    QVector<QRectF> m_boxes;
    QSizeF m_logicalSize{ 100, 100 };
    QSize m_viewport;
    QString m_message;
    qreal m_scale = 1.0;
    int m_selectedNode = -1;
    int m_selectedEdge = -1;
    bool m_panning = false;
    bool m_panMoved = false;
    QPoint m_panLast;
};

class AttackGraphWindow : public QDialog
{
    Q_OBJECT
public:
    AttackGraphWindow(IpcClient* ipc, const QUuid& seedEventId, int rootPid,
                      const QString& title, QWidget* parent = nullptr);

protected:
    bool eventFilter(QObject* watched, QEvent* e) override;

private:
    void showGraph(const bulwark::AttackGraph& g);
    void showOverview();
    void showNodeDetail(int index);
    void showEdgeDetail(int index);
    void placeOverlays();
    void fit();

    IpcClient* m_ipc = nullptr;
    QUuid m_seedEventId;
    QUuid m_requestId;
    int m_rootPid = 0;
    QString m_title;
    AttackGraphCanvas* m_canvas = nullptr;
    QScrollArea* m_scroll = nullptr;
    QSplitter* m_split = nullptr;
    Inspector* m_inspector = nullptr;
    ElidingLabel* m_summary = nullptr;
    QWidget* m_zoomBar = nullptr;
    QToolButton* m_zoomReset = nullptr;
    QWidget* m_legend = nullptr;
    QString m_status;
    bool m_fitted = false;
    bulwark::AttackGraph m_graph;
};
