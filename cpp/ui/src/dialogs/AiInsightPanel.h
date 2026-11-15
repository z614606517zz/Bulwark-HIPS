#pragma once
#include <QColor>
#include <QElapsedTimer>
#include <QFrame>
#include <QPointer>
#include <QUuid>

#include "ai/AiScanner.h"
#include "bulwark/models/Enums.h"

class IconTile;
class QLabel;
class QPushButton;
class QTimer;
class QWidget;

class AiInsightPanel : public QFrame
{
    Q_OBJECT
public:
    explicit AiInsightPanel(AiExplainContext context, bool compact = false, QWidget* parent = nullptr);

    void setLoading();

    void setResult(const AiExplanation& r, bool hardIndicator);

    void setCorrectionContext(const QString& actorPath, const QString& matchedRuleNote);

    void showAutoTrustApplied(bulwark::RememberScope scope, const QUuid& ruleId);

signals:
    void trustRequested(bulwark::RememberScope scope);
    void deleteRuleRequested();

    void autoTrustApplied(bulwark::RememberScope scope);
    void autoTrustUndoRequested(const QUuid& ruleId);

protected:
    void paintEvent(QPaintEvent*) override;
    bool hasHeightForWidth() const override { return true; }
    int heightForWidth(int w) const override;

private:
    QLabel* bodyLabel(const QColor& color) const;
    void setTone(const QColor& c);
    void setMeta(const QString& text);
    void showCorrectionRow(bool show);

    AiExplainContext m_context;
    bool m_compact = false;
    QColor m_color;
    IconTile* m_tile = nullptr;
    QLabel* m_caption = nullptr;
    QLabel* m_advice = nullptr;
    QLabel* m_confidence = nullptr;
    QLabel* m_meta = nullptr;
    QLabel* m_text = nullptr;       // 紧凑版是 WrapLabel —— 改字必须走 setPlainText()(见 .cpp)
    QLabel* m_note = nullptr;
    QWidget* m_fixRow = nullptr;
    QLabel* m_fixCap = nullptr;
    QPushButton* m_trust1h = nullptr;
    QPushButton* m_trust1d = nullptr;
    QPushButton* m_trustSession = nullptr;
    QPushButton* m_delRule = nullptr;
    QPushButton* m_undoTrust = nullptr;
    QUuid m_autoTrustRuleId;
    QTimer* m_ticker = nullptr;
    QElapsedTimer m_since;
    QString m_actorPath;
    QString m_matchedRuleNote;
};
