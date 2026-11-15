#pragma once
#include "bulwark/models/ThreatSnippet.h"

#include <QColor>
#include <QFont>
#include <QVector>
#include <QWidget>

class CodeBlock : public QWidget
{
public:
    CodeBlock(const bulwark::ThreatSnippet& snippet, const QColor& accent, int maxRows,
              QWidget* parent = nullptr);

    const bulwark::ThreatSnippet& snippet() const { return m_snippet; }

    bool hasHeightForWidth() const override { return true; }
    int heightForWidth(int w) const override;
    QSize sizeHint() const override;
    QSize minimumSizeHint() const override;

protected:
    void paintEvent(QPaintEvent*) override;

private:
    struct Row {
        enum class Kind { Code, Gap, More };
        Kind kind = Kind::Code;
        int number = 0;
        bool hit = false;
        QString text;
        int hitStart = -1;
        int hitLength = 0;
    };

    const QVector<Row>& rowsFor(int width) const;
    QVector<Row> buildRows(int width) const;
    int rowHeight() const;

    bulwark::ThreatSnippet m_snippet;
    QColor m_accent;
    QFont m_font;
    int m_maxRows;
    int m_gutterW = 0;

    mutable int m_cacheW = -1;
    mutable QVector<Row> m_rows;
};
