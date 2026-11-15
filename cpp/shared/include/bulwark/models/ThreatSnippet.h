#pragma once
#include <QJsonObject>
#include <QString>
#include <QStringView>
#include <QVector>

namespace bulwark {

struct SnippetLine {
    int number = 0;
    QString text;
    bool hit = false;
    int hitStart = -1;
    int hitLength = 0;

    bool operator==(const SnippetLine&) const = default;

    QJsonObject toJson() const;
    static SnippetLine fromJson(const QJsonObject& o);
};

struct ThreatSnippet {
    static constexpr int kMaxSnippets = 3;
    static constexpr int kMaxLines = 5;
    static constexpr int kMaxLineChars = 200;
    static constexpr int kMaxWrapChars = 1000;
    static constexpr int kMaxTitleChars = 60;

    QString title;
    QVector<SnippetLine> lines;
    bool wrap = false;
    int totalChars = 0;
    bool truncated = false;

    bool isEmpty() const { return lines.isEmpty(); }
    bool sameAs(const ThreatSnippet& other) const;
    QString plainText() const;

    QJsonObject toJson() const;
    static ThreatSnippet fromJson(const QJsonObject& o);
};

namespace snippet {

QString sanitize(QStringView raw);

SnippetLine makeLine(int number, QStringView raw, bool hit, qsizetype hitStart, qsizetype hitLength,
                     int maxChars, bool* cut = nullptr);

QString titleFromName(const QString& name);

ThreatSnippet fromText(const QString& title, const QString& text);

}
}
