#include "bulwark/engine/DgaDomainAnalyzer.h"
#include <QHash>
#include <QStringList>
#include <cmath>

namespace bulwark::engine {

using detail::u;

namespace {

const QStringList& benignSuffixes() {
    static const QStringList s = {
        ".amazonaws.com", ".cloudfront.net", ".azureedge.net", ".azurewebsites.net", ".cloudapp.net",
        ".trafficmanager.net", ".akamaiedge.net", ".akamaized.net", ".akadns.net", ".edgekey.net",
        ".edgesuite.net", ".fastly.net", ".googleusercontent.com", ".gvt1.com", ".gvt2.com",
        ".googlevideo.com", ".windowsupdate.com", ".microsoft.com", ".msftncsi.com", ".office.net",
        ".live.com", ".apple.com", ".icloud.com", ".cdn.cloudflare.net", ".1e100.net", ".in-addr.arpa",
        ".local", ".lan", ".internal", ".alicdn.com", ".aliyuncs.com", ".qcloud.com", ".myqcloud.com",
        ".tencent-cloud.net", ".bcebos.com", ".bdstatic.com", ".kunlunsl.com",
    };
    return s;
}

double entropyOf(const QString& s) {
    QHash<QChar, int> counts;
    for (const QChar c : s) ++counts[c];
    double h = 0.0;
    for (const int n : std::as_const(counts)) {
        const double p = static_cast<double>(n) / s.size();
        h -= p * std::log2(p);
    }
    return h;
}

}

ScoreResult DgaDomainAnalyzer::analyze(const QString& domain) {
    ScoreResult r;
    const QString d = domain.trimmed().toLower();
    if (d.isEmpty() || !d.contains(QLatin1Char('.')))
        return r;
    for (const QString& suffix : benignSuffixes())
        if (d.endsWith(suffix))
            return r;

    const QStringList labels = d.split(QLatin1Char('.'), Qt::SkipEmptyParts);
    if (labels.size() < 2)
        return r;
    // 注册名所在的那一级:倒数第二级;遇到 com.cn、co.uk 这类二级后缀时再往前一级。
    qsizetype idx = labels.size() - 2;
    if (idx > 0 && labels.at(idx).size() <= 3 && labels.last().size() == 2)
        --idx;
    const QString label = labels.at(idx);
    if (label.size() < 10)
        return r;

    int vowels = 0, digits = 0, run = 0, maxRun = 0;
    for (const QChar c : label) {
        const bool vowel = QStringLiteral("aeiou").contains(c);
        if (vowel) ++vowels;
        if (c.isDigit()) ++digits;
        run = (c.isLetter() && !vowel) ? run + 1 : 0;
        maxRun = qMax(maxRun, run);
    }
    const double vowelRatio = static_cast<double>(vowels) / label.size();
    const double digitRatio = static_cast<double>(digits) / label.size();

    if (label.size() >= 12 && entropyOf(label) > 3.8) {
        r.score += 25;
        r.reasons << u("域名字符分布接近随机(T1568.002)");
    }
    if (vowelRatio < 0.2) {
        r.score += 15;
        r.reasons << u("域名几乎没有元音,不像可读单词(T1568.002)");
    }
    if (maxRun >= 5) {
        r.score += 10;
        r.reasons << u("域名含长串连续辅音(T1568.002)");
    }
    if (digitRatio >= 0.2 && digitRatio <= 0.7) {
        r.score += 10;
        r.reasons << u("域名字母数字混杂(T1568.002)");
    }
    if (label.size() >= 20) {
        r.score += 10;
        r.reasons << u("域名注册名超长(T1568.002)");
    }
    r.score = qMin(r.score, 60);
    if (r.score < 25) {
        r.score = 0;
        r.reasons.clear();
    }
    return r;
}

}
