#pragma once
#include <QByteArray>
#include <QString>
#include "bulwark/engine/ZipIntegrity.h"

namespace bulwark::engine {

// 有界的头、中、尾取样。未取到的范围不表示已经验证；读盘由服务端完成。
struct FileContentSample {
    // Unavailable:这个位置读不了(网络盘、云端占位文件)。Busy:这会儿读不到(被独占、读盘超时),稍后再试。
    enum class Kind { Unavailable, Busy, Missing, Present };
    Kind kind = Kind::Unavailable;
    qint64 size = 0;
    QByteArray head;
    QByteArray middle;
    QByteArray tail;
    FileIntegrity integrity = FileIntegrity::Unchecked;
};

enum class ContentVerdict {
    Recognized,   // 已取样范围符合已知格式，不保证未取样的正文完整
    Scrambled,    // 名字说它是文档 / 图片 / …,内容却是认不出格式的高熵数据
    Unsettled,    // 空文件或开头全是零:多半还没写完,过一会儿再看
    Unknown,      // 说明不了什么(未知类型、取样太小、类型与内容对不上但不是乱码)
    Damaged,      // 结构/正文校验失败，不单独证明恶意行为
};

// 文件名自称的类型。
struct ContentClaim {
    QString type;              // 不带点的小写扩展名;空 = 从名字看不出它该是什么内容
    bool textAllowed = false;  // 这种类型的文件可以是纯文本(.doc / .xls 常常其实是 HTML)
    bool inner = false;        // 类型取自里层扩展名:report.docx.abc 里的 docx
    QString original;          // inner 时:去掉外加后缀的原文件名(report.docx)
};

// 判断「这个文件现在的内容,还是不是它名字所说的那种文件」。只看开头一小段:
// 认文件头、认文本、算取样的熵。纯函数,不读盘。
class FileContentClassifier {
public:
    static constexpr int kHeadBytes = 4096;
    static constexpr int kTailBytes = 65557; // maximum ZIP EOCD + comment

    static ContentClaim claimOf(const QString& lowerName);
    static ContentVerdict classify(const ContentClaim& claim, const FileContentSample& sample);
    static ContentVerdict classify(const QString& lowerName, const FileContentSample& sample) {
        return classify(claimOf(lowerName), sample);
    }

    static bool hasKnownSignature(const QByteArray& head);
    static bool looksLikeText(const QByteArray& head);
    static double entropyBits(const QByteArray& data);
};

}
