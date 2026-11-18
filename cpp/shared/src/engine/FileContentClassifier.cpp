#include "bulwark/engine/FileContentClassifier.h"

#include <QSet>
#include <array>
#include <cmath>
#include <cstring>
#include <initializer_list>

namespace bulwark::engine {

namespace {

// 取样不到这么多字节时,熵说明不了问题。
constexpr int kMinJudgeBytes = 512;
// 随机数据的经验熵:4096 字节约 7.95,1024 字节约 7.8,512 字节约 7.6;没压缩过的二进制远低于此。
constexpr double kHighEntropy = 7.2;
constexpr double kHighEntropySmall = 7.0;
constexpr int kPdfSearchBytes = 1024;

struct Signature {
    int offset;
    const char* bytes;
    int length;
};

#define BLW_SIG(offset, literal) { offset, literal, static_cast<int>(sizeof(literal) - 1) }

// 十六进制转义后面紧跟十六进制字符时必须拆开字面量,否则会被并进同一个转义。
const Signature kSignatures[] = {
    // 压缩包,以及拿它当容器的文档(docx / xlsx / pptx / odt / epub / jar / apk)
    BLW_SIG(0, "PK\x03\x04"), BLW_SIG(0, "PK\x05\x06"), BLW_SIG(0, "PK\x07\x08"),
    BLW_SIG(0, "7z\xBC\xAF\x27\x1C"), BLW_SIG(0, "Rar!\x1A\x07"), BLW_SIG(0, "\x1F\x8B\x08"),
    BLW_SIG(0, "\xFD" "7zXZ\x00"), BLW_SIG(0, "\x28\xB5\x2F\xFD"), BLW_SIG(0, "\x04\x22\x4D\x18"),
    BLW_SIG(0, "MSCF"), BLW_SIG(0, "ISc("), BLW_SIG(0, "LZIP"), BLW_SIG(257, "ustar"), BLW_SIG(0, "!<arch>\n"),
    BLW_SIG(0, "PAR2\x00PKT"),
    // Office 97-2003 / WPS / MSI / 加了密码的 OOXML
    BLW_SIG(0, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"),
    BLW_SIG(0, "{\\rtf"), BLW_SIG(0, "%!PS"),
    // 图片
    BLW_SIG(0, "\xFF\xD8\xFF"), BLW_SIG(0, "\x89PNG\r\n\x1A\n"), BLW_SIG(0, "GIF87a"), BLW_SIG(0, "GIF89a"),
    BLW_SIG(0, "II*\x00"), BLW_SIG(0, "MM\x00*"), BLW_SIG(0, "II+\x00"), BLW_SIG(0, "MM\x00+"),
    BLW_SIG(0, "8BPS"), BLW_SIG(0, "\x00\x00\x00\x0CjP  \r\n\x87\n"), BLW_SIG(0, "\xFF\x4F\xFF\x51"),
    BLW_SIG(0, "DDS "), BLW_SIG(0, "\x76\x2F\x31\x01"), BLW_SIG(0, "\xD7\xCD\xC6\x9A"), BLW_SIG(40, " EMF"),
    BLW_SIG(0, "AT&TFORM"),
    // 音视频
    BLW_SIG(4, "ftyp"), BLW_SIG(4, "moov"), BLW_SIG(4, "mdat"), BLW_SIG(4, "wide"), BLW_SIG(4, "free"),
    BLW_SIG(4, "skip"), BLW_SIG(4, "styp"), BLW_SIG(4, "moof"), BLW_SIG(4, "sidx"), BLW_SIG(4, "pnot"),
    BLW_SIG(0, "\x1A\x45\xDF\xA3"), BLW_SIG(0, "fLaC"), BLW_SIG(0, "OggS"), BLW_SIG(0, "ID3"),
    BLW_SIG(0, "MThd"), BLW_SIG(0, "\x30\x26\xB2\x75\x8E\x66\xCF\x11"), BLW_SIG(0, "\x00\x00\x01\xBA"),
    BLW_SIG(0, "\x00\x00\x01\xB3"), BLW_SIG(0, "FLV\x01"), BLW_SIG(0, "FWS"), BLW_SIG(0, "CWS"), BLW_SIG(0, "ZWS"),
    BLW_SIG(0, "RF64"), BLW_SIG(0, "FORM"), BLW_SIG(0, ".snd"), BLW_SIG(0, "#!AMR"), BLW_SIG(0, "wvpk"),
    BLW_SIG(0, "MAC "), BLW_SIG(0, "TTA1"), BLW_SIG(0, "MPCK"), BLW_SIG(0, ".RMF"), BLW_SIG(0, "ADIF"),
    // 程序与数据
    BLW_SIG(0, "MZ"), BLW_SIG(0, "\x7F" "ELF"), BLW_SIG(0, "\xCA\xFE\xBA\xBE"),
    BLW_SIG(0, "SQLite format 3\x00"), BLW_SIG(0, "!BDN"), BLW_SIG(4, "Standard Jet DB"),
    BLW_SIG(4, "Standard ACE DB"), BLW_SIG(0, "regf"), BLW_SIG(0, "ElfFile\x00"), BLW_SIG(0, "vhdxfile"),
    BLW_SIG(0, "conectix"), BLW_SIG(0, "KDMV"), BLW_SIG(0, "QFI\xFB"),
    BLW_SIG(0, "\x03\xD9\xA2\x9A\x67\xFB\x4B\xB5"), BLW_SIG(0, "bplist0"),
    BLW_SIG(0, "L\x00\x00\x00\x01\x14\x02\x00"), BLW_SIG(0, "ITSF"), BLW_SIG(60, "BOOKMOBI"),
    BLW_SIG(60, "TEXtREAd"), BLW_SIG(0, "AutoCAD Binary DXF"),
    // 字体
    BLW_SIG(0, "OTTO"), BLW_SIG(0, "wOFF"), BLW_SIG(0, "wOF2"), BLW_SIG(0, "ttcf"), BLW_SIG(0, "true"),
    BLW_SIG(0, "\x00\x01\x00\x00\x00"),
};

#undef BLW_SIG

unsigned char byteAt(const QByteArray& data, qsizetype index) {
    return static_cast<unsigned char>(data.at(index));
}

bool printableAscii(unsigned char c) { return c >= 0x20 && c < 0x7F; }

bool asciiDigit(char c) { return c >= '0' && c <= '9'; }

// A ZIP magic alone is not evidence that an OOXML/archive body is intact.
// Reject impossible header lengths without attempting to decompress untrusted data.
bool zipHeaderFits(const FileContentSample& sample) {
    const QByteArray& h = sample.head;
    const auto word = [&h](qsizetype at) -> quint32 {
        return static_cast<quint32>(byteAt(h, at))
            | (static_cast<quint32>(byteAt(h, at + 1)) << 8);
    };
    if (h.startsWith(QByteArray("PK\x03\x04", 4))) {
        if (h.size() < 30) return false;
        const quint64 headerBytes = 30ULL + word(26) + word(28);
        return word(26) > 0 && headerBytes <= static_cast<quint64>(sample.size);
    }
    if (h.startsWith(QByteArray("PK\x05\x06", 4))) {
        return h.size() >= 22 && 22ULL + word(20) <= static_cast<quint64>(sample.size);
    }
    return true;
}

// 标记太短或位置不固定的格式,逐个加验。
bool hasSpecialSignature(const QByteArray& h) {
    const qsizetype n = h.size();
    // RIFF 容器(WAV / AVI / WebP / CDR):4 字节长度之后是 4 个可打印字符的形式码
    if (n >= 12 && h.startsWith("RIFF") && printableAscii(byteAt(h, 8)) && printableAscii(byteAt(h, 9))
        && printableAscii(byteAt(h, 10)) && printableAscii(byteAt(h, 11)))
        return true;
    // BMP 只有两个字节的标记,加验保留字段为零
    if (n >= 14 && h.at(0) == 'B' && h.at(1) == 'M' && byteAt(h, 6) == 0 && byteAt(h, 7) == 0
        && byteAt(h, 8) == 0 && byteAt(h, 9) == 0)
        return true;
    if (n >= 10 && h.startsWith("BZh") && h.at(3) >= '1' && h.at(3) <= '9'
        && std::memcmp(h.constData() + 4, "1AY&SY", 6) == 0)
        return true;
    // zlib 流:头两个字节按 31 取模为零,常见的只有这四种
    if (n >= 2 && byteAt(h, 0) == 0x78
        && (byteAt(h, 1) == 0x01 || byteAt(h, 1) == 0x5E || byteAt(h, 1) == 0x9C || byteAt(h, 1) == 0xDA))
        return true;
    // DWG:AC10xx,老版本是 AC1.x / AC2.x
    if (n >= 6 && h.at(0) == 'A' && h.at(1) == 'C' && (h.at(2) == '1' || h.at(2) == '2')
        && (asciiDigit(h.at(3)) || h.at(3) == '.') && asciiDigit(h.at(4)))
        return true;
    // ICO / CUR
    if (n >= 10 && byteAt(h, 0) == 0 && byteAt(h, 1) == 0 && (byteAt(h, 2) == 1 || byteAt(h, 2) == 2)
        && byteAt(h, 3) == 0 && byteAt(h, 4) >= 1 && byteAt(h, 4) <= 64 && byteAt(h, 5) == 0 && byteAt(h, 9) == 0)
        return true;
    // MPEG 音频帧 / ADTS:同步字之外再验版本、层、码率、采样率字段
    if (n >= 4 && byteAt(h, 0) == 0xFF && (byteAt(h, 1) & 0xE0) == 0xE0) {
        const unsigned char b1 = byteAt(h, 1);
        const unsigned char b2 = byteAt(h, 2);
        const bool mpegAudio = (b1 & 0x18) != 0x08 && (b1 & 0x06) != 0x00 && (b2 & 0xF0) != 0xF0
                               && (b2 & 0xF0) != 0x00 && (b2 & 0x0C) != 0x0C;
        const bool adts = (b1 & 0xF6) == 0xF0 && (b2 & 0x3C) != 0x3C;
        if (mpegAudio || adts)
            return true;
    }
    // MPEG-TS:每 188 字节(m2ts 为 192)一个 0x47 同步字节
    if (n >= 377 && byteAt(h, 0) == 0x47 && byteAt(h, 188) == 0x47 && byteAt(h, 376) == 0x47)
        return true;
    if (n >= 389 && byteAt(h, 4) == 0x47 && byteAt(h, 196) == 0x47 && byteAt(h, 388) == 0x47)
        return true;
    // PDF:%PDF- 前面允许有少量杂字节
    if (h.left(kPdfSearchBytes).contains("%PDF-"))
        return true;
    // BT 种子:bencode 字典,以 d<长度>:<键> 开头;后面的分片哈希是高熵的
    if (n >= 5 && h.at(0) == 'd' && h.at(1) >= '1' && h.at(1) <= '9') {
        const qsizetype colon = asciiDigit(h.at(2)) ? 3 : 2;
        if (h.at(colon) == ':' && h.at(colon + 1) >= 'a' && h.at(colon + 1) <= 'z')
            return true;
    }
    return false;
}

bool allZero(const QByteArray& data) {
    for (const char c : data)
        if (c != 0)
            return false;
    return true;
}

// 开头像某种容器的固定头:有好几个零字节,或一串可打印字符的标记。不认识的私有格式、加密软件的
// 容器、先留空文件头最后再回填的写法都是这样;密文的开头是随机的,前 32 字节里出现 4 个零的
// 概率约十万分之一,出现 8 个连续可打印字符不到百分之一。
bool hasStructuredPrefix(const QByteArray& h) {
    const qsizetype n = qMin<qsizetype>(h.size(), 32);
    int zeros = 0;
    int run = 0;
    int longest = 0;
    for (qsizetype i = 0; i < n; ++i) {
        const unsigned char c = byteAt(h, i);
        if (c == 0)
            ++zeros;
        if (printableAscii(c)) {
            ++run;
            longest = qMax(longest, run);
        } else {
            run = 0;
        }
    }
    return zeros >= 4 || longest >= 8;
}

QSet<QString> makeSet(std::initializer_list<const char*> items) {
    QSet<QString> out;
    out.reserve(static_cast<qsizetype>(items.size()));
    for (const char* s : items)
        out.insert(QString::fromLatin1(s));
    return out;
}

// 文件头可靠的类型:内容既没有任何已知文件头、又是高熵数据,就不可能还是这种文件。
// 刻意不收:标记弱或常带前导杂数据的(mp3 / aac / mpg)、一名多用的(ts)、
// 应用常拿来装私有或加密数据的(db / dat / bin / sqlite / log / iso)。
const QSet<QString>& binaryTypes() {
    static const QSet<QString> k = makeSet({
        "pdf", "docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xlsb", "xltx", "xltm", "pptx", "pptm", "ppsx",
        "potx", "odt", "ods", "odp", "odg", "vsdx", "vsd", "pub", "msg", "pst", "ost", "mdb", "accdb", "wps",
        "et", "dps", "epub", "mobi", "azw3", "chm", "djvu",
        "jpg", "jpeg", "jpe", "jfif", "png", "gif", "bmp", "tif", "tiff", "webp", "heic", "heif", "avif", "psd",
        "psb", "ico", "cr2", "nef", "arw", "dng",
        "wav", "flac", "ogg", "opus", "m4a", "wma", "mid", "midi", "mp4", "m4v", "mov", "3gp", "avi", "mkv",
        "webm", "wmv", "asf", "flv",
        "zip", "rar", "7z", "gz", "tgz", "bz2", "xz", "zst", "cab", "jar", "apk",
        "exe", "dll", "msi", "kdbx", "dwg", "ttf", "otf", "woff", "woff2", "swf", "lnk",
    });
    return k;
}

// 可以是纯文本的类型:.doc / .xls 常常其实是 HTML、RTF 或 CSV。变成认不出格式的高熵数据才算坏。
const QSet<QString>& textTypes() {
    static const QSet<QString> k = makeSet({
        "doc", "dot", "xls", "xlt", "ppt", "pps", "pot", "rtf", "txt", "csv", "tsv", "xml", "html", "htm",
        "xhtml", "mht", "json", "yaml", "yml", "md", "ini", "sql", "svg", "tex", "srt", "vcf", "ics",
        "c", "h", "cpp", "hpp", "cc", "cxx", "cs", "java", "py", "js", "jsx", "tsx", "go", "rs", "php", "rb",
        "sh", "bat", "cmd", "ps1", "vbs", "lua", "css", "scss", "vue", "kt", "swift", "dart", "toml", "dxf",
        "eps", "ps",
    });
    return k;
}

// 外加在原文件名后面、内容本来就可以是无文件头高熵数据的后缀:加密工具、无头压缩、
// 下载半成品、签名与校验、通用数据文件。report.docx.gpg 不能按「本该是 docx」去判。
const QSet<QString>& wrapperExtensions() {
    static const QSet<QString> k = makeSet({
        "gpg", "pgp", "asc", "age", "aes", "enc", "axx", "bc", "c9r", "cpt", "nc", "hc", "tc", "p7m", "p7e",
        "vault", "tmp", "temp", "part", "partial", "crdownload", "download", "downloading", "filepart", "bak",
        "old", "orig", "swp", "!ut", "bc!", "td", "xltd", "aria2", "!qb", "br", "lzma", "deflate", "zz", "sz",
        "torrent", "dat", "bin", "data", "raw", "db", "cache", "idx", "sig", "sign", "p7s", "hash", "crc",
        "par2", "rev", "thumb",
    });
    return k;
}

bool isWrapperExtension(const QString& ext) {
    bool digits = !ext.isEmpty();
    for (const QChar c : ext)
        digits = digits && c.isDigit();
    if (digits)
        return true;   // 分卷:.001 .002
    if (ext.size() == 3 && (ext.at(0) == QLatin1Char('z') || ext.at(0) == QLatin1Char('r')) && ext.at(1).isDigit()
        && ext.at(2).isDigit())
        return true;   // 分卷:.z01 .r00
    return wrapperExtensions().contains(ext);
}

bool lookupType(const QString& ext, ContentClaim& claim) {
    if (binaryTypes().contains(ext)) {
        claim.type = ext;
        claim.textAllowed = false;
        return true;
    }
    if (textTypes().contains(ext)) {
        claim.type = ext;
        claim.textAllowed = true;
        return true;
    }
    return false;
}

}

ContentClaim FileContentClassifier::claimOf(const QString& lowerName) {
    ContentClaim claim;
    const qsizetype lastDot = lowerName.lastIndexOf(QLatin1Char('.'));
    if (lastDot <= 0 || lastDot == lowerName.size() - 1)
        return claim;
    const QString last = lowerName.mid(lastDot + 1);
    if (lookupType(last, claim))
        return claim;
    if (isWrapperExtension(last))
        return claim;
    // 外层后缀不认识:往里找原来的扩展名。report.docx.abc 自称原本是 report.docx。
    qsizetype end = lastDot;
    while (end > 1) {
        const qsizetype dot = lowerName.lastIndexOf(QLatin1Char('.'), end - 1);
        if (dot <= 0)
            break;
        if (lookupType(lowerName.mid(dot + 1, end - dot - 1), claim)) {
            claim.inner = true;
            claim.original = lowerName.left(end);
            return claim;
        }
        end = dot;
    }
    return claim;
}

bool FileContentClassifier::hasKnownSignature(const QByteArray& head) {
    for (const Signature& s : kSignatures) {
        if (head.size() >= s.offset + s.length
            && std::memcmp(head.constData() + s.offset, s.bytes, static_cast<size_t>(s.length)) == 0)
            return true;
    }
    return hasSpecialSignature(head);
}

bool FileContentClassifier::looksLikeText(const QByteArray& head) {
    const qsizetype n = head.size();
    if (n == 0)
        return false;
    const auto* p = reinterpret_cast<const unsigned char*>(head.constData());
    // UTF-16 / UTF-32 的 BOM:正文里全是零字节,不能按「有零字节就不是文本」判
    if (n >= 2 && ((p[0] == 0xFF && p[1] == 0xFE) || (p[0] == 0xFE && p[1] == 0xFF)))
        return true;
    // 随机数据里控制字符约占 12%;文本(含 GBK、UTF-8 等多字节编码)几乎没有。
    qsizetype control = 0;
    for (qsizetype i = 0; i < n; ++i) {
        const unsigned char c = p[i];
        if (c == 0)
            return false;
        if ((c < 0x20 && c != '\t' && c != '\n' && c != '\r' && c != '\f' && c != 0x1B) || c == 0x7F)
            ++control;
    }
    return control * 50 <= n;
}

double FileContentClassifier::entropyBits(const QByteArray& data) {
    const qsizetype n = data.size();
    if (n <= 0)
        return 0.0;
    std::array<int, 256> counts{};
    for (qsizetype i = 0; i < n; ++i)
        ++counts[byteAt(data, i)];
    double bits = 0.0;
    for (const int count : counts) {
        if (count == 0)
            continue;
        const double p = static_cast<double>(count) / static_cast<double>(n);
        bits -= p * std::log2(p);
    }
    return bits;
}

ContentVerdict FileContentClassifier::classify(const ContentClaim& claim, const FileContentSample& sample) {
    if (sample.kind != FileContentSample::Kind::Present)
        return ContentVerdict::Unknown;
    const QByteArray& head = sample.head;
    if (sample.integrity == FileIntegrity::Invalid) return ContentVerdict::Damaged;
    if (sample.integrity == FileIntegrity::Unsupported) return ContentVerdict::Unknown;
    // 预分配或刚建好还没写入的文件读出来就是空的或全零。
    if (sample.size <= 0 || head.isEmpty() || allZero(head))
        return ContentVerdict::Unsettled;
    static const QSet<QString> plain = { "txt", "csv", "json", "xml", "yaml", "yml", "md", "log" };
    if (plain.contains(claim.type)) {
        for (const QByteArray* range : { &sample.middle, &sample.tail })
            if (range->size() >= kMinJudgeBytes && !looksLikeText(*range)
                && entropyBits(*range) >= kHighEntropy)
                return ContentVerdict::Scrambled;
    }
    if (hasKnownSignature(head)) {
        if (!zipHeaderFits(sample)) return ContentVerdict::Unknown;
        if (head.startsWith(QByteArray("PK\x03\x04", 4)) && !sample.tail.isEmpty()) {
            const qsizetype end = sample.tail.lastIndexOf(QByteArray("PK\x05\x06", 4));
            if (end < 0 || end + 22 > sample.tail.size()) return ContentVerdict::Unknown;
            const auto* b = reinterpret_cast<const unsigned char*>(sample.tail.constData() + end);
            const int comment = b[20] | (b[21] << 8);
            if (end + 22 + comment != sample.tail.size()) return ContentVerdict::Unknown;
        }
        return ContentVerdict::Recognized;
    }
    if (looksLikeText(head)) {
        // 名字说是图片 / 压缩包、内容却是文本:对不上,但也不是乱码(常见于下载失败存下的网页)。
        return (claim.type.isEmpty() || claim.textAllowed) ? ContentVerdict::Recognized : ContentVerdict::Unknown;
    }
    if (claim.type.isEmpty() || head.size() < kMinJudgeBytes)
        return ContentVerdict::Unknown;
    if (hasStructuredPrefix(head))
        return ContentVerdict::Unknown;
    const double threshold = head.size() >= 1024 ? kHighEntropy : kHighEntropySmall;
    return entropyBits(head) >= threshold ? ContentVerdict::Scrambled : ContentVerdict::Unknown;
}

}
