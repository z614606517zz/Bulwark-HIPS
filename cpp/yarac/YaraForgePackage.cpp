#include "YaraForgePackage.h"

#include "puff.h"

#include <array>
#include <cctype>

namespace bulwark::yara {
namespace {

constexpr std::uint32_t kEocdSig = 0x06054b50u;
constexpr std::uint32_t kCentralSig = 0x02014b50u;
constexpr std::uint32_t kLocalSig = 0x04034b50u;
constexpr std::size_t kEocdSize = 22;
constexpr std::size_t kCentralSize = 46;
constexpr std::size_t kLocalSize = 30;

std::uint16_t rd16(std::string_view b, std::size_t off) {
    return static_cast<std::uint16_t>(static_cast<unsigned char>(b[off])
                                      | (static_cast<unsigned char>(b[off + 1]) << 8));
}

std::uint32_t rd32(std::string_view b, std::size_t off) {
    return static_cast<std::uint32_t>(static_cast<unsigned char>(b[off]))
         | (static_cast<std::uint32_t>(static_cast<unsigned char>(b[off + 1])) << 8)
         | (static_cast<std::uint32_t>(static_cast<unsigned char>(b[off + 2])) << 16)
         | (static_cast<std::uint32_t>(static_cast<unsigned char>(b[off + 3])) << 24);
}

bool fits(std::string_view b, std::size_t off, std::size_t len) {
    return off <= b.size() && len <= b.size() - off;
}

bool isBlank(char c) { return c == ' ' || c == '\t' || c == '\r'; }
bool isIdentStart(char c) { return std::isalpha(static_cast<unsigned char>(c)) != 0 || c == '_'; }
bool isIdentChar(char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_'; }

std::string_view trim(std::string_view s) {
    while (!s.empty() && (isBlank(s.front()) || s.front() == '\n')) s.remove_prefix(1);
    while (!s.empty() && (isBlank(s.back()) || s.back() == '\n')) s.remove_suffix(1);
    return s;
}

// 行首(允许缩进)的 [private|global]* rule NAME。
bool ruleHeaderName(std::string_view line, std::string& name) {
    std::size_t i = 0;
    const auto skipBlank = [&] {
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
    };
    const auto word = [&]() -> std::string_view {
        const std::size_t start = i;
        while (i < line.size() && isIdentChar(line[i])) ++i;
        return line.substr(start, i - start);
    };
    skipBlank();
    for (;;) {
        if (i >= line.size() || !isIdentStart(line[i]))
            return false;
        const std::string_view w = word();
        if (w == "private" || w == "global") {
            if (i >= line.size() || (line[i] != ' ' && line[i] != '\t'))
                return false;
            skipBlank();
            continue;
        }
        if (w != "rule")
            return false;
        break;
    }
    if (i >= line.size() || (line[i] != ' ' && line[i] != '\t'))
        return false;
    skipBlank();
    if (i >= line.size() || !isIdentStart(line[i]))
        return false;
    const std::string_view n = word();
    if (i < line.size() && !isBlank(line[i]) && line[i] != ':' && line[i] != '{')
        return false;
    name.assign(n);
    return true;
}

bool isImportLine(std::string_view line) {
    const std::string_view t = trim(line);
    if (t.substr(0, 6) != "import" || t.size() < 8)
        return false;
    std::size_t i = 6;
    if (t[i] != ' ' && t[i] != '\t')
        return false;
    while (i < t.size() && (t[i] == ' ' || t[i] == '\t')) ++i;
    return i < t.size() && t[i] == '"';
}

// 字符串不跨行;返回本行结束时是否仍在块注释里。
bool endsInBlockComment(std::string_view line, bool inBlock) {
    bool inString = false;
    for (std::size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        const char n = i + 1 < line.size() ? line[i + 1] : '\0';
        if (inBlock) {
            if (c == '*' && n == '/') {
                inBlock = false;
                ++i;
            }
        } else if (inString) {
            if (c == '\\')
                ++i;
            else if (c == '"')
                inString = false;
        } else if (c == '"') {
            inString = true;
        } else if (c == '/' && n == '/') {
            break;
        } else if (c == '/' && n == '*') {
            inBlock = true;
            ++i;
        }
    }
    return inBlock;
}

int parseCount(std::string_view s) {
    s = trim(s);
    int n = 0;
    bool any = false;
    for (const char c : s) {
        if (c < '0' || c > '9')
            break;
        if (n > 100000000)
            return 0;
        n = n * 10 + (c - '0');
        any = true;
    }
    return any ? n : 0;
}

}

std::uint32_t crc32(std::string_view data) {
    static const std::array<std::uint32_t, 256> table = [] {
        std::array<std::uint32_t, 256> t{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
        return t;
    }();
    std::uint32_t c = 0xFFFFFFFFu;
    for (const char ch : data)
        c = table[(c ^ static_cast<unsigned char>(ch)) & 0xFFu] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

bool extractZipEntry(std::string_view zip, const std::function<bool(std::string_view)>& pick,
                     std::size_t maxUncompressed, ZipEntry& out, std::string& error) {
    if (zip.size() < kEocdSize) {
        error = "not a zip archive";
        return false;
    }
    // EOCD 在末尾,其后最多跟 65535 字节的注释。
    const std::size_t floor = zip.size() > kEocdSize + 0xFFFF ? zip.size() - kEocdSize - 0xFFFF : 0;
    std::size_t eocd = std::string_view::npos;
    for (std::size_t pos = zip.size() - kEocdSize + 1; pos-- > floor;) {
        if (rd32(zip, pos) == kEocdSig) {
            eocd = pos;
            break;
        }
    }
    if (eocd == std::string_view::npos) {
        error = "end of central directory not found";
        return false;
    }
    const std::uint16_t diskNo = rd16(zip, eocd + 4);
    const std::uint16_t cdDisk = rd16(zip, eocd + 6);
    const std::uint16_t entriesHere = rd16(zip, eocd + 8);
    const std::uint16_t entries = rd16(zip, eocd + 10);
    const std::uint32_t cdSize = rd32(zip, eocd + 12);
    const std::uint32_t cdOffset = rd32(zip, eocd + 16);
    if (diskNo != 0 || cdDisk != 0 || entriesHere != entries) {
        error = "multi-volume archives are not supported";
        return false;
    }
    if (entries == 0xFFFFu || cdSize == 0xFFFFFFFFu || cdOffset == 0xFFFFFFFFu) {
        error = "zip64 archives are not supported";
        return false;
    }
    if (!fits(zip, cdOffset, cdSize) || static_cast<std::size_t>(cdOffset) + cdSize > eocd) {
        error = "central directory is out of bounds";
        return false;
    }

    const std::size_t cdEnd = static_cast<std::size_t>(cdOffset) + cdSize;
    std::size_t p = cdOffset;
    for (std::uint32_t i = 0; i < entries; ++i) {
        if (p + kCentralSize > cdEnd || rd32(zip, p) != kCentralSig) {
            error = "corrupt central directory";
            return false;
        }
        const std::uint16_t flags = rd16(zip, p + 8);
        const std::uint16_t method = rd16(zip, p + 10);
        const std::uint32_t crc = rd32(zip, p + 16);
        const std::uint32_t compSize = rd32(zip, p + 20);
        const std::uint32_t uncompSize = rd32(zip, p + 24);
        const std::uint16_t nameLen = rd16(zip, p + 28);
        const std::uint16_t extraLen = rd16(zip, p + 30);
        const std::uint16_t commentLen = rd16(zip, p + 32);
        const std::uint16_t diskStart = rd16(zip, p + 34);
        const std::uint32_t localOff = rd32(zip, p + 42);
        const std::size_t recordLen = kCentralSize + nameLen + extraLen + commentLen;
        if (p + recordLen > cdEnd) {
            error = "corrupt central directory";
            return false;
        }
        const std::string_view name = zip.substr(p + kCentralSize, nameLen);
        p += recordLen;
        if (!pick(name))
            continue;

        if (flags & 0x0001u) {
            error = "encrypted entries are not supported";
            return false;
        }
        if (compSize == 0xFFFFFFFFu || uncompSize == 0xFFFFFFFFu || localOff == 0xFFFFFFFFu
            || diskStart != 0) {
            error = "zip64 entries are not supported";
            return false;
        }
        if (method != 0 && method != 8) {
            error = "unsupported compression method " + std::to_string(method);
            return false;
        }
        if (uncompSize > maxUncompressed) {
            error = "entry exceeds the size limit (" + std::to_string(uncompSize) + " bytes)";
            return false;
        }
        if (!fits(zip, localOff, kLocalSize) || rd32(zip, localOff) != kLocalSig) {
            error = "corrupt local file header";
            return false;
        }
        const std::size_t dataOff = static_cast<std::size_t>(localOff) + kLocalSize
                                  + rd16(zip, localOff + 26) + rd16(zip, localOff + 28);
        if (!fits(zip, dataOff, compSize) || dataOff + compSize > cdOffset) {
            error = "entry data is out of bounds";
            return false;
        }

        std::string data;
        if (method == 0) {
            if (compSize != uncompSize) {
                error = "stored entry size mismatch";
                return false;
            }
            data.assign(zip.substr(dataOff, compSize));
        } else {
            data.resize(uncompSize);
            unsigned long destLen = uncompSize;
            unsigned long srcLen = compSize;
            const int rc = puff(reinterpret_cast<unsigned char*>(data.data()), &destLen,
                                reinterpret_cast<const unsigned char*>(zip.data() + dataOff), &srcLen);
            if (rc != 0 || destLen != uncompSize) {
                error = "corrupt deflate stream (puff " + std::to_string(rc) + ")";
                return false;
            }
        }
        if (crc32(data) != crc) {
            error = "crc-32 mismatch";
            return false;
        }
        out.name.assign(name);
        out.data = std::move(data);
        return true;
    }
    error = "entry not found";
    return false;
}

SplitRules splitRules(std::string_view source) {
    SplitRules out;
    std::vector<std::string> imports;
    bool inBlock = false;
    std::size_t current = 0;
    bool haveCurrent = false;
    std::size_t lineNo = 0;
    std::size_t pos = 0;
    while (pos < source.size()) {
        const std::size_t eol = source.find('\n', pos);
        const std::size_t lineEnd = eol == std::string_view::npos ? source.size() : eol;
        const std::size_t next = eol == std::string_view::npos ? source.size() : eol + 1;
        const std::string_view line = source.substr(pos, lineEnd - pos);
        std::string_view raw = source.substr(pos, next - pos);
        ++lineNo;

        const bool startsInComment = inBlock;
        inBlock = endsInBlockComment(line, inBlock);

        std::string name;
        if (!startsInComment && isImportLine(line)) {
            const std::string imp(trim(line));
            bool seen = false;
            for (const std::string& s : imports)
                seen = seen || s == imp;
            if (!seen)
                imports.push_back(imp);
            if (haveCurrent)
                out.rules[current].text.push_back('\n');
        } else if (!startsInComment && ruleHeaderName(line, name)) {
            RuleChunk chunk;
            chunk.name = std::move(name);
            chunk.line = lineNo;
            chunk.text.assign(raw);
            out.rules.push_back(std::move(chunk));
            current = out.rules.size() - 1;
            haveCurrent = true;
        } else if (haveCurrent) {
            out.rules[current].text.append(raw);
        }
        if (haveCurrent && eol == std::string_view::npos)
            out.rules[current].text.push_back('\n');
        pos = next;
    }
    for (const std::string& imp : imports) {
        out.imports.append(imp);
        out.imports.push_back('\n');
    }
    return out;
}

ForgePackageInfo parseForgePackageInfo(std::string_view source) {
    ForgePackageInfo info;
    bool awaitingRepoCount = false;
    std::size_t pos = 0;
    while (pos < source.size()) {
        const std::size_t eol = source.find('\n', pos);
        const std::size_t lineEnd = eol == std::string_view::npos ? source.size() : eol;
        std::string_view line = trim(source.substr(pos, lineEnd - pos));
        pos = eol == std::string_view::npos ? source.size() : eol + 1;
        if (line.empty() || line.front() != '*')
            continue;
        line.remove_prefix(1);
        line = trim(line);
        const auto value = [&line](std::string_view key) -> std::string_view {
            return line.substr(0, key.size()) == key ? trim(line.substr(key.size())) : std::string_view();
        };
        const std::string_view repo = value("Repository Name:");
        const std::string_view count = value("Number of Rules:");
        const std::string_view name = value("Name:");
        const std::string_view created = value("Creation Date:");
        if (!repo.empty()) {
            info.sources.push_back({std::string(repo), 0});
            awaitingRepoCount = true;
        } else if (!count.empty()) {
            if (awaitingRepoCount)
                info.sources.back().rules = parseCount(count);
            else if (info.declaredRules == 0)
                info.declaredRules = parseCount(count);
            awaitingRepoCount = false;
        } else if (!name.empty() && info.name.empty() && info.sources.empty()) {
            info.name.assign(name);
        } else if (!created.empty() && info.created.empty()) {
            info.created.assign(created);
        }
    }
    return info;
}

}
