#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

// YARA Forge 规则包的离线处理:取出 ZIP 里的 .yar、按规则切块、读包头统计。
// 不依赖 Qt 与 YARA-X,编译程序和单元测试共用同一份实现。
namespace bulwark::yara {

std::uint32_t crc32(std::string_view data);

struct ZipEntry {
    std::string name;
    std::string data;
};

// 取出第一条名字满足 pick 的条目。只支持存储(0)与 deflate(8),并校验 CRC-32;
// 加密、ZIP64、多卷与解压后超过 maxUncompressed 的条目一律拒绝。
bool extractZipEntry(std::string_view zip, const std::function<bool(std::string_view)>& pick,
                     std::size_t maxUncompressed, ZipEntry& out, std::string& error);

struct RuleChunk {
    std::string name;
    std::size_t line = 0;
    std::string text;
};

struct SplitRules {
    std::string imports;
    std::vector<RuleChunk> rules;
};

// 以「行首的 rule 声明」为界切块,每块单独交给编译器:一条规则编译不过只丢它自己。
// import 行统一收进 imports,每块编译前补在前面;块内出现的 import 行替换为空行。
SplitRules splitRules(std::string_view source);

struct ForgeSource {
    std::string repository;
    int rules = 0;
};

struct ForgePackageInfo {
    std::string name;
    std::string created;
    int declaredRules = 0;
    std::vector<ForgeSource> sources;
};

// 读 YARA Forge 写在注释里的包头(Name / Creation Date / Number of Rules)
// 与各来源仓库的分节头(Repository Name / Number of Rules)。
ForgePackageInfo parseForgePackageInfo(std::string_view source);

}
