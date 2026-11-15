#pragma once
#include <QString>

namespace bulwark {
struct SecurityEvent;
}

namespace bulwark::service {

bool looksLikeInstaller(const bulwark::SecurityEvent& e, QString* displayName = nullptr);

// PE 版本资源里的 OriginalFilename,转小写并去掉 .mui 后缀;读不到返回空串。
// 位于 Windows 目录或 Program Files 下的程序直接返回空:那里的系统工具不需要核对改名。
QString originalFileNameOutsideInstallDirs(const QString& path);

}
