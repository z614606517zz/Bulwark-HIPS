#pragma once
#include <QString>

namespace bulwark::engine {

struct SystemPaths {
    static QString volumeRelative(const QString& path);

    // Windows 所在卷的盘符,小写,形如 "c:"。
    static QString systemDrive();

    // path 位于系统盘时返回去掉盘符后的部分(以 '\' 开头,保留原大小写),否则返回空串。
    // 「位于系统目录 / Program Files 下即可信」一类判定必须用它而不是 volumeRelative:
    // U 盘、挂载的 ISO、第二块硬盘上都能建出同名目录。
    static QString systemVolumeRelative(const QString& path);

    // 测试用:固定系统盘,使结果与运行机器无关;传空串恢复为实际系统盘。
    static void setSystemDriveForTest(const QString& drive);
};

}
