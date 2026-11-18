#pragma once
#include <QByteArray>
namespace bulwark::engine {
enum class FileIntegrity { Unchecked, Valid, Invalid, Unsupported };
class ZipIntegrity {
public:
    static constexpr qint64 maxArchiveBytes = 16 * 1024 * 1024;
    static constexpr qint64 maxExpandedBytes = 32 * 1024 * 1024;
    // Valid only when every supported entry was decoded and its CRC verified.
    // Unsupported includes encryption, ZIP64, and exhausted size/time budgets.
    static FileIntegrity verify(const QByteArray& archive);
};
}
