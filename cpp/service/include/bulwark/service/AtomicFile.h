#pragma once
#include "bulwark/service/Logger.h"

#include <QByteArray>
#include <QFile>
#include <QSaveFile>
#include <QString>

namespace bulwark::service {

inline bool writeFileAtomically(const QString& path, const QByteArray& bytes,
                                const QString& whatForLog = QString()) {
    {
        QSaveFile sf(path);
        if (sf.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            if (sf.write(bytes) == bytes.size() && sf.commit())
                return true;
            sf.cancelWriting();
        }
    }

    // 退路:非原子就地覆写。先留 .bak,写失败时用它恢复原内容,不能把原文件删掉。
    const QString bak = path + QStringLiteral(".bak");
    const bool hadOld = QFile::exists(path);
    if (hadOld) {
        QFile::remove(bak);
        if (!QFile::copy(path, bak))
            return false;
    }
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return false;
    const bool ok = (f.write(bytes) == bytes.size()) && f.flush();
    f.close();
    if (!ok) {
        f.remove();
        if (hadOld)
            QFile::copy(bak, path);
    }
    if (hadOld)
        QFile::remove(bak);
    Logger(QStringLiteral("bulwark.service.Store"))
        .warning(QStringLiteral("原子写入不可用,已退回就地覆写%1(ok=%2):%3")
                     .arg(whatForLog.isEmpty() ? QString() : QStringLiteral("(") + whatForLog + QStringLiteral(")"))
                     .arg(ok ? 1 : 0)
                     .arg(path));
    return ok;
}

}
