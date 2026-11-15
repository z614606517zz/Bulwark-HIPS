#pragma once
#include <QString>
#include <QStringList>
#include <QVector>

namespace bulwark::service {

class InstallDirAclCheck {
public:
    struct Target {
        QString path;
        bool readable = false;
        bool writableByNonAdmin = false;
        QStringList who;
        QString error;
    };

    struct Report {
        QVector<Target> targets;
        bool checked = false;
        bool anyWritable = false;
        bool anyUnreadable = false;

        bool intact() const { return checked && !anyWritable && !anyUnreadable; }
        QString detail() const;
    };

    static bool daclGrantsNonAdminWrite(const void* dacl, QStringList* who = nullptr);

    static Report check(const QString& installDir);
};

}
