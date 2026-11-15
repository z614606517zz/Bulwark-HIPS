#pragma once
#include <QString>

namespace bulwark::service {

enum class RegHive { LocalMachine, CurrentUser, ClassesRoot, Users, CurrentConfig };
enum class RegView { Default, Registry32, Registry64 };

namespace RegSurgery {

bool forceDeleteValue(RegHive hive, const QString& subKey, const QString& valueName,
                      RegView view = RegView::Default);

bool forceDeleteSubKeyTree(RegHive hive, const QString& parentSubKey, const QString& childName,
                           RegView view = RegView::Default);

}
}
