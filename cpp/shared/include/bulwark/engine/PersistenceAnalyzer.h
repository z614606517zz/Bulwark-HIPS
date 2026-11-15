#pragma once
#include <QString>
#include "bulwark/models/PersistenceEntry.h"

namespace bulwark::engine {

// 给「已存在的」自启动项评风险(持久化扫描列表的排序与理由),不产生裁决。
struct PersistenceAnalyzer {
    static void analyze(bulwark::PersistenceEntry& entry);

    static QString techniqueFor(bulwark::PersistenceCategory c);
};

}
