#pragma once
#include "bulwark/models/SecurityEvent.h"
#include <QHash>
#include <algorithm>

namespace bulwark::service {
struct WmiObjectFingerprint { QString type,digest; };
class WmiRepositoryPolicy {
public:
    struct Result { QVector<bulwark::SecurityEvent> events; bool baseline=false,accepted=false,backlog=false; };
    Result update(const QHash<QString,WmiObjectFingerprint>& current,bool complete) {
        Result result;
        if (!complete || current.size()>4096) return result;
        for (auto it=current.constBegin();it!=current.constEnd();++it)
            if (it.key().isEmpty() || it->type.isEmpty() || it->digest.isEmpty()) return result;
        result.accepted=true;
        if (!primed_) { previous_=current;primed_=true;result.baseline=true;return result; }
        auto next=current;
        auto keys=current.keys(); std::sort(keys.begin(),keys.end());
        for (const QString& key:keys) {
            const auto item=current.value(key);
            const auto old=previous_.constFind(key);
            if (old!=previous_.constEnd() && old->digest==item.digest && old->type==item.type) continue;
            if (result.events.size()>=64) {
                result.backlog=true;
                // Changes not enqueued stay pending for the next successful poll.
                if (old!=previous_.constEnd()) next.insert(key,old.value()); else next.remove(key);
                continue;
            }
            bulwark::SecurityEvent e;e.type=bulwark::EventType::WmiSubscription;e.userModeObserved=true;
            e.actorPath=QStringLiteral("WMI repository (caller unknown)");e.target=key;
            e.auditOperation=(old==previous_.constEnd()?QStringLiteral("新增 "):QStringLiteral("修改 "))+item.type;
            e.detail=QStringLiteral("只读 WMI 对象快照检测到%1；载荷指纹 %2。属于变更后告警，未推断调用方，不记录脚本正文")
                .arg(e.auditOperation,item.digest);
            result.events.push_back(e);
        }
        previous_=std::move(next);
        return result;
    }
private:
    bool primed_=false;
    QHash<QString,WmiObjectFingerprint> previous_;
};
}
