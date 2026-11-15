#pragma once
#include <QList>
#include <QDateTime>
#include <QUuid>
#include <memory>
#include <optional>
#include "bulwark/ipc/Payloads.h"

namespace bulwark::service {

class EventHistoryStore {
public:
    EventHistoryStore();
    ~EventHistoryStore();

    void add(const bulwark::ipc::EventLogPayload& payload);
    QList<bulwark::ipc::EventLogPayload> getRecent();
    void clear();

    bulwark::ipc::TimelineResponsePayload query(const bulwark::ipc::TimelineRequestPayload& req);

    QList<bulwark::ipc::EventLogPayload> eventsInWindow(const QDateTime& fromUtc,
                                                       const QDateTime& toUtc, int maxEvents);

    std::optional<bulwark::ipc::EventLogPayload> findById(const QUuid& id);

private:
    struct Impl;
    std::unique_ptr<Impl> d_;
};

}
