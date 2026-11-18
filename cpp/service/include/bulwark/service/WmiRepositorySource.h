#pragma once
#include "bulwark/service/EventSource.h"
#include "bulwark/service/Logger.h"
#include <memory>
#include <thread>
class QTimer;
namespace bulwark::service {
class WmiRepositorySource : public EventSource {
    Q_OBJECT
public:
    explicit WmiRepositorySource(QObject* parent=nullptr);
    ~WmiRepositorySource() override;
    void start() override;
    void stop() override;
    bool isAvailable() const override;
private:
    struct Shared;
    static void run(const std::shared_ptr<Shared>& state);
    std::shared_ptr<Shared> state_;
    std::thread thread_;
    QTimer* timer_=nullptr;
    Logger log_{QStringLiteral("bulwark.service.WmiRepository")};
};
}
