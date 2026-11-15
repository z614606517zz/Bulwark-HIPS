#pragma once
#include <QDialog>

#include <optional>

#include "bulwark/models/SecurityEvent.h"
#include "dialogs/EventViews.h"

class IpcClient;
class QBoxLayout;

class AttackTimelineWindow : public QDialog
{
    Q_OBJECT
public:
    explicit AttackTimelineWindow(const bulwark::SecurityEvent& event, QWidget* parent = nullptr,
                                  IpcClient* ipc = nullptr,
                                  std::optional<evtview::Outcome> outcome = std::nullopt);

protected:
    void resizeEvent(QResizeEvent* e) override;

private:
    QBoxLayout* m_columns = nullptr;
};
