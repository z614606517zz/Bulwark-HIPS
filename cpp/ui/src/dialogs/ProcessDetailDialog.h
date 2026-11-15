#pragma once
#include <QDialog>
#include "bulwark/models/ProcessEntry.h"

class IpcClient;

class ProcessDetailDialog : public QDialog
{
    Q_OBJECT
public:
    ProcessDetailDialog(const bulwark::ProcessEntry& entry, IpcClient* ipc, QWidget* parent = nullptr);
};
