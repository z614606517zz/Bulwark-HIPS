#pragma once
#include <QDateTime>
#include <QHash>
#include <QList>
#include <QString>
#include <QUuid>
#include <QWidget>

class IpcClient;
class LampWidget;
class QLabel;
class QShowEvent;
class QVBoxLayout;
class SevenSegCounter;
class StickerText;

// 仪表盘 = 驾驶舱:表情屏(小垒的眼睛就是防护状态)、战绩数码管、24 小时战况雷达、
// 防护维度拨杆、作战日志、任务简报。
class DashboardPage : public QWidget
{
    Q_OBJECT
public:
    explicit DashboardPage(IpcClient* ipc, QWidget* parent = nullptr);

protected:
    void showEvent(QShowEvent* e) override;

private:
    struct Dimension {
        QWidget* lever = nullptr;
        int on = -1;
    };

    QWidget* buildFace();
    QWidget* buildCounters();
    QWidget* buildRadar();
    QWidget* buildDimensions();
    QWidget* buildLog();
    QWidget* buildMissions();
    // 金刚皮肤按设计稿另搭一套器件;数据和刷新逻辑与上面共用。
    QWidget* buildFaceTitan();
    QWidget* buildCountersTitan();
    QWidget* buildRadarTitan();
    QWidget* buildDimensionsTitan();
    QWidget* buildLogTitan();
    QWidget* buildMissionsTitan();
    void setDimension(const QString& key, int on);
    void refreshFace();
    void refreshMissions();
    void refreshTally();
    void requestChart(bool force);

    IpcClient* m_ipc = nullptr;

    QWidget* m_face = nullptr;
    QLabel* m_faceStatus = nullptr;
    StickerText* m_faceTitle = nullptr;
    QLabel* m_faceSub = nullptr;
    LampWidget* m_segKernel = nullptr;
    LampWidget* m_segService = nullptr;
    LampWidget* m_segDims = nullptr;
    LampWidget* m_segTasks = nullptr;
    QLabel* m_segKernelText = nullptr;
    QLabel* m_segDimsText = nullptr;
    QLabel* m_segTasksText = nullptr;

    bool m_connected = false;
    bool m_haveSettings = false;
    bool m_protectionEnabled = false;
    bool m_kernelConnected = false;
    QString m_kernelStatus;

    SevenSegCounter* m_statBlocked = nullptr;
    SevenSegCounter* m_statEvents = nullptr;
    SevenSegCounter* m_statQuarantine = nullptr;
    SevenSegCounter* m_statRules = nullptr;

    QWidget* m_chart = nullptr;
    QLabel* m_chartNote = nullptr;
    QUuid m_chartRequest;
    QDateTime m_chartFetched;

    QVBoxLayout* m_missionBox = nullptr;
    QLabel* m_missionCount = nullptr;
    QWidget* m_missionMarker = nullptr;   // 金刚:任务简报面板头的色标,有待办时转琥珀
    QLabel* m_tally = nullptr;
    int m_unenforced = 0;

    QVBoxLayout* m_logBox = nullptr;
    QLabel* m_logEmpty = nullptr;
    QHash<QString, Dimension> m_dims;
    QLabel* m_dimsNote = nullptr;

    int m_blockedCount = 0;
    int m_eventCount = 0;
    int m_askCount = 0;
    int m_allowCount = 0;
    int m_logRows = 0;
};
