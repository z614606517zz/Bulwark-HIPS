#pragma once
#include <QAbstractNativeEventFilter>
#include <QObject>
#include <QString>

#include <functional>

class QWidget;
class QTimer;

namespace bulwark::ui {

class WindowGuard : public QObject, public QAbstractNativeEventFilter {
    Q_OBJECT
public:
    using ReportHandler = std::function<void(const QString& what, const QString& detail)>;

    explicit WindowGuard(QWidget* mainWindow, QObject* parent = nullptr);
    ~WindowGuard() override;

    void setReportHandler(ReportHandler fn) { report_ = std::move(fn); }

    void setExpectedHidden(bool hidden) { expectedHidden_ = hidden; }
    bool expectedHidden() const { return expectedHidden_; }

    bool consumeCloseToTrayAuthorization();

    void arm();

    void allowQuit(const QString& reason);
    bool quitAllowed() const { return quitReason_.isEmpty() ? false : true; }

    bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;

    bool windowNativeEvent(const QByteArray& eventType, void* message, qintptr* result);

private slots:
    void onStateTick();
    void onAboutToQuit();

private:
    void hardenMessageFilters();
    void snapshotGeometry();
    void emitReport(const QString& what, const QString& detail);
    void logOnly(const QString& what, const QString& detail);

    bool filterSysClose(quintptr wParam, qintptr* result, const char* via);

    void noteUserCloseIntent();
    bool userCloseIntentFresh() const;
    void armUserCloseSequence();
    bool userCloseSequenceFresh() const;
    void clearUserCloseSequence();
    static bool physicalInputFresh(unsigned withinMs);

    QWidget* win_ = nullptr;
    QTimer*  tick_ = nullptr;
    ReportHandler report_;

    QString quitReason_;
    bool    armed_ = false;
    bool    relaunching_ = false;

    int wantW_ = 0, wantH_ = 0;
    bool expectedHidden_ = false;

    QString lastReported_;

    quint32 closeIntentTick_ = 0;
    bool    haveCloseIntent_ = false;
    quint32 closeSequenceTick_ = 0;
    bool    pendingUserCloseSequence_ = false;
    quint32 closeToTrayAuthorizationTick_ = 0;
    bool    closeToTrayAuthorized_ = false;

    static constexpr int kTickMs = 1500;
    static constexpr unsigned kIntentWindowMs = 3000;
    static constexpr unsigned kCloseAuthorizationMs = 2000;
};

}
