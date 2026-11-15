#pragma once
#include <QHash>
#include <QObject>
#include <QString>

#include "bulwark/models/Enums.h"

class QTimer;

class VoiceAnnouncer : public QObject
{
    Q_OBJECT
public:
    enum class Status {
        Idle,
        Ready,
        NoChineseVoice,
        Unavailable,
    };

    static VoiceAnnouncer* instance();
    ~VoiceAnnouncer() override;

    bool isEnabled() const { return m_enabled; }
    void setEnabled(bool on);
    Status status() const { return m_enabled ? m_engineStatus : Status::Idle; }

    void announceBlock(const QString& actorPath, bulwark::EnforcementOutcome enforcement);
    void announceBatch(int blocked, int unenforced);

signals:
    void statusChanged();

private:
    explicit VoiceAnnouncer(QObject* parent);

    bool alreadySpoken(const QString& actorPath, const QString& sentence);
    void enqueue(const QString& sentence, int blocked, int unenforced);
    bool ensureEngine();
    void speak(const QString& sentence);
    void poll();
    bool flushPending();
    void stopSpeaking();
    void shutdown();
    void setEngineStatus(Status s);

    struct Impl;
    Impl* d = nullptr;

    bool m_enabled = false;
    bool m_engineTried = false;
    bool m_shutDown = false;
    Status m_engineStatus = Status::Idle;

    bool m_busy = false;
    qint64 m_busySinceMs = 0;
    QString m_current;

    int m_pendingItems = 0;
    int m_pendingBlocked = 0;
    int m_pendingUnenforced = 0;
    QString m_pendingSentence;

    QHash<QString, qint64> m_spoken;

    QTimer* m_poll = nullptr;
};
