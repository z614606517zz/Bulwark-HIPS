#include "voice/VoiceAnnouncer.h"
// 「算不算需要用户自己动手」这条界线必须与右下角通知逐字一致,所以共用 EventFormat 里的那个
// 判据,而不是在这里再手写一份。
#include "dialogs/EventFormat.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QFileInfo>
#include <QPointer>
#include <QRegularExpression>
#include <QSettings>
#include <QStringList>
#include <QTimer>
#include <QtGlobal>

#include <algorithm>

#ifdef Q_OS_WIN
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <sapi.h>
#  include <wrl/client.h>
#endif

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

const char kSettingKey[] = "ui/voiceAnnounceBlocks";

constexpr int kPollMs = 200;
constexpr qint64 kStuckMs = 30000;
constexpr int kMaxSpokenNameLen = 24;
constexpr int kMaxSpokenKeys = 2048;

QString spokenProgram(const QString& actorPath)
{
    static const QRegularExpression separators(QStringLiteral("[._\\-]+"));
    QString name = QFileInfo(actorPath).completeBaseName();
    name.replace(separators, QStringLiteral(" "));
    name = name.simplified();
    return name.size() > kMaxSpokenNameLen ? QString() : name;
}

QString blockSentence(const QString& actorPath, bulwark::EnforcementOutcome enforcement)
{
    using EO = bulwark::EnforcementOutcome;
    const QString who = spokenProgram(actorPath);
    const QString what = who.isEmpty() ? u("危险行为") : u(" %1 的危险行为").arg(who);
    switch (enforcement) {
    case EO::AlertedOnly:       return u("检测到%1,未能拦截,请手动处理").arg(what);
    case EO::Failed:            return u("检测到%1,处置未成功,请手动处理").arg(what);
    case EO::Terminated:        return u("已拦截%1,并结束了该进程").arg(what);
    case EO::ModuleBlacklisted: return u("已拦截%1,相关模块已禁止加载").arg(what);
    case EO::ExecDenied:        return u("已拦截%1,并已禁止它再次启动").arg(what);
    case EO::WriteUndone:       return u("已拦截%1,并撤销了刚才的写入").arg(what);
    case EO::PayloadQuarantined: return u("已处置%1,恶意文件已移入隔离区").arg(what);
    case EO::ActorAlreadyGone:  return u("检测到%1,发起进程此前已被结束").arg(what);
    case EO::KernelBlocked:
    case EO::NotApplicable:     break;
    }
    return u("已拦截%1").arg(what);
}

QString batchSentence(int blocked, int unenforced, bool followUp)
{
    const int total = blocked + unenforced;
    if (unenforced <= 0)
        return followUp ? u("又拦截了 %1 项危险行为").arg(blocked)
                        : u("短时间内共拦截 %1 项危险行为").arg(blocked);
    if (blocked <= 0)
        return followUp ? u("又有 %1 项危险行为未能拦截,请手动处理").arg(unenforced)
                        : u("短时间内有 %1 项危险行为未能拦截,请手动处理").arg(unenforced);
    return followUp ? u("又有 %1 项危险行为,其中 %2 项未能拦截,请手动处理").arg(total).arg(unenforced)
                    : u("短时间内共 %1 项危险行为,其中 %2 项未能拦截,请手动处理").arg(total).arg(unenforced);
}

#ifdef Q_OS_WIN
using Microsoft::WRL::ComPtr;

bool isChineseVoice(ISpObjectToken* token)
{
    ComPtr<ISpDataKey> attrs;
    if (!token || FAILED(token->OpenKey(L"Attributes", attrs.GetAddressOf())) || !attrs)
        return false;
    LPWSTR raw = nullptr;
    if (FAILED(attrs->GetStringValue(L"Language", &raw)) || !raw)
        return false;
    const QString langs = QString::fromWCharArray(raw);
    ::CoTaskMemFree(raw);
    for (const QString& part : langs.split(QLatin1Char(';'), Qt::SkipEmptyParts)) {
        bool ok = false;
        const uint lcid = part.trimmed().toUInt(&ok, 16);
        if (ok && PRIMARYLANGID(static_cast<WORD>(lcid)) == LANG_CHINESE)
            return true;
    }
    return false;
}

bool selectChineseVoice(ISpVoice* voice)
{
    ComPtr<ISpObjectToken> current;
    if (SUCCEEDED(voice->GetVoice(current.GetAddressOf())) && isChineseVoice(current.Get()))
        return true;

    const wchar_t* const categories[] = {
        SPCAT_VOICES,
        L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Speech_OneCore\\Voices",
    };
    const wchar_t* const languages[] = {L"Language=804", L"Language=404"};
    for (const wchar_t* category : categories) {
        ComPtr<ISpObjectTokenCategory> cat;
        if (FAILED(::CoCreateInstance(__uuidof(SpObjectTokenCategory), nullptr, CLSCTX_ALL,
                                      IID_PPV_ARGS(cat.GetAddressOf())))
            || FAILED(cat->SetId(category, FALSE)))
            continue;
        for (const wchar_t* language : languages) {
            ComPtr<IEnumSpObjectTokens> tokens;
            if (FAILED(cat->EnumTokens(language, nullptr, tokens.GetAddressOf())) || !tokens)
                continue;
            for (;;) {
                ComPtr<ISpObjectToken> token;
                ULONG fetched = 0;
                if (tokens->Next(1, token.GetAddressOf(), &fetched) != S_OK || fetched != 1 || !token)
                    break;
                if (SUCCEEDED(voice->SetVoice(token.Get())))
                    return true;
            }
        }
    }
    return false;
}
#endif

}

struct VoiceAnnouncer::Impl {
#ifdef Q_OS_WIN
    ComPtr<ISpVoice> voice;
    bool comInit = false;
#endif
};

VoiceAnnouncer* VoiceAnnouncer::instance()
{
    static QPointer<VoiceAnnouncer> s;
    if (!s)
        s = new VoiceAnnouncer(QCoreApplication::instance());
    return s;
}

VoiceAnnouncer::VoiceAnnouncer(QObject* parent) : QObject(parent), d(new Impl)
{
    m_enabled = QSettings().value(QLatin1String(kSettingKey), false).toBool();

    m_poll = new QTimer(this);
    m_poll->setInterval(kPollMs);
    connect(m_poll, &QTimer::timeout, this, &VoiceAnnouncer::poll);

    if (QCoreApplication* app = QCoreApplication::instance())
        connect(app, &QCoreApplication::aboutToQuit, this, &VoiceAnnouncer::shutdown);

    if (m_enabled)
        QTimer::singleShot(0, this, [this] {
            if (m_enabled)
                ensureEngine();
        });
}

VoiceAnnouncer::~VoiceAnnouncer()
{
    shutdown();
    delete d;
}

void VoiceAnnouncer::setEnabled(bool on)
{
    if (on == m_enabled)
        return;
    m_enabled = on;
    QSettings().setValue(QLatin1String(kSettingKey), on);
    if (on) {
        m_engineTried = false;
        ensureEngine();
    } else {
        stopSpeaking();
    }
    emit statusChanged();
}

void VoiceAnnouncer::announceBlock(const QString& actorPath, bulwark::EnforcementOutcome enforcement)
{
    if (!m_enabled || !ensureEngine())
        return;
    const QString sentence = blockSentence(actorPath, enforcement);
    if (alreadySpoken(actorPath, sentence))
        return;
    const bool unenforced = evtfmt::needsManualAction(enforcement);
    enqueue(sentence, unenforced ? 0 : 1, unenforced ? 1 : 0);
}

bool VoiceAnnouncer::alreadySpoken(const QString& actorPath, const QString& sentence)
{
    const QString key = actorPath + QLatin1Char('|') + sentence;
    if (m_spoken.contains(key))
        return true;
    if (m_spoken.size() >= kMaxSpokenKeys) {
        QList<qint64> stamps = m_spoken.values();
        std::nth_element(stamps.begin(), stamps.begin() + stamps.size() / 4, stamps.end());
        const qint64 cutoff = stamps.at(stamps.size() / 4);
        for (auto it = m_spoken.begin(); it != m_spoken.end();) {
            if (it.value() <= cutoff)
                it = m_spoken.erase(it);
            else
                ++it;
        }
    }
    m_spoken.insert(key, QDateTime::currentMSecsSinceEpoch());
    return false;
}

void VoiceAnnouncer::announceBatch(int blocked, int unenforced)
{
    blocked = qMax(0, blocked);
    unenforced = qMax(0, unenforced);
    if (blocked + unenforced <= 0)
        return;
    enqueue(batchSentence(blocked, unenforced, false), blocked, unenforced);
}

void VoiceAnnouncer::enqueue(const QString& sentence, int blocked, int unenforced)
{
    if (!m_enabled || !ensureEngine())
        return;
    if (!m_busy) {
        speak(sentence);
        return;
    }
    ++m_pendingItems;
    m_pendingBlocked += blocked;
    m_pendingUnenforced += unenforced;
    m_pendingSentence = sentence;
}

bool VoiceAnnouncer::ensureEngine()
{
    if (m_shutDown)
        return false;
#ifdef Q_OS_WIN
    if (d->voice)
        return true;
    if (m_engineTried)
        return false;
    m_engineTried = true;

    const HRESULT init = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(init) && init != RPC_E_CHANGED_MODE) {
        qWarning("VoiceAnnouncer: CoInitializeEx failed (0x%08lx)", static_cast<unsigned long>(init));
        setEngineStatus(Status::Unavailable);
        return false;
    }
    d->comInit = SUCCEEDED(init);

    const HRESULT hr = ::CoCreateInstance(__uuidof(SpVoice), nullptr, CLSCTX_ALL,
                                          IID_PPV_ARGS(d->voice.GetAddressOf()));
    if (FAILED(hr) || !d->voice) {
        qWarning("VoiceAnnouncer: cannot create SAPI SpVoice (0x%08lx)", static_cast<unsigned long>(hr));
        d->voice.Reset();
        if (d->comInit) {
            ::CoUninitialize();
            d->comInit = false;
        }
        setEngineStatus(Status::Unavailable);
        return false;
    }
    d->voice->SetInterest(0, 0);
    setEngineStatus(selectChineseVoice(d->voice.Get()) ? Status::Ready : Status::NoChineseVoice);
    return true;
#else
    m_engineTried = true;
    setEngineStatus(Status::Unavailable);
    return false;
#endif
}

void VoiceAnnouncer::speak(const QString& sentence)
{
#ifdef Q_OS_WIN
    if (!d->voice)
        return;
    m_current = sentence;
    // SPF_IS_NOT_XML:句子里的程序名由样本自己决定,绝不能被当成 SAPI XML 解析(音量 / 静音 / 改读音标签)。
    const HRESULT hr = d->voice->Speak(reinterpret_cast<LPCWSTR>(m_current.utf16()),
                                       static_cast<DWORD>(SPF_ASYNC | SPF_IS_NOT_XML), nullptr);
    if (FAILED(hr)) {
        qWarning("VoiceAnnouncer: Speak failed (0x%08lx)", static_cast<unsigned long>(hr));
        m_current.clear();
        return;
    }
    m_busy = true;
    m_busySinceMs = QDateTime::currentMSecsSinceEpoch();
    m_poll->start();
#else
    Q_UNUSED(sentence);
#endif
}

void VoiceAnnouncer::poll()
{
#ifdef Q_OS_WIN
    if (d->voice && m_busy) {
        const HANDLE doneEvent = d->voice->SpeakCompleteEvent();
        const bool done = !doneEvent || ::WaitForSingleObject(doneEvent, 0) == WAIT_OBJECT_0;
        if (!done && QDateTime::currentMSecsSinceEpoch() - m_busySinceMs < kStuckMs)
            return;
        if (!done)
            d->voice->Speak(nullptr, SPF_PURGEBEFORESPEAK, nullptr);
    }
#endif
    m_busy = false;
    m_current.clear();
    if (!flushPending())
        m_poll->stop();
}

bool VoiceAnnouncer::flushPending()
{
    if (m_pendingItems <= 0)
        return false;
    const QString sentence = m_pendingItems == 1
                                 ? m_pendingSentence
                                 : batchSentence(m_pendingBlocked, m_pendingUnenforced, true);
    m_pendingItems = 0;
    m_pendingBlocked = 0;
    m_pendingUnenforced = 0;
    m_pendingSentence.clear();
    speak(sentence);
    return m_busy;
}

void VoiceAnnouncer::stopSpeaking()
{
    m_pendingItems = 0;
    m_pendingBlocked = 0;
    m_pendingUnenforced = 0;
    m_pendingSentence.clear();
#ifdef Q_OS_WIN
    if (d->voice && m_busy)
        d->voice->Speak(nullptr, SPF_PURGEBEFORESPEAK, nullptr);
#endif
    m_busy = false;
    m_current.clear();
    if (m_poll)
        m_poll->stop();
}

void VoiceAnnouncer::shutdown()
{
    if (m_shutDown)
        return;
    m_shutDown = true;
    stopSpeaking();
#ifdef Q_OS_WIN
    d->voice.Reset();
    if (d->comInit) {
        ::CoUninitialize();
        d->comInit = false;
    }
#endif
}

void VoiceAnnouncer::setEngineStatus(Status s)
{
    if (m_engineStatus == s)
        return;
    m_engineStatus = s;
    if (m_enabled)
        emit statusChanged();
}
