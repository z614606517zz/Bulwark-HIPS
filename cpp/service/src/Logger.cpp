#include "bulwark/service/Logger.h"

#include <QCoreApplication>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <stdexcept>
#include <thread>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#endif

namespace bulwark::service {
namespace {

class FileLogSink {
public:
    void start() {
        std::lock_guard<std::mutex> lk(mutex_);
        if (running_) return;
        path_ = logFilePath();
        disposed_ = false;
        running_ = true;
        worker_ = std::thread([this] { writeLoop(); });
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (!running_) return;
            disposed_ = true;
        }
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
        running_ = false;
    }

    void enqueue(const QString& line) {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (disposed_ || !running_) return;
            if (queue_.size() >= kMaxQueue) return;
            queue_.push_back(line);
        }
        cv_.notify_one();
    }

private:
    void writeLoop() {
        for (;;) {
            QByteArray batch;
            {
                std::unique_lock<std::mutex> lk(mutex_);
                cv_.wait(lk, [this] { return disposed_ || !queue_.empty(); });
                if (queue_.empty()) {
                    if (disposed_) return;
                    continue;
                }
                int count = 0;
                while (!queue_.empty() && count < kMaxBatch) {
                    batch += queue_.front().toUtf8();
                    queue_.pop_front();
                    ++count;
                }
            }
            if (!batch.isEmpty())
                writeBatch(batch);
        }
    }

    void writeBatch(const QByteArray& bytes) {
        QFileInfo fi(path_);
        if (fi.exists() && fi.size() > kMaxLogBytes) {
            const QString bak = path_ + ".1";
            QFile::remove(bak);
            QFile::rename(path_, bak);
        }
        QFile f(path_);
        if (f.open(QIODevice::Append | QIODevice::WriteOnly)) {
            f.write(bytes);
            f.close();
        }
        // Write failures are ignored; logging must not affect callers.
    }

    static constexpr size_t kMaxQueue   = 8192;
    static constexpr int    kMaxBatch   = 512;
    static constexpr qint64 kMaxLogBytes = 5LL * 1024 * 1024;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<QString> queue_;
    std::thread worker_;
    std::atomic<bool> running_{false};   // stop() 在锁外写它,所以必须是原子的
    bool disposed_ = false;
    QString path_;
};

FileLogSink& sink() {
    static FileLogSink s;
    return s;
}

const char* levelTag(LogLevel level) {
    switch (level) {
        case LogLevel::Trace:       return "trce";
        case LogLevel::Debug:       return "dbug";
        case LogLevel::Information: return "info";
        case LogLevel::Warning:     return "warn";
        case LogLevel::Error:       return "fail";
        case LogLevel::Critical:    return "crit";
    }
    return "info";
}

#ifdef _WIN32
bool setPrivateAcl(const QString& path, PACL dacl, PSID owner) {
    std::wstring native = QDir::toNativeSeparators(path).toStdWString();
    DWORD rc = ::SetNamedSecurityInfoW(
        native.data(), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
            | PROTECTED_DACL_SECURITY_INFORMATION,
        owner, nullptr, dacl, nullptr);
    if (rc != ERROR_SUCCESS) {
        // 某些管理员启动路径没有设置 owner 所需的令牌权限；DACL 收紧仍必须尝试。
        rc = ::SetNamedSecurityInfoW(native.data(), SE_FILE_OBJECT,
                                     DACL_SECURITY_INFORMATION
                                         | PROTECTED_DACL_SECURITY_INFORMATION,
                                     nullptr, nullptr, dacl, nullptr);
    }
    return rc == ERROR_SUCCESS;
}

void secureDefaultDataTree(const QString& root) {
    const QString nativeRoot = QDir::toNativeSeparators(root);
    const DWORD rootAttrs = ::GetFileAttributesW(
        reinterpret_cast<const wchar_t*>(nativeRoot.utf16()));
    if (rootAttrs == INVALID_FILE_ATTRIBUTES || (rootAttrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
        ::OutputDebugStringW(L"[Bulwark] ProgramData ACL: root missing or is a reparse point; refused.\n");
        return;
    }

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
            SDDL_REVISION_1, &descriptor, nullptr)) {
        ::OutputDebugStringW(L"[Bulwark] ProgramData ACL: invalid security descriptor.\n");
        return;
    }

    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = nullptr;
    PSID owner = nullptr;
    BOOL ownerDefaulted = FALSE;
    const bool parsed =
        ::GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) != FALSE
        && present && dacl != nullptr
        && ::GetSecurityDescriptorOwner(descriptor, &owner, &ownerDefaulted) != FALSE
        && owner != nullptr;
    if (!parsed || !setPrivateAcl(root, dacl, owner)) {
        ::OutputDebugStringW(L"[Bulwark] ProgramData ACL: failed to secure root.\n");
        ::LocalFree(descriptor);
        return;
    }

    // 根目录先收紧后再迁移既有子项，消除普通用户在遍历期间继续预创建文件的竞态。
    QDirIterator it(root, QDir::AllEntries | QDir::Hidden | QDir::System | QDir::NoDotAndDotDot,
                    QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QString path = it.next();
        const DWORD attrs = ::GetFileAttributesW(
            reinterpret_cast<const wchar_t*>(QDir::toNativeSeparators(path).utf16()));
        if (attrs == INVALID_FILE_ATTRIBUTES)
            continue;
        if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) {
            ::OutputDebugStringW(L"[Bulwark] ProgramData ACL: reparse point skipped.\n");
            continue;
        }
        (void)setPrivateAcl(path, dacl, owner);
    }
    ::LocalFree(descriptor);
}
#endif

}

QString programDataDir() {
    // 自定义目录用于便携/非管理员调试，不擅自改 ACL；正式 ProgramData 根必须由服务收紧。
    QString dir = qEnvironmentVariable("BULWARK_DATA_DIR").trimmed();
    const bool defaultLocation = dir.isEmpty();
    if (defaultLocation) {
        QString base = qEnvironmentVariable("ProgramData");
        if (base.isEmpty()) base = QStringLiteral("C:/ProgramData");
        dir = base + QStringLiteral("/Bulwark");
    }
    QDir().mkpath(dir);
#ifdef _WIN32
    if (defaultLocation) {
        const QString native = QDir::toNativeSeparators(dir);
        const DWORD attrs = ::GetFileAttributesW(
            reinterpret_cast<const wchar_t*>(native.utf16()));
        if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_REPARSE_POINT))
            throw std::runtime_error("Bulwark ProgramData root is missing or a reparse point");
        static std::once_flag aclOnce;
        std::call_once(aclOnce, [&dir] { secureDefaultDataTree(dir); });
    }
#endif
    return dir;
}

QString logFilePath() {
    return programDataDir() + QStringLiteral("/service.log");
}

void startFileLog() { sink().start(); }
void stopFileLog() { sink().stop(); }

void writeCrashLog(const QString& phase, const QString& detail) {
    // Full record to crash.log; never throws.
    const QString line = QStringLiteral("==== %1 [%2] PID=%3 ====\n%4\n\n")
        .arg(QDateTime::currentDateTime().toString(Qt::ISODateWithMs),
             phase,
             QString::number(QCoreApplication::applicationPid()),
             detail);
    QFile f(programDataDir() + QStringLiteral("/crash.log"));
    if (f.open(QIODevice::Append | QIODevice::WriteOnly)) {
        f.write(line.toUtf8());
        f.close();
    }
}

Logger::Logger(const QString& category) {
    const int idx = category.lastIndexOf(QLatin1Char('.'));
    category_ = idx >= 0 ? category.mid(idx + 1) : category;
}

void Logger::write(LogLevel level, const QString& msg) const {
    if (!isEnabled(level)) return;
    const QString line = QStringLiteral("%1 %2 [%3] %4\n")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")),
             QLatin1String(levelTag(level)),
             category_,
             msg);
    sink().enqueue(line);
}

void Logger::error(const QString& msg, const QString& detail) const {
    if (!isEnabled(LogLevel::Error)) return;
    QString line = QStringLiteral("%1 %2 [%3] %4")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")),
             QLatin1String(levelTag(LogLevel::Error)),
             category_,
             msg);
    if (!detail.isEmpty()) line += QStringLiteral("\n") + detail;
    line += QStringLiteral("\n");
    sink().enqueue(line);
}

}
