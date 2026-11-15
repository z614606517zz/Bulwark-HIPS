#include "bulwark/service/FileContentProbe.h"

#include <QByteArray>
#include <QDir>

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <utility>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#ifndef FILE_ATTRIBUTE_RECALL_ON_OPEN
#define FILE_ATTRIBUTE_RECALL_ON_OPEN 0x00040000
#endif
#ifndef FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
#define FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS 0x00400000
#endif

namespace bulwark::service {

using bulwark::engine::FileContentClassifier;
using bulwark::engine::FileContentSample;

struct FileContentProbe::Shared {
    std::mutex gate;
    std::condition_variable wake;
    std::condition_variable done;
    QString path;
    quint64 asked = 0;      // 最近一次请求的编号
    quint64 answered = 0;   // 工作线程答完的编号;与 asked 不等表示还在读
    FileContentSample answer;
    bool stop = false;
};

FileContentProbe::FileContentProbe(int timeoutMs)
    : shared_(std::make_shared<Shared>()), timeoutMs_(timeoutMs > 0 ? timeoutMs : 1) {
    worker_ = std::thread(&FileContentProbe::run, shared_);
}

FileContentProbe::~FileContentProbe() {
    bool reading = false;
    {
        std::lock_guard<std::mutex> lock(shared_->gate);
        shared_->stop = true;
        reading = shared_->asked != shared_->answered;
    }
    shared_->wake.notify_all();
    // 卡在读盘里的线程等不回来;它自己握着 Shared 的一份引用,读完自行退出。
    if (reading)
        worker_.detach();
    else
        worker_.join();
}

void FileContentProbe::run(std::shared_ptr<Shared> shared) {
    std::unique_lock<std::mutex> lock(shared->gate);
    for (;;) {
        shared->wake.wait(lock, [&shared] { return shared->stop || shared->asked != shared->answered; });
        if (shared->stop)
            return;
        const quint64 id = shared->asked;
        const QString path = shared->path;
        lock.unlock();
        FileContentSample result = readHead(path);
        lock.lock();
        shared->answer = std::move(result);
        shared->answered = id;
        shared->done.notify_all();
    }
}

FileContentSample FileContentProbe::sample(const QString& path) {
    FileContentSample busy;
    busy.kind = FileContentSample::Kind::Busy;
    std::unique_lock<std::mutex> lock(shared_->gate);
    if (shared_->stop)
        return {};
    // 上一次读盘还没回来:不排队,让调用方稍后再问。
    if (shared_->asked != shared_->answered)
        return busy;
    const quint64 id = ++shared_->asked;
    shared_->path = path;
    shared_->wake.notify_one();
    const bool answered = shared_->done.wait_for(lock, std::chrono::milliseconds(timeoutMs_),
                                                 [this, id] { return shared_->answered == id; });
    if (!answered)
        return busy;
    return std::move(shared_->answer);
}

FileContentSample FileContentProbe::readHead(const QString& path) {
    using Kind = FileContentSample::Kind;
    FileContentSample out;

    QString native = QDir::toNativeSeparators(path.trimmed());
    QString local = native;
    if (local.startsWith(QLatin1String("\\\\?\\")))
        local = local.mid(4);
    // 只读本地盘。网络路径在服务器不可达时一次打开能卡数秒。
    if (local.size() < 3 || local.at(1) != QLatin1Char(':') || local.at(2) != QLatin1Char('\\'))
        return out;
    const std::wstring root = local.left(3).toStdWString();
    if (::GetDriveTypeW(root.c_str()) == DRIVE_REMOTE)
        return out;

    if (!native.startsWith(QLatin1String("\\\\?\\")) && native.size() >= MAX_PATH - 12)
        native.prepend(QLatin1String("\\\\?\\"));
    const std::wstring wide = native.toStdWString();

    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!::GetFileAttributesExW(wide.c_str(), GetFileExInfoStandard, &data)) {
        const DWORD err = ::GetLastError();
        // 其余的错(正在删除中、被占用、拒绝访问)都是一时的,稍后再看。
        out.kind = (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) ? Kind::Missing : Kind::Busy;
        return out;
    }
    if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        out.kind = Kind::Missing;
        return out;
    }
    // 云端占位文件一读就触发下载,脱机文件要从别处取回;重解析点不跟过去。
    constexpr DWORD kHandsOff = FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN
                                | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_REPARSE_POINT;
    if (data.dwFileAttributes & kHandsOff)
        return out;

    qint64 size = (static_cast<qint64>(data.nFileSizeHigh) << 32) | static_cast<qint64>(data.nFileSizeLow);

    const HANDLE h = ::CreateFileW(wide.c_str(), GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                   FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD err = ::GetLastError();
        // 正被别的程序独占、正在删除中:内容暂时看不到,由调用方稍后再看。
        out.kind = (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) ? Kind::Missing : Kind::Busy;
        return out;
    }
    if (::GetFileType(h) != FILE_TYPE_DISK) {
        ::CloseHandle(h);
        return out;
    }
    LARGE_INTEGER actual{};
    if (::GetFileSizeEx(h, &actual))
        size = actual.QuadPart;

    const int want = FileContentClassifier::kHeadBytes;
    QByteArray head(want, Qt::Uninitialized);
    int total = 0;
    while (total < want) {
        DWORD got = 0;
        if (!::ReadFile(h, head.data() + total, static_cast<DWORD>(want - total), &got, nullptr)) {
            ::CloseHandle(h);
            out.kind = Kind::Busy;   // 文件开头被锁住、读盘出错
            return out;
        }
        if (got == 0)
            break;
        total += static_cast<int>(got);
    }
    ::CloseHandle(h);
    head.truncate(total);

    out.kind = Kind::Present;
    out.size = size;
    out.head = head;
    return out;
}

}
