#pragma once
#include <QDateTime>
#include <QTimeZone>
#include <atomic>

namespace bulwark {

namespace clock_detail {

inline std::atomic<qint64> &fixedNowMs()
{
    static std::atomic<qint64> v{ 0 };
    return v;
}

}

inline QDateTime nowUtc()
{
    const qint64 fixed = clock_detail::fixedNowMs().load(std::memory_order_relaxed);
    if (fixed != 0)
        return QDateTime::fromMSecsSinceEpoch(fixed, QTimeZone::UTC);
    return QDateTime::currentDateTimeUtc();
}

inline void setFixedNowUtcForTest(const QDateTime &fixed)
{
    clock_detail::fixedNowMs().store(fixed.isValid() ? fixed.toMSecsSinceEpoch() : 0,
                                     std::memory_order_relaxed);
}

inline bool isNowUtcFixedForTest()
{
    return clock_detail::fixedNowMs().load(std::memory_order_relaxed) != 0;
}

}
