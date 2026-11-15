#include "widgets/FileIconSafe.h"

#include <QDir>
#include <QImage>

#include <algorithm>
#include <cstdint>
#include <vector>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#endif

namespace fileicon {

#ifdef Q_OS_WIN
namespace {

HICON extractIcon(const QString& path, int px)
{
    const QString native = QDir::toNativeSeparators(path);
    if (native.isEmpty() || native.size() >= MAX_PATH)
        return nullptr;
    wchar_t buf[MAX_PATH] = {};
    native.toWCharArray(buf);

    HICON icon = nullptr;
    UINT id = 0;
    const UINT got = ::PrivateExtractIconsW(buf, 0, px, px, &icon, &id, 1, LR_DEFAULTCOLOR);
    if (got != 0 && got != UINT(-1) && icon != nullptr)
        return icon;

    HICON small = nullptr;
    const UINT n = ::ExtractIconExW(buf, 0, nullptr, &small, 1);
    if (n != 0 && n != UINT(-1) && small != nullptr)
        return small;
    return nullptr;
}

QImage imageFromIcon(HICON icon, int px)
{
    BITMAPINFO bi = {};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = px;
    bi.bmiHeader.biHeight = -px;   // 负数 = 自上而下,与 QImage 的行序一致
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    HDC screen = ::GetDC(nullptr);
    HDC dc = ::CreateCompatibleDC(screen);
    void* bits = nullptr;
    HBITMAP dib = ::CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    ::ReleaseDC(nullptr, screen);
    if (dc == nullptr || dib == nullptr || bits == nullptr) {
        if (dib != nullptr)
            ::DeleteObject(dib);
        if (dc != nullptr)
            ::DeleteDC(dc);
        return {};
    }
    HGDIOBJ prev = ::SelectObject(dc, dib);

    const size_t count = static_cast<size_t>(px) * static_cast<size_t>(px);
    auto* raw = static_cast<uint32_t*>(bits);
    std::vector<uint32_t> onBlack(count), onWhite(count);
    const auto render = [&](uint32_t background, std::vector<uint32_t>& out) {
        std::fill(raw, raw + count, background);
        ::DrawIconEx(dc, 0, 0, icon, px, px, 0, nullptr, DI_NORMAL);
        ::GdiFlush();   // GDI 是批处理的:直接读 DIB 内存之前必须先刷
        std::copy(raw, raw + count, out.begin());
    };
    render(0x00000000u, onBlack);
    render(0x00FFFFFFu, onWhite);

    ::SelectObject(dc, prev);
    ::DeleteObject(dib);
    ::DeleteDC(dc);

    QImage img(px, px, QImage::Format_ARGB32_Premultiplied);
    bool anyVisible = false;
    for (int y = 0; y < px; ++y) {
        auto* dst = reinterpret_cast<uint32_t*>(img.scanLine(y));
        for (int x = 0; x < px; ++x) {
            const size_t i = static_cast<size_t>(y) * static_cast<size_t>(px) + static_cast<size_t>(x);
            const uint32_t b = onBlack[i];
            const uint32_t w = onWhite[i];
            const int br = static_cast<int>((b >> 16) & 0xFFu);
            const int bg = static_cast<int>((b >> 8) & 0xFFu);
            const int bb = static_cast<int>(b & 0xFFu);
            const int wr = static_cast<int>((w >> 16) & 0xFFu);
            const int wg = static_cast<int>((w >> 8) & 0xFFu);
            const int wb = static_cast<int>(w & 0xFFu);
            const int diff = ((wr - br) + (wg - bg) + (wb - bb)) / 3;
            const int a = std::clamp(255 - diff, 0, 255);
            if (a != 0)
                anyVisible = true;
            dst[x] = (static_cast<uint32_t>(a) << 24)
                     | (static_cast<uint32_t>(std::min(br, a)) << 16)
                     | (static_cast<uint32_t>(std::min(bg, a)) << 8)
                     | static_cast<uint32_t>(std::min(bb, a));
        }
    }
    return anyVisible ? img : QImage();
}

}
#endif

QPixmap pixmapForPath(const QString& path, int logicalSize, qreal dpr)
{
#ifdef Q_OS_WIN
    if (path.isEmpty() || logicalSize <= 0)
        return {};
    const qreal ratio = std::max<qreal>(1.0, dpr);
    const int px = std::clamp(qRound(logicalSize * ratio), 8, 256);

    HICON icon = extractIcon(path, px);
    if (icon == nullptr)
        return {};
    const QImage img = imageFromIcon(icon, px);
    ::DestroyIcon(icon);
    if (img.isNull())
        return {};

    QPixmap pm = QPixmap::fromImage(img);
    pm.setDevicePixelRatio(ratio);
    return pm;
#else
    Q_UNUSED(path);
    Q_UNUSED(logicalSize);
    Q_UNUSED(dpr);
    return {};
#endif
}

QIcon iconForPath(const QString& path, int logicalSize, qreal dpr)
{
    const QPixmap pm = pixmapForPath(path, logicalSize, dpr);
    return pm.isNull() ? QIcon() : QIcon(pm);
}

}
