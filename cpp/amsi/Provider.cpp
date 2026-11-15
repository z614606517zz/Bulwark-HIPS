#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <amsi.h>
#include <objbase.h>
#include <new>

#include "AmsiProtocol.h"
#include "PipeClient.h"

static const CLSID kProviderClsid =
    { 0x0aac68c8, 0xbb18, 0x4699, { 0xaa, 0x9e, 0xb0, 0x72, 0xc4, 0x07, 0xce, 0x6b } };

static const wchar_t kClsidText[]   = L"{0AAC68C8-BB18-4699-AA9E-B072C407CE6B}";
static const wchar_t kDisplayName[] = L"Bulwark Script Guard";

static HMODULE g_module   = nullptr;
static volatile LONG g_objects = 0;

namespace {

uint32_t guessEncoding(const unsigned char* data, uint32_t bytes) {
    if (data == nullptr || bytes < 4)
        return BLW_AMSI_ENC_UNKNOWN;
    uint32_t sample = bytes < 64 ? bytes : 64;
    sample &= ~1u;
    uint32_t zeroOdd = 0, odd = 0;
    for (uint32_t i = 1; i < sample; i += 2) {
        ++odd;
        if (data[i] == 0)
            ++zeroOdd;
    }
    if (odd > 0 && zeroOdd * 4 >= odd * 3)
        return BLW_AMSI_ENC_UTF16LE;
    return BLW_AMSI_ENC_UTF8;
}

void freeHeap(void* p) {
    if (p != nullptr)
        ::HeapFree(::GetProcessHeap(), 0, p);
}

PWSTR getStringAttribute(IAmsiStream* stream, AMSI_ATTRIBUTE attr) {
    ULONG needed = 0;
    HRESULT hr = stream->GetAttribute(attr, 0, nullptr, &needed);
    if (hr != E_NOT_SUFFICIENT_BUFFER || needed == 0 || needed > 64 * 1024)
        return nullptr;
    const ULONG alloc = needed + sizeof(wchar_t);
    auto* buf = static_cast<PBYTE>(::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, alloc));
    if (buf == nullptr)
        return nullptr;
    ULONG got = 0;
    hr = stream->GetAttribute(attr, needed, buf, &got);
    if (FAILED(hr)) {
        ::HeapFree(::GetProcessHeap(), 0, buf);
        return nullptr;
    }
    return reinterpret_cast<PWSTR>(buf);
}

bool regSetString(HKEY root, const wchar_t* subKey, const wchar_t* name,
                  const wchar_t* value) {
    HKEY key = nullptr;
    if (::RegCreateKeyExW(root, subKey, 0, nullptr, REG_OPTION_NON_VOLATILE,
                          KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS)
        return false;
    const DWORD bytes = static_cast<DWORD>((::lstrlenW(value) + 1) * sizeof(wchar_t));
    const LSTATUS st = ::RegSetValueExW(key, name, 0, REG_SZ,
                                        reinterpret_cast<const BYTE*>(value), bytes);
    ::RegCloseKey(key);
    return st == ERROR_SUCCESS;
}

}

class BulwarkProvider : public IAntimalwareProvider {
public:
    BulwarkProvider() : refs_(1) { ::InterlockedIncrement(&g_objects); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** out) override {
        if (out == nullptr)
            return E_POINTER;
        *out = nullptr;
        if (riid == __uuidof(IAntimalwareProvider) || riid == IID_IUnknown) {
            *out = static_cast<IAntimalwareProvider*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override {
        return static_cast<ULONG>(::InterlockedIncrement(&refs_));
    }
    ULONG STDMETHODCALLTYPE Release() override {
        const LONG n = ::InterlockedDecrement(&refs_);
        if (n == 0) {
            ::InterlockedDecrement(&g_objects);
            delete this;
        }
        return static_cast<ULONG>(n);
    }

    HRESULT STDMETHODCALLTYPE Scan(IAmsiStream* stream, AMSI_RESULT* result) override {
        if (result == nullptr)
            return E_POINTER;
        *result = AMSI_RESULT_NOT_DETECTED;
        if (stream == nullptr)
            return S_OK;

        ULONG got = 0;

        ULONGLONG contentSize = 0;
        if (FAILED(stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(contentSize),
                                        reinterpret_cast<PBYTE>(&contentSize), &got))
            || contentSize == 0)
            return S_OK;

        const bool edgeSample = contentSize > BLW_AMSI_MAX_CONTENT;
        const uint32_t scanBytes = edgeSample
                                 ? BLW_AMSI_MAX_CONTENT
                                 : static_cast<uint32_t>(contentSize);

        PWSTR appName = getStringAttribute(stream, AMSI_ATTRIBUTE_APP_NAME);
        PWSTR contentName = getStringAttribute(stream, AMSI_ATTRIBUTE_CONTENT_NAME);
        ULONGLONG session = 0;
        stream->GetAttribute(AMSI_ATTRIBUTE_SESSION, sizeof(session),
                             reinterpret_cast<PBYTE>(&session), &got);

        PBYTE direct = nullptr;
        stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_ADDRESS, sizeof(direct),
                             reinterpret_cast<PBYTE>(&direct), &got);

        uint32_t sendBytes = scanBytes;
        PBYTE owned = nullptr;
        const unsigned char* content = nullptr;
        if (!edgeSample && direct != nullptr) {
            content = direct;
        } else {
            owned = static_cast<PBYTE>(::HeapAlloc(::GetProcessHeap(), 0, scanBytes));
            if (owned == nullptr) {
                freeHeap(appName);
                freeHeap(contentName);
                return S_OK;
            }

            if (edgeSample) {
                const uint32_t firstBytes = scanBytes / 2;
                const uint32_t tailBytes = scanBytes - firstBytes;
                const ULONGLONG tailOffset = contentSize - tailBytes;
                if (direct != nullptr && tailOffset <= static_cast<ULONGLONG>(SIZE_MAX)) {
                    ::CopyMemory(owned, direct, firstBytes);
                    ::CopyMemory(owned + firstBytes,
                                 direct + static_cast<size_t>(tailOffset), tailBytes);
                } else {
                    ULONG firstRead = 0;
                    ULONG tailRead = 0;
                    if (FAILED(stream->Read(0, firstBytes, owned, &firstRead))
                        || firstRead != firstBytes
                        || FAILED(stream->Read(tailOffset, tailBytes, owned + firstBytes, &tailRead))
                        || tailRead != tailBytes) {
                        ::HeapFree(::GetProcessHeap(), 0, owned);
                        freeHeap(appName);
                        freeHeap(contentName);
                        return S_OK;
                    }
                }
            } else {
                ULONG read = 0;
                if (FAILED(stream->Read(0, scanBytes, owned, &read)) || read == 0) {
                    ::HeapFree(::GetProcessHeap(), 0, owned);
                    freeHeap(appName);
                    freeHeap(contentName);
                    return S_OK;
                }
                if (read < sendBytes)
                    sendBytes = read;
            }
            content = owned;
        }

        BLW_AMSI_REQUEST head = {};
        head.hostPid      = ::GetCurrentProcessId();
        head.contentBytes = sendBytes;
        head.encoding     = guessEncoding(content, sendBytes);
        head.session      = session;

        wchar_t reason[256] = {};
        const blw::AskResult verdict = blw::askService(head, appName, contentName,
                                                       content, reason, 256);

        if (owned != nullptr)
            ::HeapFree(::GetProcessHeap(), 0, owned);
        freeHeap(appName);
        freeHeap(contentName);

        if (verdict == blw::AskResult::Blocked) {
            *result = AMSI_RESULT_DETECTED;
#if defined(_DEBUG)
            ::OutputDebugStringW(L"[Bulwark AMSI] blocked: ");
            ::OutputDebugStringW(reason[0] != L'\0' ? reason : L"(no reason)");
            ::OutputDebugStringW(L"\n");
#endif
        }
        return S_OK;
    }

    void STDMETHODCALLTYPE CloseSession(ULONGLONG) override {}

    HRESULT STDMETHODCALLTYPE DisplayName(LPWSTR* displayName) override {
        if (displayName == nullptr)
            return E_POINTER;
        *displayName = const_cast<LPWSTR>(kDisplayName);
        return S_OK;
    }

private:
    ~BulwarkProvider() = default;
    volatile LONG refs_;
};

class ProviderFactory : public IClassFactory {
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** out) override {
        if (out == nullptr)
            return E_POINTER;
        *out = nullptr;
        if (riid == IID_IClassFactory || riid == IID_IUnknown) {
            *out = static_cast<IClassFactory*>(this);
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return 2; }
    ULONG STDMETHODCALLTYPE Release() override { return 1; }

    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID riid,
                                             void** out) override {
        if (out == nullptr)
            return E_POINTER;
        *out = nullptr;
        if (outer != nullptr)
            return CLASS_E_NOAGGREGATION;
        BulwarkProvider* p = new (std::nothrow) BulwarkProvider();
        if (p == nullptr)
            return E_OUTOFMEMORY;
        const HRESULT hr = p->QueryInterface(riid, out);
        p->Release();
        return hr;
    }
    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override {
        if (lock) ::InterlockedIncrement(&g_objects);
        else      ::InterlockedDecrement(&g_objects);
        return S_OK;
    }
};

static ProviderFactory g_factory;

extern "C" BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_module = static_cast<HMODULE>(inst);
        ::DisableThreadLibraryCalls(inst);
    }
    return TRUE;
}

extern "C" HRESULT __stdcall DllGetClassObject(REFCLSID clsid, REFIID riid, void** out) {
    if (out == nullptr)
        return E_POINTER;
    *out = nullptr;
    if (clsid != kProviderClsid)
        return CLASS_E_CLASSNOTAVAILABLE;
    return g_factory.QueryInterface(riid, out);
}

extern "C" HRESULT __stdcall DllCanUnloadNow() {
    return (::InterlockedCompareExchange(&g_objects, 0, 0) == 0) ? S_OK : S_FALSE;
}

extern "C" HRESULT __stdcall DllRegisterServer() {
    wchar_t path[MAX_PATH] = {};
    if (::GetModuleFileNameW(g_module, path, MAX_PATH) == 0)
        return HRESULT_FROM_WIN32(::GetLastError());

    wchar_t clsKey[128] = L"SOFTWARE\\Classes\\CLSID\\";
    ::lstrcatW(clsKey, kClsidText);
    wchar_t inprocKey[160] = {};
    ::lstrcpyW(inprocKey, clsKey);
    ::lstrcatW(inprocKey, L"\\InprocServer32");

    wchar_t amsiKey[128] = L"SOFTWARE\\Microsoft\\AMSI\\Providers\\";
    ::lstrcatW(amsiKey, kClsidText);

    bool ok = regSetString(HKEY_LOCAL_MACHINE, clsKey, nullptr, kDisplayName);
    ok = ok && regSetString(HKEY_LOCAL_MACHINE, inprocKey, nullptr, path);
    ok = ok && regSetString(HKEY_LOCAL_MACHINE, inprocKey, L"ThreadingModel", L"Both");
    ok = ok && regSetString(HKEY_LOCAL_MACHINE, amsiKey, nullptr, kDisplayName);
    return ok ? S_OK : E_ACCESSDENIED;
}

extern "C" HRESULT __stdcall DllUnregisterServer() {
    wchar_t clsKey[128] = L"SOFTWARE\\Classes\\CLSID\\";
    ::lstrcatW(clsKey, kClsidText);
    wchar_t amsiKey[128] = L"SOFTWARE\\Microsoft\\AMSI\\Providers\\";
    ::lstrcatW(amsiKey, kClsidText);

    ::RegDeleteTreeW(HKEY_LOCAL_MACHINE, amsiKey);
    ::RegDeleteTreeW(HKEY_LOCAL_MACHINE, clsKey);
    return S_OK;
}
