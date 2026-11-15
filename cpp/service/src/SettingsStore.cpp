#include "bulwark/service/SettingsStore.h"
#include "bulwark/service/AtomicFile.h"
#include "bulwark/service/Logger.h"

#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>
#endif

namespace bulwark::service {

namespace {

const QString& protectedKeyField() {
    static const QString field = QStringLiteral("aiApiKeyProtected");
    return field;
}

const QString& protectedKeyPrefix() {
    static const QString prefix = QStringLiteral("dpapi:v1:");
    return prefix;
}

std::optional<QString> protectAiApiKey(const QString& plainText, unsigned long* errorOut) {
    if (errorOut)
        *errorOut = 0;
    if (plainText.isEmpty())
        return QString();

#ifdef _WIN32
    QByteArray plain = plainText.toUtf8();
    QByteArray entropyBytes("Bulwark.SettingsStore.aiApiKey.v1");
    DATA_BLOB input{};
    input.cbData = static_cast<DWORD>(plain.size());
    input.pbData = reinterpret_cast<BYTE*>(plain.data());
    DATA_BLOB entropy{};
    entropy.cbData = static_cast<DWORD>(entropyBytes.size());
    entropy.pbData = reinterpret_cast<BYTE*>(entropyBytes.data());
    DATA_BLOB output{};

    const BOOL ok = ::CryptProtectData(&input, L"Bulwark AI API key", &entropy, nullptr, nullptr,
                                       CRYPTPROTECT_UI_FORBIDDEN,
                                       &output);
    if (!plain.isEmpty())
        ::SecureZeroMemory(plain.data(), static_cast<SIZE_T>(plain.size()));
    if (!ok) {
        if (errorOut)
            *errorOut = static_cast<unsigned long>(::GetLastError());
        return std::nullopt;
    }

    const QByteArray cipher(reinterpret_cast<const char*>(output.pbData),
                            static_cast<qsizetype>(output.cbData));
    if (output.pbData)
        ::LocalFree(output.pbData);
    return protectedKeyPrefix()
         + QString::fromLatin1(cipher.toBase64(QByteArray::Base64Encoding));
#else
    Q_UNUSED(plainText);
    if (errorOut)
        *errorOut = 1;
    return std::nullopt;
#endif
}

std::optional<QString> unprotectAiApiKey(const QString& protectedText, unsigned long* errorOut) {
    if (errorOut)
        *errorOut = 0;
    if (!protectedText.startsWith(protectedKeyPrefix())) {
#ifdef _WIN32
        if (errorOut)
            *errorOut = ERROR_INVALID_DATA;
#else
        if (errorOut)
            *errorOut = 1;
#endif
        return std::nullopt;
    }

#ifdef _WIN32
    const QByteArray encoded = protectedText.mid(protectedKeyPrefix().size()).toLatin1();
    QByteArray cipher = QByteArray::fromBase64(encoded, QByteArray::AbortOnBase64DecodingErrors);
    if (cipher.isEmpty()) {
        if (errorOut)
            *errorOut = ERROR_INVALID_DATA;
        return std::nullopt;
    }

    QByteArray entropyBytes("Bulwark.SettingsStore.aiApiKey.v1");
    DATA_BLOB input{};
    input.cbData = static_cast<DWORD>(cipher.size());
    input.pbData = reinterpret_cast<BYTE*>(cipher.data());
    DATA_BLOB entropy{};
    entropy.cbData = static_cast<DWORD>(entropyBytes.size());
    entropy.pbData = reinterpret_cast<BYTE*>(entropyBytes.data());
    DATA_BLOB output{};
    LPWSTR description = nullptr;

    const BOOL ok = ::CryptUnprotectData(&input, &description, &entropy, nullptr, nullptr,
                                         CRYPTPROTECT_UI_FORBIDDEN, &output);
    if (description)
        ::LocalFree(description);
    if (!ok) {
        if (errorOut)
            *errorOut = static_cast<unsigned long>(::GetLastError());
        return std::nullopt;
    }

    QByteArray plain(reinterpret_cast<const char*>(output.pbData),
                     static_cast<qsizetype>(output.cbData));
    if (output.pbData)
        ::LocalFree(output.pbData);
    const QString result = QString::fromUtf8(plain.constData(), plain.size());
    if (!plain.isEmpty())
        ::SecureZeroMemory(plain.data(), static_cast<SIZE_T>(plain.size()));
    return result;
#else
    Q_UNUSED(protectedText);
    if (errorOut)
        *errorOut = 1;
    return std::nullopt;
#endif
}

}

SettingsStore::SettingsStore() {
    path_ = QDir(programDataDir()).filePath(QStringLiteral("settings.json"));
}

std::optional<bulwark::RuntimeSettings> SettingsStore::load() {
    QMutexLocker lk(&io_);
    QFile f(path_);
    if (!f.exists() || !f.open(QIODevice::ReadOnly)) return std::nullopt;
    const QByteArray data = f.readAll();
    f.close();
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(data, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) return std::nullopt;

    Logger log(QStringLiteral("bulwark.service.SettingsStore"));
    const QString plainField = QStringLiteral("aiApiKey");
    QJsonObject diskObject = doc.object();
    QJsonObject runtimeObject = diskObject;
    unreadableProtectedAiApiKey_.clear();

    if (diskObject.contains(protectedKeyField())) {
        const QString protectedText = diskObject.value(protectedKeyField()).toString();
        unsigned long winError = 0;
        const std::optional<QString> plain = unprotectAiApiKey(protectedText, &winError);
        if (plain.has_value()) {
            runtimeObject.insert(plainField, *plain);
            if (diskObject.contains(plainField)) {
                QJsonObject migrated = diskObject;
                migrated.remove(plainField);
                if (writeFileAtomically(path_, QJsonDocument(migrated).toJson(QJsonDocument::Indented),
                                        QStringLiteral("运行时设置密钥去明文"))) {
                    log.info(QStringLiteral("运行时设置密钥迁移:已移除与 DPAPI 密文并存的明文字段。"));
                } else {
                    log.error(QStringLiteral("运行时设置密钥迁移失败:无法移除残留明文字段，原文件保持不变。"));
                }
            }
        } else {
            // 不把密文或旁边可能残留的明文当作 API Key。保留不可读密文，避免启动期其它
            // 设置迁移调用 save() 时顺手擦除，管理员仍可从备份恢复或写入新 Key。
            runtimeObject.remove(plainField);
            unreadableProtectedAiApiKey_ = protectedText;
            log.error(QStringLiteral("DPAPI 无法解密运行时设置中的 AI API Key(error=%1)；"
                                     "本次不启用该 Key，且不会在其它设置保存时覆盖原密文。")
                          .arg(winError));
        }
    } else {
        // 兼容旧 settings.json：首次由新服务读取时，把明文原子迁移为机器范围 DPAPI 密文。
        const QString legacyPlain = diskObject.value(plainField).toString();
        if (!legacyPlain.isEmpty()) {
            unsigned long winError = 0;
            const std::optional<QString> protectedText = protectAiApiKey(legacyPlain, &winError);
            if (protectedText.has_value()) {
                QJsonObject migrated = diskObject;
                migrated.remove(plainField);
                migrated.insert(protectedKeyField(), *protectedText);
                if (writeFileAtomically(path_, QJsonDocument(migrated).toJson(QJsonDocument::Indented),
                                        QStringLiteral("运行时设置密钥 DPAPI 迁移"))) {
                    log.info(QStringLiteral("运行时设置密钥迁移:旧明文 AI API Key 已改为机器范围 DPAPI 密文。"));
                } else {
                    log.error(QStringLiteral("运行时设置密钥迁移落盘失败:旧文件保持不变，Key 仅在内存中使用。"));
                }
            } else {
                // 加密失败时绝不以新格式重写，也绝不把 Key 打进日志。
                log.error(QStringLiteral("运行时设置密钥迁移失败:DPAPI 加密失败(error=%1)，旧文件保持不变。")
                              .arg(winError));
            }
        }
    }

    bulwark::RuntimeSettings s = bulwark::RuntimeSettings::fromJson(runtimeObject);
    s.kernelConnected = false;
    s.kernelStatus.clear();
    return s;
}

void SettingsStore::save(const bulwark::RuntimeSettings& settings) {
    QMutexLocker lk(&io_);
    QJsonObject o = settings.toJson();
    o.remove(QStringLiteral("kernelConnected"));
    o.remove(QStringLiteral("kernelStatus"));

    const QString plainText = o.take(QStringLiteral("aiApiKey")).toString();
    o.remove(protectedKeyField());
    if (!plainText.isEmpty()) {
        unsigned long winError = 0;
        const std::optional<QString> protectedText = protectAiApiKey(plainText, &winError);
        if (!protectedText.has_value()) {
            Logger(QStringLiteral("bulwark.service.SettingsStore"))
                .error(QStringLiteral("运行时设置未保存:AI API Key 的 DPAPI 加密失败(error=%1)，"
                                      "拒绝回退为明文。")
                           .arg(winError));
            return;
        }
        o.insert(protectedKeyField(), *protectedText);
        unreadableProtectedAiApiKey_.clear();
    } else if (!unreadableProtectedAiApiKey_.isEmpty()) {
        o.insert(protectedKeyField(), unreadableProtectedAiApiKey_);
    }

    // 原子落盘。失败时 writeFileAtomically 只返回 false,必须检查并记日志,否则 UI 照常显示已保存。
    if (!writeFileAtomically(path_, QJsonDocument(o).toJson(QJsonDocument::Indented),
                             QStringLiteral("运行时设置"))) {
        Logger(QStringLiteral("bulwark.service.SettingsStore"))
            .error(QStringLiteral("运行时设置落盘失败,本次修改仅在内存中生效,重启后将丢失:%1")
                       .arg(path_));
    }
}

}
