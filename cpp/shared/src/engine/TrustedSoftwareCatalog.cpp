#include "bulwark/engine/TrustedSoftwareCatalog.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMutexLocker>
#include <QRegularExpression>
#include <QSaveFile>
#include <QUuid>

#include <algorithm>

namespace bulwark::engine {

namespace {

QString lowerName(QString n) { return n.trimmed().toLower(); }

bool nameMatches(const QString& publisher, const QString& needle)
{
    if (publisher.isEmpty() || needle.isEmpty())
        return false;
    const QString hay = publisher.toLower();
    const QString want = needle.toLower();
    int from = 0;
    for (;;) {
        const int i = hay.indexOf(want, from);
        if (i < 0)
            return false;
        const bool leftOk = (i == 0) || !hay.at(i - 1).isLetterOrNumber();
        const int end = i + want.size();
        const bool rightOk = (end >= hay.size()) || !hay.at(end).isLetterOrNumber();
        if (leftOk && rightOk)
            return true;
        from = i + 1;
    }
}

TrustedApp mk(const char* id, const char* name, const char* vendor, const char* cat,
              std::initializer_list<const char*> exes,
              std::initializer_list<const char*> pubs = {},
              const char* note = nullptr)
{
    TrustedApp a;
    a.id = QString::fromUtf8(id);
    a.name = QString::fromUtf8(name);
    a.vendor = QString::fromUtf8(vendor);
    a.category = QString::fromUtf8(cat);
    for (const char* e : exes)
        a.exes << lowerName(QString::fromUtf8(e));
    for (const char* p : pubs)
        a.publishers << QString::fromUtf8(p);
    if (note)
        a.note = QString::fromUtf8(note);
    a.scope = TrustedApp::Scope::Exe;
    a.builtin = true;
    a.enabled = true;
    return a;
}

TrustedApp mkVendor(const char* id, const char* name, const char* vendor, const char* cat,
                    std::initializer_list<const char*> pubs,
                    const char* note = nullptr)
{
    TrustedApp a;
    a.id = QString::fromUtf8(id);
    a.name = QString::fromUtf8(name);
    a.vendor = QString::fromUtf8(vendor);
    a.category = QString::fromUtf8(cat);
    for (const char* p : pubs)
        a.publishers << QString::fromUtf8(p);
    if (note)
        a.note = QString::fromUtf8(note);
    a.scope = TrustedApp::Scope::Vendor;
    a.builtin = true;
    a.enabled = true;
    return a;
}

QList<TrustedApp> builtinApps()
{
    QList<TrustedApp> s;

    s << mkVendor("ven-tencent", "腾讯系列软件", "腾讯", "厂商",
                  {"Tencent Technology", "Shenzhen Tencent", "Tencent Holdings",
                   "Tencent Cloud", "Tencent America", "Tencent Technology (Shenzhen)",
                   "Beijing Tencent", "Tencent"},
                  "覆盖 QQ/微信/企业微信/腾讯会议/腾讯视频/腾讯电脑管家/WeGame 等");
    s << mkVendor("ven-360", "360 系列软件", "360", "厂商",
                  {"Qihoo 360", "Beijing Qihu", "360 Internet Security", "360.cn",
                   "Beijing Qihu Technology", "Qihoo"},
                  "覆盖 360 安全卫士/压缩/浏览器/极速版/杀毒 等");
    s << mkVendor("ven-alibaba", "阿里 / 蚂蚁系列", "阿里", "厂商",
                  {"Alibaba", "Alipay", "Taobao", "Alibaba (China)", "Alibaba Cloud",
                   "Ant Group", "Ant Financial", "DingTalk", "Alibaba Group"},
                  "覆盖 钉钉/阿里云盘/旺旺/支付宝/优酷 等");
    s << mkVendor("ven-bytedance", "字节跳动系列", "字节跳动", "厂商",
                  {"ByteDance", "Beijing ByteDance", "Douyin", "Feishu", "Lark",
                   "Beijing Microlive", "TikTok"},
                  "覆盖 飞书/抖音/剪映/TikTok 等");
    s << mkVendor("ven-baidu", "百度系列", "百度", "厂商",
                  {"Baidu", "Beijing Baidu", "Baidu Online", "Baidu Netcom"},
                  "覆盖 百度网盘/浏览器/输入法/翻译 等");
    s << mkVendor("ven-kingsoft", "金山 / WPS 系列", "金山", "厂商",
                  {"Kingsoft", "Zhuhai Kingsoft", "Kingsoft Office", "Kingsoft Security",
                   "Cheetah Mobile", "Kingsoft Internet"},
                  "覆盖 WPS/金山毒霸/驱动精灵/猎豹 等");
    s << mkVendor("ven-netease", "网易系列", "网易", "厂商",
                  {"NetEase", "Hangzhou NetEase", "NetEase (Hangzhou)", "Youdao",
                   "NetEase Youdao", "Guangzhou NetEase"},
                  "覆盖 网易云音乐/有道词典/UU加速/梦幻西游 等");
    s << mkVendor("ven-sohu-sogou", "搜狐 / 搜狗系列", "搜狗", "厂商",
                  {"Sogou", "Beijing Sogou", "Sohu", "Sohu.com", "Sogou Input"},
                  "覆盖 搜狗输入法/浏览器/搜狐视频 等");
    s << mkVendor("ven-jd", "京东系列", "京东", "厂商",
                  {"JD.com", "Beijing Jingdong", "Jingdong", "JD Cloud"},
                  "覆盖 京东/京东金融 等");
    s << mkVendor("ven-meituan", "美团 / 点评", "美团", "厂商",
                  {"Meituan", "Beijing Meituan", "Dianping", "Sankuai"},
                  "覆盖 美团/大众点评 等");
    s << mkVendor("ven-xiaomi", "小米 / 金山办公生态", "小米", "厂商",
                  {"Xiaomi", "Beijing Xiaomi", "Xiaomi Communications", "Mi Phone"},
                  "覆盖 小米助手/MIUI 相关 等");
    s << mkVendor("ven-huawei", "华为系列", "华为", "厂商",
                  {"Huawei", "Huawei Technologies", "Huawei Device", "Honor"},
                  "覆盖 华为手机助手/电脑管家/应用市场 等");
    s << mkVendor("ven-lenovo", "联想系列", "联想", "厂商",
                  {"Lenovo", "Lenovo (Beijing)", "Lenovo Group", "Lenovo Software"},
                  "覆盖 联想电脑管家/驱动 等");
    s << mkVendor("ven-asus", "华硕系列", "华硕", "厂商",
                  {"ASUS", "ASUSTeK", "ASUSTeK Computer"},
                  "覆盖 Armoury Crate/Armoury 等");
    s << mkVendor("ven-dell", "戴尔系列", "戴尔", "厂商",
                  {"Dell", "Dell Inc", "Dell Computer"},
                  "覆盖 SupportAssist/Dell Update 等");
    s << mkVendor("ven-hp", "惠普系列", "惠普", "厂商",
                  {"HP Inc", "Hewlett-Packard", "HP Development", "Hewlett Packard"},
                  "覆盖 HP Support Assistant 等");
    s << mkVendor("ven-oray", "向日葵 / 花生壳", "Oray", "厂商",
                  {"Oray", "Shanghai Oray", "Sunlogin", "Oray Shell"},
                  "覆盖 向日葵远程/花生壳内网穿透 等");
    s << mkVendor("ven-yonyou", "用友 / 金蝶", "用友/金蝶", "厂商",
                  {"Yonyou", "Kingdee", "UFIDA", "Yonyou Network"},
                  "覆盖 用友/金蝶财务与 ERP 客户端 等");
    s << mkVendor("ven-kingsoft-wps-cloud", "金山云 / 猎豹", "金山云", "厂商",
                  {"Kingsoft Cloud", "Cheetah Mobile", "Cheetah Mobile Inc"},
                  "覆盖 金山云盘/猎豹浏览器 等");
    s << mkVendor("ven-iqiyi", "爱奇艺 / 奇安信", "爱奇艺/奇安信", "厂商",
                  {"iQiyi", "Beijing iQiyi", "Qianxin", "Qi An Xin", "QAX"},
                  "覆盖 爱奇艺/奇安信天擎 等");
    s << mkVendor("ven-huorong", "火绒安全", "火绒", "厂商",
                  {"Huorong", "火绒", "Beijing Huorong", "北京火绒网络科技有限公司"},
                  "覆盖 火绒安全/火绒剑 等");
    s << mkVendor("ven-rising", "瑞星 / 江民", "瑞星", "厂商",
                  {"Rising", "Beijing Rising", "Jiangmin", "KV Technology"},
                  "覆盖 瑞星杀毒/江民 等");
    s << mkVendor("ven-bilibili", "哔哩哔哩", "B站", "厂商",
                  {"Bilibili", "Shanghai Bilibili", "B Station"},
                  "覆盖 哔哩哔哩客户端/直播姬 等");
    s << mkVendor("ven-kuaishou", "快手系列", "快手", "厂商",
                  {"Kuaishou", "Beijing Kuaishou", "Kwai"},
                  "覆盖 快手/快手直播伴侣 等");
    s << mkVendor("ven-mihoyo", "米哈游", "米哈游", "厂商",
                  {"miHoYo", "Cognosphere", "HoYoverse", "Shanghai miHoYo"},
                  "覆盖 原神/崩坏系列 等");
    s << mkVendor("ven-netease-games", "网易游戏", "网易游戏", "厂商",
                  {"NetEase Games", "Hangzhou NetEase Games"},
                  "覆盖 网易游戏平台/逆水寒 等");

    s << mkVendor("ven-microsoft", "Microsoft 全家桶", "Microsoft", "厂商",
                  {"Microsoft Corporation", "Microsoft Windows", "Microsoft Ireland",
                   "Microsoft Corp", "Microsoft Ltd"},
                  "覆盖 Windows 组件/Office/Edge/VS/Teams/OneDrive 等");
    s << mkVendor("ven-google", "Google 系列", "Google", "厂商",
                  {"Google LLC", "Google Inc", "Google Ireland"},
                  "覆盖 Chrome/Earth/Picasa/输入法 等");
    s << mkVendor("ven-adobe", "Adobe 系列", "Adobe", "厂商",
                  {"Adobe Inc", "Adobe Systems", "Adobe Systems Incorporated",
                   "Adobe Systems Software"},
                  "覆盖 Acrobat/Photoshop/Premiere/Reader 等");
    s << mkVendor("ven-jetbrains", "JetBrains 系列", "JetBrains", "厂商",
                  {"JetBrains", "JetBrains s.r.o"},
                  "覆盖 IDEA/PyCharm/WebStorm 等全系 IDE");
    s << mkVendor("ven-oracle", "Oracle / Java", "Oracle", "厂商",
                  {"Oracle", "Oracle Corporation", "Sun Microsystems", "Oracle America"},
                  "覆盖 Java/VirtualBox/SQL Developer 等");
    s << mkVendor("ven-autodesk", "Autodesk 系列", "Autodesk", "厂商",
                  {"Autodesk", "Autodesk, Inc", "Autodesk Development"},
                  "覆盖 AutoCAD/3ds Max/Revit/Maya 等");
    s << mkVendor("ven-ibm", "IBM / Red Hat", "IBM", "厂商",
                  {"IBM", "IBM Corp", "Red Hat", "Red Hat Inc"},
                  "覆盖 IBM/Red Hat 系软件 等");
    s << mkVendor("ven-cisco", "Cisco 系列", "Cisco", "厂商",
                  {"Cisco", "Cisco Systems", "Cisco Webex"},
                  "覆盖 Webex/AnyConnect/网管工具 等");
    s << mkVendor("ven-vmware", "VMware 系列", "VMware", "厂商",
                  {"VMware", "VMware, Inc", "VMware Worldwide"},
                  "覆盖 Workstation/Fusion/Tools 等");
    s << mkVendor("ven-valve", "Valve / Steam", "Valve", "厂商",
                  {"Valve", "Valve Corporation"},
                  "覆盖 Steam 客户端与游戏组件 等");
    s << mkVendor("ven-epic", "Epic Games", "Epic", "厂商",
                  {"Epic Games", "Epic Games Inc"},
                  "覆盖 Epic 启动器/虚幻引擎工具 等");
    s << mkVendor("ven-blizzard", "Blizzard / Riot", "暴雪/Riot", "厂商",
                  {"Blizzard", "Blizzard Entertainment", "Riot Games", "Riot Games Inc"},
                  "覆盖 战网/LOL 客户端 等");
    s << mkVendor("ven-discord", "Discord", "Discord", "厂商",
                  {"Discord", "Discord Inc"},
                  "覆盖 Discord 客户端 等");
    s << mkVendor("ven-slack-zoom", "Slack / Zoom", "协作", "厂商",
                  {"Slack", "Slack Technologies", "Zoom", "Zoom Video", "Zoom Communications"},
                  "覆盖 Slack/Zoom 会议 等");
    s << mkVendor("ven-steam-tools", "游戏平台与加速", "游戏平台", "厂商",
                  {"Watt Toolkit", "Steam++", "Netease UU", "Xunyou"},
                  "覆盖 UU加速/迅游/Steam++ 等");
    s << mkVendor("ven-apple", "Apple 系列", "Apple", "厂商",
                  {"Apple Inc"},
                  "覆盖 iTunes/iCloud/Bonjour/Apple Devices 等");
    s << mkVendor("ven-mozilla", "Mozilla 系列", "Mozilla", "厂商",
                  {"Mozilla Corporation", "Mozilla Foundation"},
                  "覆盖 Firefox/Thunderbird/维护服务 等");
    s << mkVendor("ven-dropbox-spotify", "Dropbox / Spotify", "Dropbox/Spotify", "厂商",
                  {"Dropbox, Inc", "Spotify AB", "Spotify Ltd"},
                  "覆盖 Dropbox 同步客户端/Spotify 客户端 等");
    s << mkVendor("ven-ea-ubisoft", "EA / 育碧", "EA/Ubisoft", "厂商",
                  {"Electronic Arts", "Ubisoft Entertainment"},
                  "覆盖 EA app/Origin/Ubisoft Connect 等");
    s << mkVendor("ven-iflytek", "科大讯飞", "讯飞", "厂商",
                  {"iFLYTEK", "iFlytek Co"},
                  "覆盖 讯飞输入法/讯飞听见 等");
    s << mkVendor("ven-xunlei", "迅雷系列", "迅雷", "厂商",
                  {"Shenzhen Xunlei", "Xunlei Networking"},
                  "覆盖 迅雷/迅雷影音/迅雷 X 等");
    s << mkVendor("ven-wondershare", "万兴科技", "万兴", "厂商",
                  {"Wondershare Technology", "Wondershare Software"},
                  "覆盖 万兴喵影/Filmora/PDFelement 等");
    s << mkVendor("ven-intel", "Intel 驱动与工具", "Intel", "厂商",
                  {"Intel Corporation"},
                  "覆盖 显卡控制中心/驱动与支持助理/RST 等");
    s << mkVendor("ven-nvidia", "NVIDIA 驱动与工具", "NVIDIA", "厂商",
                  {"NVIDIA Corporation"},
                  "覆盖 NVIDIA App/GeForce Experience/控制面板/容器服务 等");
    s << mkVendor("ven-amd", "AMD 驱动与工具", "AMD", "厂商",
                  {"Advanced Micro Devices"},
                  "覆盖 Adrenalin/Ryzen Master/芯片组驱动 等");
    s << mkVendor("ven-realtek", "Realtek 声卡/网卡", "Realtek", "厂商",
                  {"Realtek Semiconductor"},
                  "覆盖 Realtek 音频控制台/网卡诊断 等");
    s << mkVendor("ven-peripherals", "罗技 / 雷蛇 外设", "Logitech/Razer", "厂商",
                  {"Logitech", "Razer USA", "Razer Inc"},
                  "覆盖 G HUB/Options+/Razer Synapse 等");
    s << mkVendor("ven-samsung", "三星系列", "Samsung", "厂商",
                  {"Samsung Electronics"},
                  "覆盖 Samsung Magician/Smart Switch 等");

    s << mk("bin-chrome", "Google Chrome", "Google", "浏览器",
            {"chrome.exe"}, {"Google LLC", "Google Inc"});
    s << mk("bin-edge", "Microsoft Edge", "Microsoft", "浏览器",
            {"msedge.exe"}, {"Microsoft Corporation", "Microsoft Windows"});
    s << mk("bin-firefox", "Mozilla Firefox", "Mozilla", "浏览器",
            {"firefox.exe"}, {"Mozilla Corporation"});
    s << mk("bin-opera", "Opera 浏览器", "Opera", "浏览器",
            {"opera.exe"}, {"Opera Norway", "Opera Software"});
    s << mk("bin-brave", "Brave 浏览器", "Brave", "浏览器",
            {"brave.exe"}, {"Brave Software"});
    s << mk("bin-vivaldi", "Vivaldi", "Vivaldi", "浏览器",
            {"vivaldi.exe"}, {"Vivaldi Technologies"});
    s << mk("bin-360browser", "360浏览器 / 极速浏览器X", "360", "浏览器",
            {"360browser.exe", "360chrome.exe", "360se.exe", "browser.exe"},
            {"360", "Qihoo 360", "Beijing Qihu"});
    s << mk("bin-qqbrowser", "QQ浏览器", "腾讯", "浏览器",
            {"qqbrowser.exe", "qqbrowser_core.exe"}, {"Tencent"});
    s << mk("bin-sogou", "搜狗浏览器 / 输入法", "搜狗", "浏览器",
            {"sogouexplorer.exe", "sogouinput.exe", "sgime.exe", "sogouwb.exe"},
            {"Sogou", "Sohu", "Beijing Sogou"});
    s << mk("bin-uc", "UC浏览器 / 夸克", "阿里", "浏览器",
            {"ucbrowser.exe", "quark.exe", "quarkbrowser.exe"}, {"UC", "Quark", "Alibaba"});
    s << mk("bin-maxthon", "傲游浏览器", "傲游", "浏览器",
            {"maxthon.exe", "maxthon64.exe"}, {"Maxthon"});
    s << mk("bin-2345", "2345浏览器 / 好压", "2345", "浏览器",
            {"2345explorer.exe", "2345chrome.exe", "2345zip.exe", "haozip.exe"},
            {"2345", "Shanghai 2345"});
    s << mk("bin-office", "Microsoft Office", "Microsoft", "办公",
            {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
             "onenote.exe", "mspub.exe", "visio.exe", "winproj.exe"},
            {"Microsoft Corporation"});
    s << mk("bin-wps", "WPS Office", "Kingsoft", "办公",
            {"wps.exe", "et.exe", "wpp.exe", "wpscloud.exe"},
            {"Kingsoft", "Zhuhai Kingsoft"});
    s << mk("bin-pdf", "Adobe Acrobat / Reader", "Adobe", "办公",
            {"acrord32.exe", "acrobat.exe"}, {"Adobe Inc", "Adobe Systems"});
    s << mk("bin-foxit", "福昕 PDF", "Foxit", "办公",
            {"foxitreader.exe", "foxitphantom.exe", "foxitedit.exe"}, {"Foxit"});
    s << mk("bin-notepadpp", "Notepad++", "Notepad++", "办公",
            {"notepad++.exe"}, {"Notepad++", "Don Ho"});
    s << mk("bin-typora", "Typora", "Typora", "办公",
            {"typora.exe"}, {"Typora"});
    s << mk("bin-onlyoffice", "ONLYOFFICE", "ONLYOFFICE", "办公",
            {"onlyoffice.exe", "desktopeditors.exe"}, {"ONLYOFFICE", "Ascensio"});
    s << mk("bin-libreoffice", "LibreOffice", "The Document Foundation", "办公",
            {"soffice.exe", "swriter.exe", "scalc.exe", "simpress.exe"},
            {"The Document Foundation", "LibreOffice"});
    s << mk("bin-sumatra", "SumatraPDF", "Sumatra", "办公",
            {"sumatrapdf.exe"}, {"Sumatra", "Krzysztof Kowalczyk"});
    s << mk("bin-xmind", "XMind 思维导图", "XMind", "办公",
            {"xmind.exe"}, {"XMind"});
    s << mk("bin-obsidian", "Obsidian", "Obsidian", "办公",
            {"obsidian.exe"}, {"Obsidian"});
    s << mk("bin-notion", "Notion", "Notion", "办公",
            {"notion.exe"}, {"Notion"});
    s << mk("bin-yuque", "语雀 / 有道云笔记", "阿里/有道", "办公",
            {"yuque.exe", "youdaonote.exe", "ynote.exe"},
            {"Yuque", "Alibaba", "Youdao", "NetEase Youdao"});
    s << mk("bin-wecom-doc", "腾讯文档 / 石墨文档", "腾讯/石墨", "办公",
            {"tencentdocs.exe", "shimo.exe"}, {"Tencent", "Shimo"});
    s << mk("bin-cnki", "CAJViewer / 知网", "同方知网", "办公",
            {"cajviewer.exe", "caj.exe"}, {"CNKI", "Tongfang"});
    s << mk("bin-grammarly", "Grammarly", "Grammarly", "办公",
            {"grammarly.exe"}, {"Grammarly"});
    s << mk("bin-lark-doc", "飞书文档 / 钉钉文档", "字节/阿里", "办公",
            {"feishudocs.exe", "dingtalkdocs.exe"}, {"ByteDance", "Alibaba", "DingTalk"});
    s << mk("bin-qq", "QQ / TIM", "腾讯", "即时通讯",
            {"qq.exe", "tim.exe", "qqprotect.exe"},
            {"Tencent Technology", "Shenzhen Tencent"});
    s << mk("bin-wechat", "微信 / 企业微信", "腾讯", "即时通讯",
            {"wechat.exe", "weixin.exe", "wxwork.exe"},
            {"Tencent Technology", "Shenzhen Tencent"});
    s << mk("bin-dingtalk", "钉钉", "阿里", "即时通讯",
            {"dingtalk.exe", "dingtalklauncher.exe"}, {"Alibaba", "DingTalk"});
    s << mk("bin-feishu", "飞书", "字节跳动", "即时通讯",
            {"feishu.exe", "lark.exe"}, {"ByteDance", "Beijing Feishu"});
    s << mk("bin-whatsapp", "WhatsApp", "Meta", "即时通讯",
            {"whatsapp.exe"}, {"WhatsApp", "Meta Platforms"});
    s << mk("bin-telegram", "Telegram", "Telegram", "即时通讯",
            {"telegram.exe"}, {"Telegram FZ-LLC", "Telegram"});
    s << mk("bin-skype", "Skype", "Microsoft", "即时通讯",
            {"skype.exe"}, {"Microsoft Corporation"});
    s << mk("bin-teams", "Microsoft Teams", "Microsoft", "即时通讯",
            {"teams.exe", "ms-teams.exe"}, {"Microsoft Corporation"});
    s << mk("bin-line", "LINE / KakaoTalk", "LINE/Kakao", "即时通讯",
            {"line.exe", "kakaotalk.exe"}, {"LINE", "Kakao", "LY Corporation"});
    s << mk("bin-discord", "Discord", "Discord", "即时通讯",
            {"discord.exe", "discordptb.exe", "discordcanary.exe"}, {"Discord"});
    s << mk("bin-slack", "Slack", "Slack", "即时通讯",
            {"slack.exe"}, {"Slack", "Salesforce"});
    s << mk("bin-qqnt", "QQ新版 / TIM", "腾讯", "即时通讯",
            {"qqnt.exe", "qq.exe"}, {"Tencent", "Shenzhen Tencent"});
    s << mk("bin-yy", "YY语音 / 虎牙", "欢聚时代", "即时通讯",
            {"yy.exe", "duowan.exe", "huyalive.exe"},
            {"YY", "Huya", "Guangzhou Huya", "Joyy"});
    s << mk("bin-douyin-live", "抖音直播伴侣 / 快手", "字节/快手", "即时通讯",
            {"douyinlive.exe", "livecompanion.exe", "kwaishou.exe"},
            {"ByteDance", "Douyin", "Kuaishou", "Beijing Kuaishou"});
    s << mk("bin-vscode", "Visual Studio Code", "Microsoft", "开发",
            {"code.exe"}, {"Microsoft Corporation"});
    s << mk("bin-vs", "Visual Studio", "Microsoft", "开发",
            {"devenv.exe", "ssms.exe"}, {"Microsoft Corporation"});
    s << mk("bin-idea", "IntelliJ / JetBrains", "JetBrains", "开发",
            {"idea64.exe", "pycharm64.exe", "webstorm64.exe", "clion64.exe",
             "goland64.exe", "rider64.exe", "datagrip64.exe"},
            {"JetBrains"});
    s << mk("bin-git", "Git for Windows", "Git", "开发",
            {"git.exe", "git-bash.exe", "git-gui.exe"},
            {"The Git", "Git for Windows", "Software Freedom Conservancy"});
    s << mk("bin-node", "Node.js", "OpenJS", "开发",
            {"node.exe", "npm.exe", "npx.exe"}, {"OpenJS", "Node.js"});
    s << mk("bin-python", "Python", "Python Software Foundation", "开发",
            {"python.exe", "pythonw.exe", "pip.exe"},
            {"Python Software Foundation"});
    s << mk("bin-docker", "Docker Desktop", "Docker", "开发",
            {"docker desktop.exe", "docker.exe", "com.docker.backend.exe"}, {"Docker"});
    s << mk("bin-postman", "Postman", "Postman", "开发",
            {"postman.exe"}, {"Postman"});
    s << mk("bin-git-desktop", "GitHub Desktop", "GitHub", "开发",
            {"githubdesktop.exe", "github.exe"}, {"GitHub", "The GitHub"});
    s << mk("bin-sublime", "Sublime Text", "Sublime", "开发",
            {"sublime_text.exe", "sublime_text_3.exe"}, {"Sublime"});
    s << mk("bin-hbuilderx", "HBuilderX / 微信开发者工具", "DCloud/腾讯", "开发",
            {"hbuilderx.exe", "wechatwebdevtools.exe"},
            {"DCloud", "Tencent", "WeChat"});
    s << mk("bin-navicat", "Navicat", "PremiumSoft", "开发",
            {"navicat.exe", "navicat64.exe", "navicatpremium.exe"}, {"PremiumSoft", "Navicat"});
    s << mk("bin-dbeaver", "DBeaver", "DBeaver", "开发",
            {"dbeaver.exe"}, {"DBeaver", "dbeaver.io"});
    s << mk("bin-xshell", "Xshell / Xftp", "NetSarang", "开发",
            {"xshell.exe", "xftp.exe", "xshell7.exe", "xftp7.exe"}, {"NetSarang"});
    s << mk("bin-finalshell", "FinalShell / MobaXterm", "FinalShell/Mobatek", "开发",
            {"finalshell.exe", "mobaxterm.exe"}, {"FinalShell", "Mobatek"});
    s << mk("bin-vmware", "VMware Workstation", "VMware", "开发",
            {"vmware.exe", "vmware-vmx.exe", "vmplayer.exe", "vmware-tray.exe"},
            {"VMware", "VMware, Inc"});
    s << mk("bin-virtualbox", "VirtualBox", "Oracle", "开发",
            {"virtualbox.exe", "virtualboxvm.exe", "vboxmanage.exe"}, {"Oracle", "VirtualBox"});
    s << mk("bin-eclipse", "Eclipse", "Eclipse", "开发",
            {"eclipse.exe"}, {"Eclipse", "Eclipse Foundation"});
    s << mk("bin-android-studio", "Android Studio", "Google", "开发",
            {"studio64.exe", "studio.exe"}, {"Google"});
    s << mk("bin-rust-analyzer", "RustRover / GoLand", "JetBrains", "开发",
            {"rustrover64.exe", "goland64.exe"}, {"JetBrains"});
    s << mk("bin-charles", "Charles / Fiddler", "Charles/Fiddler", "开发",
            {"charles.exe", "fiddler.exe", "fiddler everywhere.exe"},
            {"Charles", "XK72", "Telerik", "Progress"});
    s << mk("bin-wireshark", "Wireshark", "Wireshark", "开发",
            {"wireshark.exe", "dumpcap.exe"}, {"Wireshark", "Gerald Combs"});
    s << mk("bin-sublime-merge", "Sublime Merge", "Sublime", "开发",
            {"sublime_merge.exe"}, {"Sublime"});
    s << mk("bin-7zip", "7-Zip", "Igor Pavlov", "压缩",
            {"7z.exe", "7zfm.exe", "7zg.exe"}, {"Igor Pavlov"});
    s << mk("bin-winrar", "WinRAR", "win.rar", "压缩",
            {"winrar.exe", "rar.exe"}, {"win.rar", "Alexander Roshal"});
    s << mk("bin-bandizip", "Bandizip", "Bandisoft", "压缩",
            {"bandizip.exe", "bandizip64.exe"}, {"Bandisoft"});
    s << mk("bin-360zip", "360压缩", "360", "压缩",
            {"360zip.exe", "360zipcore.exe", "360zips.exe"},
            {"360", "Qihoo 360", "Beijing Qihu"});
    s << mk("bin-baidu-netdisk", "百度网盘", "百度", "传输",
            {"baidunetdisk.exe", "baidunetdiskhost.exe"}, {"Baidu", "Beijing Baidu"});
    s << mk("bin-weiyun", "腾讯微云", "腾讯", "传输",
            {"weiyun.exe"}, {"Tencent"});
    s << mk("bin-aliyundrive", "阿里云盘", "阿里", "传输",
            {"aliyundrive.exe", "aliyunpan.exe"}, {"Alibaba", "Aliyun", "阿里"});
    s << mk("bin-115", "115网盘 / 坚果云", "115/坚果云", "传输",
            {"115.exe", "115browser.exe", "nutstore.exe"},
            {"115", "Nutstore", "YiQu"});
    s << mk("bin-qqdownload", "QQ旋风 / 迅雷极速版", "腾讯/迅雷", "传输",
            {"qqdownloader.exe", "thunderlite.exe", "xiunian.exe"},
            {"Tencent", "Xunlei", "Thunder"});
    s << mk("bin-motrix", "Motrix / qBittorrent", "开源", "传输",
            {"motrix.exe", "qbittorrent.exe"}, {"Motrix", "qBittorrent", "The qBittorrent"});
    s << mk("bin-filezilla", "FileZilla", "FileZilla", "传输",
            {"filezilla.exe"}, {"FileZilla", "Tim Kosse"});
    s << mk("bin-winscp", "WinSCP", "WinSCP", "传输",
            {"winscp.exe"}, {"WinSCP", "Martin Prikryl"});
    s << mk("bin-pan-download", "Pandownload / 夸克网盘", "第三方/夸克", "传输",
            {"pandownload.exe", "quarkdrive.exe"}, {"Pandownload", "Quark", "Alibaba"});
    s << mk("bin-obs", "OBS Studio", "OBS", "媒体",
            {"obs64.exe", "obs32.exe"}, {"OBS", "obsproject"});
    s << mk("bin-potplayer", "PotPlayer", "Kakao", "媒体",
            {"potplayer.exe", "potplayer64.exe", "potplayermini.exe"}, {"Kakao", "DAUM"});
    s << mk("bin-vlc", "VLC", "VideoLAN", "媒体",
            {"vlc.exe"}, {"VideoLAN"});
    s << mk("bin-qqmusic", "QQ音乐 / 酷狗 / 酷我", "腾讯/酷狗", "媒体",
            {"qqmusic.exe", "kugou.exe", "kuwo.exe"},
            {"Tencent", "Kugou", "Guangzhou Kugou", "Kuwo"});
    s << mk("bin-neteasemusic", "网易云音乐", "网易", "媒体",
            {"cloudmusic.exe"}, {"NetEase", "Hangzhou NetEase"});
    s << mk("bin-iyk", "爱奇艺 / 优酷 / 腾讯视频", "长视频", "媒体",
            {"iqiyi.exe", "youkudesktop.exe", "qqlive.exe"},
            {"iQiyi", "Youku", "Tencent"});
    s << mk("bin-ps", "Adobe Photoshop / Lightroom", "Adobe", "媒体",
            {"photoshop.exe", "lightroom.exe"}, {"Adobe"});
    s << mk("bin-pr", "Adobe Premiere / After Effects", "Adobe", "媒体",
            {"adobe premiere pro.exe", "afterfx.exe"}, {"Adobe"});
    s << mk("bin-davinci", "DaVinci Resolve", "Blackmagic", "媒体",
            {"resolve.exe", "davinci resolve.exe"}, {"Blackmagic"});
    s << mk("bin-handbrake", "HandBrake", "HandBrake", "媒体",
            {"handbrake.exe"}, {"HandBrake"});
    s << mk("bin-formatfactory", "格式工厂", "格式工厂", "媒体",
            {"formatfactory.exe", "ff.exe"}, {"Format Factory", "FreeTime"});
    s << mk("bin-iris", "EV录屏 / 班迪录屏", "国内/班迪", "媒体",
            {"evcapture.exe", "bandicam.exe", "bdcam.exe"},
            {"EVCapture", "Bandicam", "Bandisoft"});
    s << mk("bin-snagit", "Snagit / FastStone", "TechSmith/FastStone", "媒体",
            {"snagit.exe", "fscapture.exe", "fsviewer.exe"},
            {"TechSmith", "FastStone"});
    s << mk("bin-figma", "Figma", "Figma", "媒体",
            {"figma.exe"}, {"Figma"});
    s << mk("bin-mastergo", "MasterGo / 即时设计", "国产设计", "媒体",
            {"mastergo.exe", "jsdesign.exe"}, {"MasterGo", "JSD"});
    s << mk("bin-blender", "Blender", "Blender", "媒体",
            {"blender.exe"}, {"Blender", "Blender Foundation"});
    s << mk("bin-c4d", "Cinema 4D / 3ds Max", "Maxon/Autodesk", "媒体",
            {"cinema 4d.exe", "c4d.exe", "3dsmax.exe", "3dsmax.exe"},
            {"Maxon", "Autodesk"});
    s << mk("bin-autocad", "AutoCAD / 天正建筑", "Autodesk/天正", "媒体",
            {"acad.exe", "autocad.exe", "tarch.exe", "tstart.exe"},
            {"Autodesk", "Tangent", "天正"});
    s << mk("bin-sketup", "SketchUp / Revit", "Trimble/Autodesk", "媒体",
            {"sketchup.exe", "revit.exe"}, {"Trimble", "Autodesk"});
    s << mk("bin-audition", "Adobe Audition / AU", "Adobe", "媒体",
            {"adobe audition.exe", "audition.exe"}, {"Adobe"});
    s << mk("bin-lr", "Lightroom Classic", "Adobe", "媒体",
            {"lightroom classic.exe", "lightroom.exe"}, {"Adobe"});
    s << mk("bin-360safe", "360安全卫士 / 极速版", "360", "安全",
            {"360safe.exe", "360tray.exe", "360sd.exe", "zhudongfangyu.exe"},
            {"360", "Qihoo 360", "Beijing Qihu"});
    s << mk("bin-huorong", "火绒", "火绒", "安全",
            {"hipstray.exe", "hipsdaemon.exe", "usysdiag.exe"},
            {"Huorong", "火绒", "北京火绒网络科技有限公司"});
    s << mk("bin-tencent-pc", "电脑管家", "腾讯", "安全",
            {"qqpcrtp.exe", "qqpctray.exe", "qqpcsafe.exe"},
            {"Tencent", "Shenzhen Tencent"});
    s << mk("bin-geek", "Geek Uninstaller", "Geek", "安全",
            {"geek.exe", "geek64.exe"}, {"Geek"});
    s << mk("bin-everything", "Everything", "voidtools", "安全",
            {"everything.exe", "everything64.exe"}, {"voidtools", "David Carpenter"});
    s << mk("bin-ccleaner", "CCleaner", "Piriform", "安全",
            {"ccleaner.exe", "ccleaner64.exe"}, {"Piriform", "Gen Digital", "Avast"});
    s << mk("bin-avast", "Avast / AVG", "Avast/AVG", "安全",
            {"avastui.exe", "avastsvc.exe", "avgui.exe", "avgsvc.exe"},
            {"Avast", "AVG", "Gen Digital"});
    s << mk("bin-avira", "Avira 小红伞", "Avira", "安全",
            {"avira.exe", "aviraoptimizer.exe"}, {"Avira", "Gen Digital"});
    s << mk("bin-bitdefender", "Bitdefender", "Bitdefender", "安全",
            {"bdagent.exe", "bdservicehost.exe"}, {"Bitdefender", "Softwin"});
    s << mk("bin-malwarebytes", "Malwarebytes", "Malwarebytes", "安全",
            {"mbam.exe", "mbamtray.exe", "mbamservice.exe"}, {"Malwarebytes"});
    s << mk("bin-kaspersky", "卡巴斯基", "Kaspersky", "安全",
            {"avp.exe", "avpui.exe", "kaspersky.exe"},
            {"Kaspersky", "AO Kaspersky", "Kaspersky Lab"});
    s << mk("bin-eset", "ESET NOD32", "ESET", "安全",
            {"egui.exe", "ekrn.exe", "eset.exe"}, {"ESET", "ESET, spol"});
    s << mk("bin-sophos", "Sophos", "Sophos", "安全",
            {"sophosui.exe", "sophoshealth.exe"}, {"Sophos"});
    s << mk("bin-2345safe", "2345安全卫士 / 腾讯电脑管家(旧)", "2345", "安全",
            {"2345safe.exe", "2345tray.exe", "qqpcmgr.exe"},
            {"2345", "Tencent"});
    s << mk("bin-drivergenius", "驱动精灵 / 驱动人生", "驱动工具", "安全",
            {"drivergenius.exe", "driversgenius.exe", "drvlife.exe", "driverlife.exe"},
            {"DriverGenius", "Drivethelife", "深圳市驱动人生"});
    s << mk("bin-ludashi", "鲁大师 / 图吧工具箱", "鲁大师", "安全",
            {"ludashi.exe", "master.exe", "tbspeed.exe"},
            {"LuDaShi", "Qihoo", "360"});
    s << mk("bin-dismpp", "Dism++ / 火绒剑", "开源/火绒", "安全",
            {"dism++.exe", "dismpp.exe", "sysdiag.exe"},
            {"Dism++", "Huorong", "北京火绒网络科技有限公司", "Chuyu"});
    s << mk("bin-procexp", "Process Explorer / Autoruns", "Microsoft Sysinternals", "安全",
            {"procexp.exe", "procexp64.exe", "autoruns.exe", "autorunsc.exe"},
            {"Microsoft", "Sysinternals"});
    s << mk("bin-hwinfo", "HWiNFO / CPU-Z", "HWiNFO/CPUID", "安全",
            {"hwinfo64.exe", "hwinfo32.exe", "cpuz.exe", "cpuz64.exe"},
            {"HWiNFO", "CPUID"});
    s << mk("bin-crystaldisk", "CrystalDiskInfo / Mark", "Crystal Dew", "安全",
            {"crystaldiskinfo.exe", "crystaldiskmark.exe"}, {"Crystal Dew", "CrystalDisk"});
    s << mk("bin-aida64", "AIDA64", "FinalWire", "安全",
            {"aida64.exe", "aida64extreme.exe"}, {"FinalWire", "AIDA64"});
    s << mk("bin-idm", "IDM 下载器", "Tonec", "传输",
            {"idman.exe", "idm64.exe"}, {"Tonec"});
    s << mk("bin-thunder", "迅雷", "迅雷", "传输",
            {"thunder.exe", "thunderplatform.exe"}, {"Thunder", "Xunlei", "深圳市迅雷"});
    s << mk("bin-toDesk", "ToDesk / 向日葵 / AnyDesk", "远程协助", "远程",
            {"todesk.exe", "sunloginclient.exe", "anydesk.exe"},
            {"ToDesk", "Sunlogin", "Oray", "AnyDesk"});
    s << mk("bin-teamviewer", "TeamViewer", "TeamViewer", "远程",
            {"teamviewer.exe", "teamviewer_service.exe"}, {"TeamViewer"});
    s << mk("bin-remote-desktop", "Windows 远程桌面 / 向日葵(官方)", "Microsoft/Oray", "远程",
            {"mstsc.exe", "msrdc.exe", "sunloginclient.exe"},
            {"Microsoft", "Oray", "Sunlogin"});
    s << mk("bin-rustdesk-official", "RustDesk(官方)", "RustDesk", "远程",
            {"rustdesk.exe"}, {"RustDesk"});
    s << mk("bin-parsec", "Parseced / Moonlight", "Parsec/Moonlight", "远程",
            {"parsec.exe", "parsec-vdd.exe", "moonlight.exe"},
            {"Parsec", "Moonlight"});
    s << mk("bin-dida", "滴答清单 / 印象笔记", "效率", "其他",
            {"dida.exe", "yinxiang.exe"}, {"Dida", "Evernote", "Yinxiang"});
    s << mk("bin-bluestacks", "模拟器(雷电/夜神/MuMu)", "模拟器", "其他",
            {"ldplayer.exe", "nox.exe", "mumu.exe", "nemu.exe"},
            {"Ldplayer", "Nox", "Netease", "MuMu"});
    s << mk("bin-steam", "Steam", "Valve", "游戏",
            {"steam.exe", "steamservice.exe", "steamwebhelper.exe"}, {"Valve"});
    s << mk("bin-epic", "Epic Games", "Epic", "游戏",
            {"epicgameslauncher.exe", "epicwebhelper.exe"}, {"Epic Games", "Epic"});
    s << mk("bin-battle", "暴雪战网 / Battle.net", "Blizzard", "游戏",
            {"battle.net.exe", "agent.exe", "launcher.exe"},
            {"Blizzard", "Battle.net"});
    s << mk("bin-wegame", "WeGame / 腾讯游戏平台", "腾讯", "游戏",
            {"wegame.exe", "tgp.exe", "tenprotect.exe"}, {"Tencent", "WeGame"});
    s << mk("bin-qqgame", "QQ游戏 / 浩方", "腾讯/浩方", "游戏",
            {"qqgame.exe", "hfgame.exe"}, {"Tencent", "Haofang"});
    s << mk("bin-uu", "UU加速器 / 迅游", "网易/迅游", "游戏",
            {"uu.exe", "uuaccelerator.exe", "xunyou.exe"},
            {"NetEase", "Xunyou", "UU"});
    s << mk("bin-genshin", "原神 / 崩坏:星穹铁道", "米哈游", "游戏",
            {"genshinimpact.exe", "star rail.exe", "hoyoverse.exe", "mihoyosdk.exe"},
            {"miHoYo", "Cognosphere", "HoYoverse"});
    s << mk("bin-lol", "英雄联盟 / WeGame组件", "腾讯/Riot", "游戏",
            {"league of legends.exe", "lol.launcher.exe", "riotclientservices.exe"},
            {"Tencent", "Riot Games"});
    s << mk("bin-alipay", "支付宝 / 财付通", "阿里/腾讯", "金融",
            {"alipay.exe", "aliedit.exe", "taodding.exe", "tenpay.exe"},
            {"Alipay", "Alibaba", "Tencent", "Tenpay"});
    s << mk("bin-bank", "工行/建行/招行网银助手", "银行", "金融",
            {"icbc.exe", "ccb.exe", "cmb.exe", "bankhelper.exe"},
            {"ICBC", "CCB", "CMB", "中国工商银行", "中国建设银行", "招商银行"});
    s << mk("bin-eastmoney", "同花顺 / 东方财富 / 通达信", "行情软件", "金融",
            {"hexin.exe", "hexinflush.exe", "eastmoney.exe", "tdxw.exe", "tdxw64.exe"},
            {"Hexin", "Eastmoney", "TDX", "同花顺", "东方财富"});
    s << mk("bin-htsec", "券商交易软件(大智慧/涨乐)", "券商", "金融",
            {"dzh.exe", "dzh2.exe", "hlzq.exe", "csc.exe"},
            {"DZH", "Huatai", "CSC", "大智慧", "华泰"});
    s << mk("bin-youdao", "有道词典 / 百度翻译", "有道/百度", "其他",
            {"youdaodict.exe", "dict.exe", "baidufanyi.exe"},
            {"Youdao", "NetEase", "Baidu"});
    s << mk("bin-wps-pdf", "WPS图片 / 看图王", "金山/2345", "其他",
            {"wpsphoto.exe", "kpicture.exe", "2345pic.exe"},
            {"Kingsoft", "2345"});
    s << mk("bin-hujiang", "有道精品课 / 腾讯课堂", "教育", "其他",
            {"youdaoclass.exe", "ke.qq.com.exe", "tencentclass.exe"},
            {"Youdao", "Tencent", "NetEase"});
    s << mk("bin-ime", "搜狗/百度/微软拼音输入法", "输入法", "其他",
            {"sogouinput.exe", "baiduinput.exe", "input.exe", "ctfmon.exe"},
            {"Sogou", "Baidu", "Microsoft", "Pinyin"});
    s << mk("bin-clipboard", "Ditto / Listary / Quicker", "效率工具", "其他",
            {"ditto.exe", "listary.exe", "quicker.exe"},
            {"Ditto", "Listary", "Quicker"});
    s << mk("bin-space-sniffer", "SpaceSniffer / WizTree", "磁盘工具", "其他",
            {"spacesniffer.exe", "wiztree.exe", "wiztree64.exe"},
            {"SpaceSniffer", "WizTree", "Antibody"});
    s << mk("bin-clash", "Clash / V2RayN / Clash Verge", "开源代理", "其他",
            {"clash.exe", "clash-for-windows.exe", "v2rayn.exe", "clash verge.exe", "verge.exe"},
            {"Clash", "V2Ray", "clash-verge"});
    s << mk("bin-steam-tools", "Steam++ / Watt Toolkit", "开源", "其他",
            {"steam++.exe", "watt.exe", "steamtools.exe"}, {"Steam++", "Watt", "Beyond"});
    s << mk("bin-hyper-v", "Hyper-V 管理器", "Microsoft", "开发",
            {"vmconnect.exe", "virtmgmt.msc", "vmms.exe"}, {"Microsoft"});
    s << mk("bin-wsl", "Windows Terminal / WSL", "Microsoft", "开发",
            {"windowsterminal.exe", "wt.exe", "wsl.exe", "wslhost.exe"},
            {"Microsoft Corporation"});
    s << mk("bin-fdm", "Free Download Manager", "FDM", "传输",
            {"fdm.exe", "fdm64.exe"}, {"Free Download Manager", "SoftDeluxe"});
    s << mk("bin-proxy-switchy", "SwitchyOmega / Proxyman", "代理工具", "其他",
            {"proxyman.exe", "switchyomega.exe"}, {"Proxyman", "SwitchyOmega"});
    s << mk("bin-wemeet", "腾讯会议", "腾讯", "即时通讯",
            {"wemeetapp.exe", "wemeet.exe"}, {"Tencent"});
    s << mk("bin-zoom", "Zoom", "Zoom", "即时通讯",
            {"zoom.exe"}, {"Zoom Video Communications", "Zoom Communications"});
    s << mk("bin-mail", "Foxmail / 网易邮箱大师 / Thunderbird", "邮件客户端", "办公",
            {"foxmail.exe", "mailmaster.exe", "thunderbird.exe"},
            {"Tencent", "NetEase", "Mozilla Corporation"});
    s << mk("bin-powertoys", "PowerToys / OneDrive", "Microsoft", "办公",
            {"powertoys.exe", "onedrive.exe"}, {"Microsoft Corporation"});
    s << mk("bin-zotero", "Zotero", "Zotero", "办公",
            {"zotero.exe"}, {"Corporation for Digital Scholarship"});
    s << mk("bin-pwmgr", "密码管理器(KeePass/KeePassXC/Bitwarden/1Password)", "密码管理", "安全",
            {"keepass.exe", "keepassxc.exe", "bitwarden.exe", "1password.exe"},
            {"Dominik Reichl", "DroidMonkey", "Bitwarden", "AgileBits"});
    s << mk("bin-cursor", "Cursor", "Anysphere", "开发",
            {"cursor.exe"}, {"Anysphere"});
    s << mk("bin-unity", "Unity / Unity Hub", "Unity", "开发",
            {"unity.exe", "unity hub.exe"}, {"Unity Technologies"});
    s << mk("bin-putty", "PuTTY", "Simon Tatham", "开发",
            {"putty.exe"}, {"Simon Tatham"});
    s << mk("bin-spotify", "Spotify", "Spotify", "媒体",
            {"spotify.exe"}, {"Spotify AB", "Spotify Ltd"});
    s << mk("bin-paintnet", "Paint.NET / Honeyview", "dotPDN/Bandisoft", "媒体",
            {"paintdotnet.exe", "honeyview.exe"}, {"dotPDN", "Bandisoft"});
    s << mk("bin-qqplayer", "QQ影音 / 迅雷影音", "腾讯/迅雷", "媒体",
            {"qqplayer.exe", "xmp.exe"}, {"Tencent", "Xunlei", "Shenzhen Xunlei"});
    s << mk("bin-jianying", "剪映专业版", "字节跳动", "媒体",
            {"jianyingpro.exe"}, {"ByteDance", "Beijing ByteDance", "Lemon"});
    s << mk("bin-itunes", "iTunes / iCloud", "Apple", "媒体",
            {"itunes.exe", "icloud.exe", "applemobiledeviceservice.exe"}, {"Apple Inc"});
    s << mk("bin-dropbox", "Dropbox", "Dropbox", "传输",
            {"dropbox.exe"}, {"Dropbox, Inc"});
    s << mk("bin-ea-ubi", "EA app / Ubisoft Connect", "EA/Ubisoft", "游戏",
            {"eadesktop.exe", "origin.exe", "upc.exe", "ubisoftconnect.exe"},
            {"Electronic Arts", "Ubisoft Entertainment"});
    s << mk("bin-gog", "GOG Galaxy", "GOG", "游戏",
            {"galaxyclient.exe"}, {"GOG Sp. z o.o", "GOG"});
    s << mk("bin-nvidia", "NVIDIA 驱动常驻组件", "NVIDIA", "硬件",
            {"nvcontainer.exe", "nvdisplay.container.exe", "nvidia share.exe",
             "nvidia app.exe", "nvidia overlay.exe"},
            {"NVIDIA Corporation"});
    s << mk("bin-amd", "AMD Adrenalin 组件", "AMD", "硬件",
            {"radeonsoftware.exe", "amdrsserv.exe", "amdow.exe"},
            {"Advanced Micro Devices"});
    s << mk("bin-intel", "Intel 显卡控制中心 / 驱动助理", "Intel", "硬件",
            {"igfxem.exe", "intelgraphicssoftware.exe", "dsatray.exe"},
            {"Intel Corporation"});
    s << mk("bin-logi", "Logitech G HUB / Options+", "Logitech", "硬件",
            {"lghub.exe", "lghub_agent.exe", "lghub_updater.exe", "logioptionsplus_agent.exe"},
            {"Logitech"});
    s << mk("bin-armoury", "华硕 Armoury Crate", "ASUS", "硬件",
            {"armourycrate.service.exe", "armourycrate.usersessionhelper.exe"},
            {"ASUSTeK"});
    s << mk("bin-msi-afterburner", "MSI Afterburner / Center", "MSI", "硬件",
            {"msiafterburner.exe", "msi center.exe"}, {"Micro-Star International", "MICRO-STAR"});
    s << mk("bin-nas", "Synology Drive / QNAP Qfinder", "Synology/QNAP", "硬件",
            {"cloud-drive-ui.exe", "synologydrive.exe", "qfinderpro.exe"},
            {"Synology", "QNAP Systems"});

    s << mk("bin-calibre", "Calibre 电子书管理", "Kovid Goyal", "办公",
            {"calibre.exe", "ebook-viewer.exe", "ebook-edit.exe"}, {"Kovid Goyal"});
    s << mk("bin-endnote", "EndNote / Mendeley", "Clarivate/Elsevier", "办公",
            {"endnote.exe", "mendeley reference manager.exe"}, {"Clarivate", "Elsevier"});
    s << mk("bin-scrivener", "Scrivener", "Literature and Latte", "办公",
            {"scrivener.exe"}, {"Literature and Latte"});
    s << mk("bin-anki", "Anki 记忆卡", "Ankitects", "办公",
            {"anki.exe"}, {"Ankitects"});
    s << mk("bin-miktex", "MiKTeX / TeXstudio", "MiKTeX/TeXstudio", "办公",
            {"miktex-console.exe", "texworks.exe", "texstudio.exe"},
            {"MiKTeX", "Christian Schenk", "TeXstudio"});
    s << mk("bin-edraw", "亿图图示 / 亿图脑图", "EdrawSoft", "办公",
            {"edrawmax.exe", "mindmaster.exe"}, {"EdrawSoft", "Wondershare"});
    s << mk("bin-zcad", "中望CAD / 浩辰CAD", "中望/浩辰", "工程",
            {"zwcad.exe", "gcad.exe"}, {"ZWSOFT", "Gstarsoft", "Suzhou Gstarsoft"});
    s << mk("bin-matlab", "MATLAB / Simulink", "MathWorks", "工程",
            {"matlab.exe"}, {"The MathWorks", "MathWorks"});
    s << mk("bin-mathematica", "Mathematica", "Wolfram", "工程",
            {"mathematica.exe", "wolframnb.exe"}, {"Wolfram Research"});
    s << mk("bin-rstudio", "RStudio", "Posit", "工程",
            {"rstudio.exe"}, {"Posit Software", "RStudio"});
    s << mk("bin-origin", "Origin / OriginPro", "OriginLab", "工程",
            {"origin64.exe", "origin.exe"}, {"OriginLab"});
    s << mk("bin-stata", "Stata", "StataCorp", "工程",
            {"statamp-64.exe", "statase-64.exe", "statabe-64.exe"}, {"StataCorp"});
    s << mk("bin-prism", "GraphPad Prism", "GraphPad", "工程",
            {"prism.exe"}, {"GraphPad Software", "Dotmatics"});
    s << mk("bin-chemdraw", "ChemDraw", "Revvity", "工程",
            {"chemdraw.exe"}, {"PerkinElmer", "Revvity"});
    s << mk("bin-solidworks", "SolidWorks / CATIA", "Dassault Systemes", "工程",
            {"sldworks.exe", "cnext.exe"}, {"Dassault Systemes", "SolidWorks"});
    s << mk("bin-labview", "LabVIEW", "NI", "工程",
            {"labview.exe"}, {"National Instruments", "Emerson"});
    s << mk("bin-arcgis", "ArcGIS Pro", "Esri", "工程",
            {"arcgispro.exe", "arcmap.exe"}, {"Esri", "Environmental Systems Research"});
    s << mk("bin-kicad", "KiCad", "KiCad", "工程",
            {"kicad.exe", "eeschema.exe", "pcbnew.exe"}, {"KiCad Services"});
    s << mk("bin-mcu-ide", "STM32CubeIDE / Keil / Arduino IDE", "嵌入式", "工程",
            {"stm32cubeide.exe", "stm32cubemx.exe", "uv4.exe", "arduino ide.exe"},
            {"STMicroelectronics", "ARM Ltd", "Arm Limited", "Arduino"});
    s << mk("bin-editors-niche", "EmEditor / UltraEdit / Beyond Compare", "编辑与对比", "开发",
            {"emeditor.exe", "uedit64.exe", "uedit32.exe", "bcompare.exe"},
            {"Emurasoft", "IDM Computer Solutions", "Scooter Software"});
    s << mk("bin-winmerge", "WinMerge", "WinMerge", "开发",
            {"winmergeu.exe"}, {"WinMerge", "Takashi Sawanaka"});
    s << mk("bin-heidisql", "HeidiSQL", "Ansgar Becker", "开发",
            {"heidisql.exe"}, {"Ansgar Becker"});
    s << mk("bin-redis-gui", "Another Redis Desktop Manager / RedisInsight", "Redis 客户端", "开发",
            {"another redis desktop manager.exe", "redisinsight.exe"},
            {"qishibo", "Redis Ltd", "Redis Inc"});
    s << mk("bin-api-tools", "Apifox / Insomnia", "API 调试", "开发",
            {"apifox.exe", "insomnia.exe"}, {"Apifox", "Kong Inc"});
    s << mk("bin-git-gui", "SourceTree / Fork / GitKraken", "Git 客户端", "开发",
            {"sourcetree.exe", "fork.exe", "gitkraken.exe"},
            {"Atlassian", "Dan Pristupov", "Axosoft"});
    s << mk("bin-tortoise", "TortoiseGit / TortoiseSVN", "Tortoise", "开发",
            {"tortoisegitproc.exe", "tortoiseproc.exe"}, {"TortoiseGit", "TortoiseSVN", "Stefan Kueng"});
    s << mk("bin-terminal-niche", "Tabby / WindTerm / SecureCRT", "终端", "开发",
            {"tabby.exe", "windterm.exe", "securecrt.exe"},
            {"Eugene Pankov", "WindTerm", "VanDyke Software"});
    s << mk("bin-foobar", "foobar2000 / MusicBee / AIMP", "播放器", "媒体",
            {"foobar2000.exe", "musicbee.exe", "aimp.exe"},
            {"Peter Pawlowski", "Steven Mayall", "AIMP DevTeam", "Artem Izmaylov"});
    s << mk("bin-mpc", "MPC-HC / mpv", "开源播放器", "媒体",
            {"mpc-hc64.exe", "mpc-hc.exe", "mpv.exe"}, {"MPC-HC", "mpv"});
    s << mk("bin-irfanview", "IrfanView / XnView MP", "看图", "媒体",
            {"i_view64.exe", "i_view32.exe", "xnviewmp.exe"}, {"Irfan Skiljan", "XnView", "Pierre-Emmanuel Gougelet"});
    s << mk("bin-krita", "Krita / Inkscape / GIMP", "开源绘图", "媒体",
            {"krita.exe", "inkscape.exe", "gimp-2.10.exe", "gimp-3.0.exe"},
            {"Krita Foundation", "Stichting Krita", "Inkscape", "GIMP"});
    s << mk("bin-csp", "CLIP STUDIO PAINT / SAI", "CELSYS/SYSTEMAX", "媒体",
            {"clipstudiopaint.exe", "sai.exe", "sai2.exe"}, {"CELSYS", "SYSTEMAX"});
    s << mk("bin-affinity", "Affinity Photo / Designer", "Serif", "媒体",
            {"photo.exe", "designer.exe", "publisher.exe"}, {"Serif (Europe)", "Serif Europe"});
    s << mk("bin-audio-niche", "Audacity / Reaper / FL Studio", "音频", "媒体",
            {"audacity.exe", "reaper.exe", "fl64.exe", "fl.exe"},
            {"Audacity", "Muse Group", "Cockos", "Image-Line"});
    s << mk("bin-ableton", "Ableton Live / Cubase", "音频工作站", "媒体",
            {"ableton live 12 suite.exe", "ableton live 11 suite.exe", "cubase14.exe", "cubase13.exe"},
            {"Ableton", "Steinberg Media"});
    s << mk("bin-shotcut", "Shotcut / Kdenlive", "开源剪辑", "媒体",
            {"shotcut.exe", "kdenlive.exe"}, {"Meltytech", "KDE e.V"});
    s << mk("bin-mkvtoolnix", "MKVToolNix / MediaInfo", "媒体工具", "媒体",
            {"mkvtoolnix-gui.exe", "mediainfo.exe"}, {"Moritz Bunkus", "MediaArea"});
    s << mk("bin-music-cn", "千千静听 / 酷狗概念版 / 汽水音乐", "国产音乐", "媒体",
            {"ttplayer.exe", "qishui.exe"}, {"Baidu", "ByteDance", "Beijing ByteDance"});
    s << mk("bin-file-mgr", "Total Commander / Directory Opus / XYplorer", "文件管理", "其他",
            {"totalcmd64.exe", "totalcmd.exe", "dopus.exe", "xyplorer.exe"},
            {"Ghisler", "GPSoftware", "Donald Lessau"});
    s << mk("bin-files-app", "Files / OneCommander", "文件管理", "其他",
            {"files.exe", "onecommander.exe"}, {"Files Community", "Milos Paripovic"});
    s << mk("bin-launcher", "Flow Launcher / Wox / uTools", "启动器", "其他",
            {"flow.launcher.exe", "wox.exe", "utools.exe"},
            {"Flow Launcher", "Yuanli"});
    s << mk("bin-snipaste", "Snipaste / ShareX / PixPin", "截图", "其他",
            {"snipaste.exe", "sharex.exe", "pixpin.exe"},
            {"Snipaste", "Liu Zhiyong", "ShareX Team", "PixPin"});
    s << mk("bin-twinkle", "Twinkle Tray / f.lux / TranslucentTB", "桌面增强", "其他",
            {"twinkle tray.exe", "flux.exe", "translucenttb.exe"},
            {"Xander Frangos", "f.lux Software", "TranslucentTB"});
    s << mk("bin-backup", "FreeFileSync / Macrium / 傲梅轻松备份", "备份", "其他",
            {"freefilesync.exe", "realtimesync.exe", "reflect.exe", "backupper.exe"},
            {"FreeFileSync", "Zenju", "Paramount Software", "AOMEI"});
    s << mk("bin-disk-tools", "DiskGenius / 分区助手 / MiniTool", "分区工具", "其他",
            {"diskgenius.exe", "partassist.exe", "partitionwizard.exe"},
            {"Eassos", "易数科技", "AOMEI", "MiniTool"});
    s << mk("bin-usb-tools", "Rufus / Ventoy / balenaEtcher", "启动盘", "其他",
            {"rufus.exe", "ventoy2disk.exe", "balenaetcher.exe"},
            {"Akeo Consulting", "Ventoy", "Balena"});
    s << mk("bin-hw-monitor", "HWMonitor / GPU-Z / OCCT", "硬件检测", "硬件",
            {"hwmonitor.exe", "hwmonitor_x64.exe", "gpu-z.exe", "occt.exe"},
            {"CPUID", "TechPowerUp", "OCBASE"});
    s << mk("bin-fan-tools", "FanControl / Rainmeter / SignalRGB", "桌面硬件", "硬件",
            {"fancontrol.exe", "rainmeter.exe", "signalrgb.exe"},
            {"Remi Mercier", "Rainmeter", "WhirlwindFX"});
    s << mk("bin-av-niche", "Emsisoft / HitmanPro / Norton", "安全软件", "安全",
            {"a2guard.exe", "hitmanpro.exe", "nortonui.exe", "ns.exe"},
            {"Emsisoft", "Sophos", "Gen Digital", "NortonLifeLock", "Symantec"});
    s << mk("bin-veracrypt", "VeraCrypt / Cryptomator", "加密", "安全",
            {"veracrypt.exe", "cryptomator.exe"}, {"IDRIX", "Skymatic"});
    s << mk("bin-gpg", "Gpg4win / Kleopatra", "Gpg4win", "安全",
            {"kleopatra.exe"}, {"g10 Code", "Intevation"});
    s << mk("bin-im-niche", "Signal / Element / Thunderbird Chat", "开源通讯", "即时通讯",
            {"signal.exe", "element.exe"}, {"Signal Messenger", "New Vector"});
    s << mk("bin-voice-niche", "KOOK / TeamSpeak / Mumble", "语音", "即时通讯",
            {"kook.exe", "kaiheila.exe", "ts3client_win64.exe", "teamspeak.exe", "mumble.exe"},
            {"KOOK", "Kaiheila", "Chengdu Kaiheila", "TeamSpeak Systems"});
    s << mk("bin-welink", "WeLink / 政务微信 / 蓝信", "政企通讯", "即时通讯",
            {"welink.exe", "gov_wechat.exe", "lanxin.exe"},
            {"Huawei", "Tencent", "Lanxin"});
    s << mk("bin-game-launchers", "Playnite / itch.io / Heroic", "游戏库", "游戏",
            {"playnite.desktopapp.exe", "itch.exe", "heroic.exe"},
            {"Josef Nemec", "itch corp", "Heroic Games Launcher"});
    s << mk("bin-game-cn", "完美对战平台 / 5E 对战平台", "国产对战平台", "游戏",
            {"perfectworldarena.exe", "5eclient.exe"},
            {"Perfect World", "完美世界", "Hangzhou Yuyang"});
    s << mk("bin-game-overlay", "MSI Afterburner RTSS / CapFrameX", "帧率工具", "游戏",
            {"rtss.exe", "capframex.exe"}, {"Unwinder", "CXWorld", "Micro-Star International"});
    s << mk("bin-tax", "个人所得税 / 电子税务局 / 金税盘", "税务", "金融",
            {"iitwins.exe", "etaxclient.exe", "kpserver.exe"},
            {"国家税务总局", "Aisino", "航天信息", "Baiwang", "百望"});
    s << mk("bin-ca-tools", "数字证书助手(CFCA/各地 CA)", "CA 证书", "金融",
            {"cfcamanager.exe", "certmanager.exe", "uKeyManager.exe"},
            {"CFCA", "China Financial Certification", "中国金融认证中心"});
    s << mk("bin-guanjiapo", "管家婆 / 速达", "进销存", "金融",
            {"gjp.exe", "superdata.exe"}, {"Rendong", "任我行", "Superdata", "速达"});
    return s;

}

QJsonObject appToJson(const TrustedApp& a)
{
    QJsonObject o;
    o[QStringLiteral("id")] = a.id;
    o[QStringLiteral("name")] = a.name;
    o[QStringLiteral("vendor")] = a.vendor;
    o[QStringLiteral("category")] = a.category;
    o[QStringLiteral("note")] = a.note;
    o[QStringLiteral("builtin")] = a.builtin;
    o[QStringLiteral("enabled")] = a.enabled;
    o[QStringLiteral("scope")] = a.scope == TrustedApp::Scope::Vendor
        ? QStringLiteral("vendor")
        : QStringLiteral("exe");
    QJsonArray ex;
    for (const QString& e : a.exes)
        ex.append(e);
    o[QStringLiteral("exes")] = ex;
    QJsonArray pubs;
    for (const QString& p : a.publishers)
        pubs.append(p);
    o[QStringLiteral("publishers")] = pubs;
    return o;
}

TrustedApp appFromJson(const QJsonObject& o)
{
    TrustedApp a;
    a.id = o[QStringLiteral("id")].toString();
    a.name = o[QStringLiteral("name")].toString();
    a.vendor = o[QStringLiteral("vendor")].toString();
    a.category = o[QStringLiteral("category")].toString();
    a.note = o[QStringLiteral("note")].toString();
    a.builtin = o[QStringLiteral("builtin")].toBool();
    a.enabled = o[QStringLiteral("enabled")].toBool(true);
    a.scope = o[QStringLiteral("scope")].toString() == QLatin1String("vendor")
        ? TrustedApp::Scope::Vendor
        : TrustedApp::Scope::Exe;
    for (const QJsonValue& v : o[QStringLiteral("exes")].toArray())
        a.exes << lowerName(v.toString());
    for (const QJsonValue& v : o[QStringLiteral("publishers")].toArray())
        a.publishers << v.toString();
    if (!o.contains(QStringLiteral("scope")) && a.exes.isEmpty() && !a.publishers.isEmpty())
        a.scope = TrustedApp::Scope::Vendor;
    return a;
}

}

TrustedSoftwareCatalog& TrustedSoftwareCatalog::instance()
{
    static TrustedSoftwareCatalog s;
    return s;
}

TrustedSoftwareCatalog::TrustedSoftwareCatalog()
    : apps_(builtinApps())
{
    path_ = QStringLiteral("C:/ProgramData/Bulwark/trusted-software.json");
}

QString TrustedSoftwareCatalog::userPath(const QString& id)
{
    return QStringLiteral("user-") + id;
}

QString TrustedSoftwareCatalog::filePath() const { QMutexLocker lk(&mu_); return path_; }

bool TrustedSoftwareCatalog::load(const QString& path)
{
    QMutexLocker lk(&mu_);
    if (!path.isEmpty())
        path_ = path;
    QFile f(path_);
    if (!f.exists()) {
        return save();
    }
    if (!f.open(QIODevice::ReadOnly))
        return false;
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    f.close();
    if (!doc.isObject())
        return false;

    QHash<QString, TrustedApp> byId;
    for (const TrustedApp& a : builtinApps())
        byId.insert(a.id, a);

    const QJsonArray arr = doc.object()[QStringLiteral("apps")].toArray();
    for (const QJsonValue& v : arr) {
        const TrustedApp a = appFromJson(v.toObject());
        if (a.id.isEmpty())
            continue;
        if (byId.contains(a.id) && a.builtin) {
            byId[a.id].enabled = a.enabled;
            if (!a.note.isEmpty())
                byId[a.id].note = a.note;
        } else {
            TrustedApp u = a;
            u.builtin = false;
            byId.insert(u.id, u);
        }
    }
    apps_ = byId.values();
    std::sort(apps_.begin(), apps_.end(),
              [](const TrustedApp& x, const TrustedApp& y) {
                  if (x.category != y.category)
                      return x.category < y.category;
                  return x.name < y.name;
              });
    loadedMtime_ = QFileInfo(path_).lastModified();
    return true;
}

bool TrustedSoftwareCatalog::save(const QString& path) const
{
    QMutexLocker lk(&mu_);
    const QString p = path.isEmpty() ? path_ : path;
    QDir().mkpath(QFileInfo(p).absolutePath());
    QJsonArray arr;
    for (const TrustedApp& a : apps_)
        arr.append(appToJson(a));
    QJsonObject root;
    root[QStringLiteral("version")] = 1;
    root[QStringLiteral("apps")] = arr;
    QSaveFile f(p);
    if (!f.open(QIODevice::WriteOnly))
        return false;
    const QByteArray data = QJsonDocument(root).toJson(QJsonDocument::Indented);
    if (f.write(data) != data.size()) {
        f.cancelWriting();
        return false;
    }
    return f.commit();
}

QStringList TrustedSoftwareCatalog::categories() const
{
    QMutexLocker lk(&mu_);
    QStringList c;
    for (const TrustedApp& a : apps_)
        if (!c.contains(a.category))
            c << a.category;
    std::sort(c.begin(), c.end());
    return c;
}

std::optional<TrustedApp> TrustedSoftwareCatalog::match(const QString& imagePath,
                                                        const QString& publisher)
{
    QMutexLocker lk(&mu_);
    if (!path_.isEmpty()) {
        const QDateTime mt = QFileInfo(path_).lastModified();
        if (mt.isValid() && mt != loadedMtime_) {
            load();
            loadedMtime_ = QFileInfo(path_).lastModified();
        }
    }
    const QString file = QFileInfo(imagePath).fileName().toLower();
    const QString pub = publisher.trimmed();

    if (!file.isEmpty()) {
        for (const TrustedApp& a : apps_) {
            if (!a.enabled || a.scope != TrustedApp::Scope::Exe)
                continue;
            if (!a.exes.contains(file))
                continue;
            if (!a.publishers.isEmpty()) {
                bool pubOk = false;
                for (const QString& p : a.publishers) {
                    if (nameMatches(pub, p)) {
                        pubOk = true;
                        break;
                    }
                }
                if (!pubOk)
                    continue;
            }
            return a;
        }
    }
    if (!pub.isEmpty()) {
        for (const TrustedApp& a : apps_) {
            if (!a.enabled || a.scope != TrustedApp::Scope::Vendor)
                continue;
            for (const QString& p : a.publishers) {
                if (nameMatches(pub, p))
                    return a;
            }
        }
    }
    return std::nullopt;
}

bool TrustedSoftwareCatalog::upsert(const TrustedApp& app, QString* error)
{
    TrustedApp a = app;
    for (QString& e : a.exes)
        e = lowerName(e);
    a.exes.removeAll(QString());
    for (QString& p : a.publishers)
        p = p.trimmed();
    a.publishers.removeAll(QString());
    if (a.name.trimmed().isEmpty()) {
        if (error)
            *error = QStringLiteral("名称必填");
        return false;
    }
    if (a.scope == TrustedApp::Scope::Vendor) {
        if (a.publishers.isEmpty()) {
            if (error)
                *error = QStringLiteral("厂商级条目必须填写签名主体关键词");
            return false;
        }
        a.exes.clear();
    } else if (a.exes.isEmpty()) {
        if (error)
            *error = QStringLiteral("至少填写一个映像名");
        return false;
    }
    if (a.id.isEmpty())
        a.id = QStringLiteral("user-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
    a.builtin = false;

    // 程序级条目只按文件名比对:不带签名主体时,任何签名健康的同名程序都能冒用这条信任。
    // 内置条目只改启用状态与备注,不受这条限制。
    const auto lacksPublisher = [&a, error]() {
        if (a.scope != TrustedApp::Scope::Exe || !a.publishers.isEmpty())
            return false;
        if (error)
            *error = QStringLiteral("程序级条目也必须填写签名主体关键词,否则任何签名的同名程序都会被信任");
        return true;
    };

    QMutexLocker lk(&mu_);
    for (int i = 0; i < apps_.size(); ++i) {
        if (apps_[i].id != a.id)
            continue;
        if (apps_[i].builtin) {
            apps_[i].enabled = a.enabled;
            if (!a.note.isEmpty())
                apps_[i].note = a.note;
            return save();
        }
        if (lacksPublisher())
            return false;
        apps_[i] = a;
        return save();
    }
    if (lacksPublisher())
        return false;
    apps_.append(a);
    return save();
}

bool TrustedSoftwareCatalog::remove(const QString& id, QString* error)
{
    QMutexLocker lk(&mu_);
    for (int i = 0; i < apps_.size(); ++i) {
        if (apps_[i].id != id)
            continue;
        if (apps_[i].builtin) {
            if (error)
                *error = QStringLiteral("内置条目不能删除,只能停用");
            return false;
        }
        apps_.removeAt(i);
        return save();
    }
    if (error)
        *error = QStringLiteral("条目不存在");
    return false;
}

bool TrustedSoftwareCatalog::setEnabled(const QString& id, bool on, QString* error)
{
    QMutexLocker lk(&mu_);
    for (TrustedApp& a : apps_) {
        if (a.id != id)
            continue;
        a.enabled = on;
        return save();
    }
    if (error)
        *error = QStringLiteral("条目不存在");
    return false;
}

void TrustedSoftwareCatalog::resetToBuiltin()
{
    QMutexLocker lk(&mu_);
    QList<TrustedApp> user;
    for (const TrustedApp& a : apps_)
        if (!a.builtin)
            user.append(a);
    apps_ = builtinApps();
    apps_.append(user);
    save();
}

}
