; 磐垒主动防御 (Bulwark) 安装包 — NSIS 脚本
;
; 安装选项:
;   [x] 进入测试模式    — bcdedit /set testsigning on
;   [x] 自动个人签名    — 创建本机个人证书并签名 Bulwark.sys
;
; 卸载行为:
;   停止/删除内核驱动、删除 System32\drivers\Bulwark.sys、
;   退出测试模式(bcdedit /set testsigning off)、移除个人签名证书、
;   注销用户态服务与 AMSI 提供程序、删除安装目录。
;
; 构建方式: makensis BulwarkSetup.nsi  (先运行 stage-payload.ps1)

Unicode true
ManifestDPIAware true
ShowInstDetails show
ShowUninstDetails show

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "WinMessages.nsh"

!define PRODUCT_NAME        "磐垒主动防御"
!define PRODUCT_NAME_EN     "Bulwark"
!define PRODUCT_VERSION     "1.0"
!define PRODUCT_PUBLISHER   "Bulwark Project"
!define PRODUCT_UNINST_KEY  "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Bulwark"
!define PRODUCT_REG_KEY     "SOFTWARE\Bulwark"
!define CERT_SUBJECT        "CN=Bulwark Local Driver Signing"

!ifndef PAYLOAD_DIR
!define PAYLOAD_DIR "payload"
!endif
!ifndef OUTPUT_FILE
!define OUTPUT_FILE "Bulwark-Setup-1.0.exe"
!endif

; 32 位安装器必须经 Sysnative 才能拿到真正的 64 位系统工具
!define SYSNATIVE "$WINDIR\Sysnative"
!define PS64      "$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe"

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "${OUTPUT_FILE}"
InstallDir "$PROGRAMFILES\Bulwark"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
BrandingText "${PRODUCT_NAME} ${PRODUCT_VERSION}"

; UI 定义
!define MUI_ABORTWARNING
!define MUI_ICON   "${PAYLOAD_DIR}\app.ico"
!define MUI_UNICON "${PAYLOAD_DIR}\app.ico"
; 视觉:保留品牌位图(侧栏 + 页眉),但不覆盖任何配色,向导沿用 Windows/MUI 默认外观。
; 组框标签、输入框、浏览按钮和底部按钮栏由 uxtheme 绘制,SetCtlColors 管不到,染成深色主题只会半深半浅。
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "brand\header.bmp"
!define MUI_HEADERIMAGE_BITMAP_NOSTRETCH
!define MUI_WELCOMEFINISHPAGE_BITMAP "brand\wizard-side.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP_NOSTRETCH
!define MUI_WELCOMEPAGE_TITLE "安装 ${PRODUCT_NAME} ${PRODUCT_VERSION}"
!define MUI_WELCOMEPAGE_TEXT  "磐垒主动防御是一款 Windows 主机行为防护软件(内核驱动 + 后台服务 + 桌面界面)。$\r$\n$\r$\n本安装包已集成全部功能,无需额外下载:内核驱动 Bulwark.sys、后台服务、桌面界面与 AMSI 提供程序。$\r$\n$\r$\n本包内核驱动已添加签名；安装时保留该签名。驱动能否加载由目标系统校验结果决定。$\r$\n$\r$\n警告:内核驱动回调出错会导致蓝屏,首次请在带快照的测试环境中验证。"

; 安装页面
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; 卸载页面
!insertmacro MUI_UNPAGE_CONFIRM
UninstPage custom un.UnOptionsCreate un.UnOptionsLeave
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "SimpChinese"

; Windows file properties use a numeric version and the requested display version.
VIProductVersion "1.0.0.0"
VIFileVersion "1.0.0.0"
VIAddVersionKey /LANG=${LANG_SIMPCHINESE} "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey /LANG=${LANG_SIMPCHINESE} "ProductVersion" "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=${LANG_SIMPCHINESE} "FileVersion" "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=${LANG_SIMPCHINESE} "FileDescription" "${PRODUCT_NAME} 安装程序"
VIAddVersionKey /LANG=${LANG_SIMPCHINESE} "LegalCopyright" "Bulwark Project"


; 变量
Var Dialog
Var LabelInfo
Var CheckTestMode
Var CheckSelfSign
Var TestModeSel
Var SelfSignSel
Var UnCheckDriver
Var UnCheckTestMode
Var UnDriverSel
Var UnTestModeSel
Var TestSigningOn        ; 安装开始前系统是否已处于测试签名模式("1"=是)

; 测试模式检测
; bcdedit 输出是本地化的(中文系统显示「是」),nsExec 捕获的又是 OEM 代码页字节,
; 所以判断交给 PowerShell,只用退出码回传(10=已开启)。
; 用 -File 调独立脚本:正则里的引号穿过 nsExec 的命令行会被提前吃掉。
; 脚本提前解到 $PLUGINSDIR:本检测在选项页之前跑,那时安装载荷还没解压。
; 判不出时一律按「未开启」处理:再设一次 bcdedit 幂等无害,反方向误判会让驱动装完却加载不起来。
Function DetectTestSigning
    StrCpy $TestSigningOn "0"
    InitPluginsDir
    File /oname=$PLUGINSDIR\detect-testsigning.ps1 "scripts\detect-testsigning.ps1"
    nsExec::ExecToStack '"${PS64}" -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\detect-testsigning.ps1"'
    Pop $0
    Pop $1
    ${If} $0 == 10
        StrCpy $TestSigningOn "1"
    ${EndIf}
FunctionEnd

; 选项页
Function OptionsPageCreate
    !insertmacro MUI_HEADER_TEXT "安装选项" "选择驱动加载所需的系统配置"

    nsDialogs::Create 1018
    Pop $Dialog
    ${If} $Dialog == error
        Abort
    ${EndIf}

    ${If} $TestSigningOn == "1"
        ${NSD_CreateLabel} 0 0 100% 54u "内核驱动 Bulwark.sys 需要下列配置才能加载。$\r$\n$\r$\n本机【已处于测试签名模式】,所以无需再次开启,安装完成后也不需要重启 —— 下面第一项已置灰。$\r$\n$\r$\n前提条件:Secure Boot 与内存完整性 (HVCI) 必须处于关闭状态。"
    ${Else}
        ${NSD_CreateLabel} 0 0 100% 54u "内核驱动 Bulwark.sys 需要下列配置才能加载。两项都勾选即可获得完整驱动功能;不勾选则只安装用户态组件(事件源会降级为用户态观测)。$\r$\n$\r$\n前提条件:Secure Boot 与内存完整性 (HVCI) 必须处于关闭状态。开启测试模式后需要重启一次电脑才会生效。"
    ${EndIf}
    Pop $LabelInfo

    ${If} $TestSigningOn == "1"
        ; 已处于测试模式:保持未勾选并置灰。再跑一次 bcdedit 不会改变任何状态,
        ; 却会让安装结束时多问一次「要不要重启」,而那次重启毫无作用。
        ${NSD_CreateCheckbox} 0 62u 100% 12u "进入测试模式 (本机已开启,无需改动)"
        Pop $CheckTestMode
        EnableWindow $CheckTestMode 0
    ${Else}
        ${NSD_CreateCheckbox} 0 62u 100% 12u "进入测试模式 (bcdedit /set testsigning on)"
        Pop $CheckTestMode
        ${NSD_SetState} $CheckTestMode ${BST_CHECKED}
    ${EndIf}

    ${NSD_CreateCheckbox} 0 82u 100% 12u "自动个人签名 (创建本机个人证书并签名驱动)"
    Pop $CheckSelfSign
    ${NSD_SetState} $CheckSelfSign ${BST_CHECKED}

    nsDialogs::Show
FunctionEnd

Function OptionsPageLeave
    ${NSD_GetState} $CheckTestMode $TestModeSel
    ${NSD_GetState} $CheckSelfSign  $SelfSignSel
FunctionEnd

; 卸载选项页
Function un.UnOptionsCreate
    !insertmacro MUI_HEADER_TEXT "卸载选项" "选择要清理的系统级配置"

    nsDialogs::Create 1018
    Pop $Dialog
    ${If} $Dialog == error
        Abort
    ${EndIf}

    ${NSD_CreateLabel} 0 0 100% 42u "卸载会移除程序文件、后台服务、AMSI 注册与快捷方式。以下两项涉及系统级配置,默认清理,可按需取消勾选。$\r$\n$\r$\n测试模式和签名证书只会在有受保护的本产品所有权记录时恢复,不会删除或关闭原本由管理员配置的状态。"
    Pop $LabelInfo

    ${NSD_CreateCheckbox} 0 56u 100% 12u "卸载内核驱动(停止并删除 Bulwark.sys、驱动服务与个人签名证书)"
    Pop $UnCheckDriver
    ${NSD_SetState} $UnCheckDriver ${BST_CHECKED}

    ${NSD_CreateCheckbox} 0 76u 100% 12u "恢复测试模式原始状态(仅当本产品安装时开启过才关闭)"
    Pop $UnCheckTestMode
    ${NSD_SetState} $UnCheckTestMode ${BST_CHECKED}

    nsDialogs::Show
FunctionEnd

Function un.UnOptionsLeave
    ${NSD_GetState} $UnCheckDriver $UnDriverSel
    ${NSD_GetState} $UnCheckTestMode $UnTestModeSel
FunctionEnd

; 初始化
Function .onInit
    ${IfNot} ${RunningX64}
        MessageBox MB_ICONSTOP "本软件仅支持 64 位 Windows。"
        Abort
    ${EndIf}

    ; 解析真实的 64 位 Program Files(32 位进程默认看到的是 Program Files (x86))
    SetRegView 64
    ReadRegStr $R0 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion" "ProgramFilesDir"
    SetRegView 32
    ${If} $R0 == ""
        StrCpy $INSTDIR "$PROGRAMFILES\Bulwark"
    ${Else}
        StrCpy $INSTDIR "$R0\Bulwark"
    ${EndIf}

    ; 先探明测试签名模式的现状,选项页与完成提示都按它分支
    StrCpy $TestSigningOn "0"
    StrCpy $TestModeSel ${BST_UNCHECKED}
    StrCpy $SelfSignSel ${BST_UNCHECKED}
FunctionEnd

; 安装
Section "主程序与驱动" SEC_MAIN
    SectionIn RO

    ; 先建立受保护的数据根，阻止普通用户预创建基线、安装记录和隔离文件
    ExpandEnvStrings $R9 "%ProgramData%"
    System::Call 'kernel32::GetFileAttributesW(w "$R9\Bulwark") i.r8'
    ${If} $R8 != -1
        IntOp $R7 $R8 & 0x400
        ${If} $R7 != 0
            MessageBox MB_ICONSTOP "$R9\Bulwark 是重解析点/目录联接。安装已中止，避免 SYSTEM 服务跟随到其它位置。"
            Abort
        ${EndIf}
    ${EndIf}
    DetailPrint "收紧 $R9\Bulwark 数据目录 ACL ..."
    CreateDirectory "$R9\Bulwark"
    nsExec::ExecToLog '"${SYSNATIVE}\icacls.exe" "$R9\Bulwark" /setowner "*S-1-5-32-544" /T /C'
    Pop $0
    ${If} $0 != 0
        MessageBox MB_ICONSTOP "无法接管 $R9\Bulwark 数据目录(代码 $0)。$\r$\n安装已停止，避免使用普通用户预创建的状态文件。"
        Abort
    ${EndIf}
    nsExec::ExecToLog '"${SYSNATIVE}\icacls.exe" "$R9\Bulwark" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /T /C'
    Pop $0
    ${If} $0 != 0
        MessageBox MB_ICONSTOP "无法保护 $R9\Bulwark 数据目录(代码 $0)。$\r$\n安装已停止，避免普通用户篡改 SYSTEM 服务状态。"
        Abort
    ${EndIf}

    SetOutPath $INSTDIR
    SetOverwrite on

    ; 解除自身防护(产品自带入口):覆盖已有安装前先卸载内核驱动、停止服务,
    ; 否则自保护会拦截文件覆盖(--prepare-replace 由产品自身进程执行,不受自保护判定)。
    ${If} ${FileExists} "$INSTDIR\bulwark_service.exe"
        inst_prepare:
        ; 带界面运行(用户亲手点了「安装」)才请已安装版本的服务退出防护;静默安装(/S)不请求,防护开着就照旧被拒绝。
        ; 服务只答应带有效发布签名的安装包;自己编译、没有签名的安装包会被拒绝,落到下面的人工指引。
        ${IfNot} ${Silent}
            DetailPrint "请已安装版本的后台服务退出防护 ..."
            Push "BULWARK-INSTALL 1"
            Call RequestStandby
            Pop $0
            ${If} $0 == "OK"
                DetailPrint "  后台服务已退出防护。"
            ${ElseIf} $0 == "NOPIPE"
                DetailPrint "  后台服务没有在运行,或是不带这项功能的旧版本。"
            ${Else}
                DetailPrint "  后台服务没有答应($0)。"
            ${EndIf}
        ${EndIf}
        DetailPrint "解除自身防护(--prepare-replace) ..."
        ; 服务的输出是 UTF-8,原样显示在这里是乱码,所以只取返回码。
        nsExec::ExecToStack '"$INSTDIR\bulwark_service.exe" --prepare-replace'
        Pop $0
        Pop $R4
        DetailPrint "  --prepare-replace 返回:$0"
        ${If} $0 != 0
            MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "已安装的旧版本没能安全停止(代码 $0),安装先停在这里,还没有覆盖任何文件。$\r$\n$\r$\n如果旧版本的实时防护还开着:请打开${PRODUCT_NAME}的主界面,关闭「实时防护」,再点「重试」。$\r$\n点「取消」放弃本次安装。" IDRETRY inst_prepare
            Abort
        ${EndIf}
    ${EndIf}

    ; 让被占用的文件可被覆盖(覆盖安装的必要前置)
    ; --prepare-replace 只卸驱动、停服务,管不到下面两类占用,File 会卡在 Abort/Retry/Ignore 对话框上:
    ;   1) 界面进程还开着:bulwark_ui.exe 与它加载的 Qt6*.dll 被锁住;
    ;   2) BulwarkAmsi.dll 已注册为 AMSI 提供程序:AMSI 消费者会把它映射进地址空间,反注册也不会立刻释放。
    ; 对 (2) 改名让位:Windows 允许对已加载映像改名,旧映像留给原进程用到退出,文件名腾给新版本。
    DetailPrint "停止界面进程 ..."
    nsExec::ExecToLog 'taskkill /F /IM bulwark_ui.exe'
    Pop $0

    ${If} ${FileExists} "$INSTDIR\BulwarkAmsi.dll"
        DetailPrint "让位旧 AMSI 提供程序 ..."
        nsExec::ExecToLog '"${SYSNATIVE}\regsvr32.exe" /u /s "$INSTDIR\BulwarkAmsi.dll"'
        Pop $0
        Delete "$INSTDIR\BulwarkAmsi.dll"
        ${If} ${FileExists} "$INSTDIR\BulwarkAmsi.dll"
            ; 仍被映射:清掉历史让位文件(没被占用时可删,含手工让位留下的带时间戳副本),
            ; 再改名腾出文件名
            Delete "$INSTDIR\BulwarkAmsi.dll.old*"
            ; 上一次让位留下的 .old 可能还被别的进程映射着(上面删不掉),名字被占时 Rename 会失败,
            ; 所以换一个空着的名字(.old2、.old3 …);这些副本不再被占用后,下次安装由上面的 Delete 清掉。
            StrCpy $R5 "$INSTDIR\BulwarkAmsi.dll.old"
            ${For} $R6 2 99
                ${IfNot} ${FileExists} "$R5"
                    ${ExitFor}
                ${EndIf}
                StrCpy $R5 "$INSTDIR\BulwarkAmsi.dll.old$R6"
            ${Next}
            Rename "$INSTDIR\BulwarkAmsi.dll" "$R5"
            Delete /REBOOTOK "$R5"
            ${If} ${FileExists} "$INSTDIR\BulwarkAmsi.dll"
                MessageBox MB_ICONSTOP "旧的 BulwarkAmsi.dll 正被其他进程占用且无法让位,安装已中止。$\r$\n请重启电脑后重新安装。"
                Abort
            ${EndIf}
            DetailPrint "  已改名让位(旧映像重启后清除)"
        ${Else}
            DetailPrint "  旧 AMSI DLL 已删除"
        ${EndIf}
    ${EndIf}

    ; 旧版本还装过下列文件,本版已不再打包(见 stage-payload.ps1)。只在覆盖本产品时清理,
    ; 且只删已知文件名、只移除空目录 —— $INSTDIR 可能被选在含其他内容的目录下。
    ${If} ${FileExists} "$INSTDIR\bulwark_service.exe"
        DetailPrint "清理旧版本遗留的多余文件 ..."
        Delete "$INSTDIR\opengl32sw.dll"
        Delete "$INSTDIR\D3Dcompiler_47.dll"
        Delete "$INSTDIR\Qt6Svg.dll"
        Delete "$INSTDIR\generic\qtuiotouchplugin.dll"
        Delete "$INSTDIR\iconengines\qsvgicon.dll"
        Delete "$INSTDIR\imageformats\qgif.dll"
        Delete "$INSTDIR\imageformats\qico.dll"
        Delete "$INSTDIR\imageformats\qjpeg.dll"
        Delete "$INSTDIR\imageformats\qsvg.dll"
        Delete "$INSTDIR\networkinformation\qnetworklistmanager.dll"
        Delete "$INSTDIR\styles\qmodernwindowsstyle.dll"
        Delete "$INSTDIR\tls\qcertonlybackend.dll"
        RMDir "$INSTDIR\generic"
        RMDir "$INSTDIR\iconengines"
        RMDir "$INSTDIR\imageformats"
        RMDir "$INSTDIR\networkinformation"
        RMDir "$INSTDIR\styles"
        ; YARA 功能已移除:清掉旧版本装过的辅助程序和内置规则包
        nsExec::ExecToLog 'taskkill /F /IM bulwark_yarac.exe'
        Pop $0
        Delete "$INSTDIR\bulwark_yarac.exe"
        Delete "$INSTDIR\rules\yara-forge-core.yarc"
        Delete "$INSTDIR\rules\yara-forge-core.json"
        RMDir "$INSTDIR\rules"
    ${EndIf}

    DetailPrint "安装程序文件到 $INSTDIR ..."
    ${If} ${FileExists} "$INSTDIR\appsettings.json"
        InitPluginsDir
        ClearErrors
        CopyFiles /SILENT "$INSTDIR\appsettings.json" "$PLUGINSDIR\appsettings-preserved.json"
        ${If} ${Errors}
            MessageBox MB_ICONSTOP "现有配置备份失败，安装已停止。"
            Abort
        ${EndIf}
    ${EndIf}
    File /r "${PAYLOAD_DIR}\*"
    ${If} ${FileExists} "$PLUGINSDIR\appsettings-preserved.json"
        ClearErrors
        CopyFiles /SILENT "$PLUGINSDIR\appsettings-preserved.json" "$INSTDIR\appsettings.json"
        ${If} ${Errors}
            MessageBox MB_ICONSTOP "现有配置恢复失败，安装已停止。"
            Abort
        ${EndIf}
    ${EndIf}

    ; 确保内核驱动已下线(服务注册的前置条件)
    ; 驱动自保护会拒绝删除 BulwarkService 的注册表键,残留键会让随后的 CreateService 失败(--install 返回 1、安装中止)。
    ; 本节开头的 --prepare-replace 以旧 bulwark_service.exe 存在为前提,上次安装中断导致文件缺失时会被跳过;
    ; 所以这里用已解压到位的新版 exe 跑产品自带的解除流程,再用 fltmc 兜底卸下 minifilter。
    DetailPrint "确保内核驱动已下线 ..."
    nsExec::ExecToLog '"$INSTDIR\bulwark_service.exe" --prepare-replace'
    Pop $0
    DetailPrint "  --prepare-replace 返回:$0"
    nsExec::ExecToLog '"${SYSNATIVE}\fltmc.exe" unload Bulwark'
    Pop $0
    DetailPrint "  fltmc unload 返回:$0"

    ; 卸载程序必须趁驱动下线时写:服务一连上驱动,安装目录就进入内核自保护(SelfGuard),只放行本产品自身进程写入,
    ; 安装程序此后再写 Uninstall.exe 会被拒绝,而 WriteUninstaller 失败不会自行中止安装。
    DetailPrint "写入卸载程序 ..."
    ClearErrors
    WriteUninstaller "$INSTDIR\Uninstall.exe"
    ${If} ${Errors}
    ${OrIfNot} ${FileExists} "$INSTDIR\Uninstall.exe"
        MessageBox MB_ICONSTOP "卸载程序写入失败($INSTDIR\Uninstall.exe)。安装已中止。$\r$\n$\r$\n最常见的原因是内核驱动仍在运行并保护着安装目录。$\r$\n请重启电脑后重新安装。"
        Abort
    ${EndIf}

    ; 清理残留服务注册并全新注册
    ; 服务的 IPC 准入按「服务二进制自身目录」判定(installDir = applicationDirPath),
    ; 旧路径残留注册会让旧二进制跑起来并拒绝新 UI(“连接方不在本产品安装目录内”);
    ; 残留键的 ImagePath 可能指向开发目录(cpp\dist),所以必须删键重建而非沿用。
    DetailPrint "清理旧服务注册 ..."
    nsExec::ExecToLog 'sc stop BulwarkService'
    Pop $0
    nsExec::ExecToLog 'sc delete BulwarkService'
    Pop $0
    nsExec::ExecToLog 'reg delete "HKLM\SYSTEM\CurrentControlSet\Services\BulwarkService" /f'
    Pop $0
    DetailPrint "全新注册服务(--install,指向 $INSTDIR) ..."
    nsExec::ExecToLog '"$INSTDIR\bulwark_service.exe" --install'
    Pop $0
    DetailPrint "  --install 返回:$0"
    ${If} $0 != 0
        MessageBox MB_ICONSTOP "后台服务注册失败(代码 $0)。安装已中止。$\r$\n$\r$\n最常见的原因是内核驱动仍在运行:它的自保护会拒绝删除残留的服务注册项,导致无法重建注册。$\r$\n$\r$\n请重启电脑后重新安装 —— 重启会让驱动一并下线。"
        Abort
    ${EndIf}

    ; 驱动安装脚本(部署 + 注册 + 测试模式 + 个人签名)
    ; 必须在 AMSI 注册之前执行:注册后任何 powershell.exe 都会加载 BulwarkAmsi.dll,
    ; 文件被占用就无法签名。
    StrCpy $R0 ""

    DetailPrint "执行驱动安装脚本(install-driver.ps1) ..."
    nsExec::ExecToLog '"${PS64}" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\scripts\install-driver.ps1" -SysSource "$INSTDIR\Bulwark.sys"$R0'
    Pop $0
    DetailPrint "  install-driver.ps1 返回:$0"
    ${If} $0 != 0
        MessageBox MB_ICONSTOP "驱动安装脚本失败(代码 $0)。安装已中止，避免留下部分注册状态。$\r$\n详情见安装日志。"
        Abort
    ${EndIf}

    ; 部署引导(--bootstrap):产品自带的完整部署入口
    ; 部署驱动文件(已有则不覆盖)、装载内核驱动、注册并启动后台服务。
    DetailPrint "执行部署引导 bulwark_service.exe --bootstrap ..."
    nsExec::ExecToLog '"$INSTDIR\bulwark_service.exe" --bootstrap'
    Pop $0
    DetailPrint "  --bootstrap 返回:$0"
    ${If} $0 != 0
        MessageBox MB_ICONSTOP "部署引导失败(代码 $0)。安装已中止。$\r$\n详情见 %ProgramData%\Bulwark\bootstrap-status.txt。"
        Abort
    ${EndIf}

    ; AMSI 提供程序(64 位 regsvr32)
    DetailPrint "注册 AMSI 提供程序 ..."
    nsExec::ExecToLog '"${SYSNATIVE}\regsvr32.exe" /s "$INSTDIR\BulwarkAmsi.dll"'
    Pop $0
    DetailPrint "  regsvr32 返回:$0"
    ${If} $0 != 0
        MessageBox MB_ICONSTOP "AMSI 提供程序注册失败(代码 $0)。安装已中止。"
        Abort
    ${EndIf}

    ; 快捷方式(所有用户桌面 + 开始菜单)
    DetailPrint "创建快捷方式 ..."
    SetShellVarContext all
    CreateShortCut "$DESKTOP\${PRODUCT_NAME}.lnk" "$INSTDIR\bulwark_ui.exe" "" "$INSTDIR\app.ico" 0
    CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}.lnk" "$INSTDIR\bulwark_ui.exe" "" "$INSTDIR\app.ico" 0
    CreateShortCut "$SMPROGRAMS\卸载 ${PRODUCT_NAME}.lnk" "$INSTDIR\Uninstall.exe" "" "$INSTDIR\Uninstall.exe" 0

    ; 卸载信息
    SetRegView 64
    WriteRegStr   HKLM "${PRODUCT_REG_KEY}" "InstallDir" "$INSTDIR"
    WriteRegStr   HKLM "${PRODUCT_UNINST_KEY}" "DisplayName"     "${PRODUCT_NAME}"
    WriteRegStr   HKLM "${PRODUCT_UNINST_KEY}" "DisplayVersion"  "${PRODUCT_VERSION}"
    WriteRegStr   HKLM "${PRODUCT_UNINST_KEY}" "Publisher"       "${PRODUCT_PUBLISHER}"
    WriteRegStr   HKLM "${PRODUCT_UNINST_KEY}" "InstallLocation" "$INSTDIR"
    WriteRegStr   HKLM "${PRODUCT_UNINST_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegStr   HKLM "${PRODUCT_UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
    WriteRegDWORD HKLM "${PRODUCT_UNINST_KEY}" "NoModify" 1
    WriteRegDWORD HKLM "${PRODUCT_UNINST_KEY}" "NoRepair" 1
    SetRegView 32

    MessageBox MB_ICONINFORMATION "安装完成。$\r$\n$\r$\n已保留内核驱动签名；实际驱动加载状态可在主界面查看。"
SectionEnd

; 卸载
; 安装、卸载全自动:请后台服务先退出防护,这样防护开着时也能一次装完、一次卸完。
; 服务只认「已提权、在交互会话里」并且映像是下面两种之一的请求方:
;   · 与安装目录内 Uninstall.exe 逐字节相同 —— 卸载程序,请求行 BULWARK-UNINSTALL 1;
;   · 带有效的发布签名(installer\scripts\sign-release.ps1)—— 安装包,请求行 BULWARK-INSTALL 1。
; 别的进程发同样的请求会被拒绝并记入审计。
; 用法:Push "<请求行>" / Call [un.]RequestStandby / Pop <结果>。
; 结果:"OK" 服务已退出防护;"NOPIPE" 服务没在运行或版本较旧;
; 其余(DENY / TIMEOUT / CLOSED / WRITE)表示没成,由调用方走人工指引。
!ifndef MAINT_PIPE
!define MAINT_PIPE "\\.\pipe\Bulwark.Maintenance"
!endif
!macro BLW_REQUEST_STANDBY UN
Function ${UN}RequestStandby
    Exch $5
    Push $1
    Push $2
    Push $3
    Push $4
    Push $6
    StrCpy $6 "NOPIPE"
    StrCpy $2 "${MAINT_PIPE}"
    System::Call 'kernel32::CreateFileW(w r2, i 0xC0000000, i 0, p 0, i 3, i 0, p 0) p .r1'
    ${If} $1 P<> -1
    ${AndIf} $1 P<> 0
        StrCpy $6 "WRITE"
        StrCpy $2 "$5$\n"
        StrLen $3 $2
        System::Call 'kernel32::WriteFile(p r1, m r2, i r3, *i .r3, p 0) i .r4'
        ${If} $4 <> 0
            StrCpy $6 "TIMEOUT"
            ; 服务要核对请求方、卸掉内核驱动再答复,平时一两秒;最多等 30 秒,不无限期挂住。
            ${For} $4 1 300
                System::Call 'kernel32::PeekNamedPipe(p r1, p 0, i 0, p 0, *i .r3, p 0) i .r2'
                ${If} $2 = 0
                    StrCpy $6 "CLOSED"
                    ${ExitFor}
                ${EndIf}
                ${If} $3 > 0
                    StrCpy $2 ""
                    System::Call 'kernel32::ReadFile(p r1, m .r2, i 16, *i .r3, p 0)'
                    StrCpy $6 $2 2
                    ${If} $6 != "OK"
                        StrCpy $6 "DENY"
                    ${EndIf}
                    ${ExitFor}
                ${EndIf}
                Sleep 100
            ${Next}
        ${EndIf}
        System::Call 'kernel32::CloseHandle(p r1)'
    ${EndIf}
    StrCpy $5 $6
    Pop $6
    Pop $4
    Pop $3
    Pop $2
    Pop $1
    Exch $5
FunctionEnd
!macroend
!insertmacro BLW_REQUEST_STANDBY ""
!insertmacro BLW_REQUEST_STANDBY "un."

Section "Uninstall"
    ; 解除自身防护(产品自带入口):卸载内核驱动 + 停止服务
    ; 必须最先做:此后删除文件/停进程/删服务不再被自保护拦截
    ; (--prepare-replace 由产品自身进程执行,不受自保护判定;之后判停的进程都没了)。
    uninst_prepare:
    ; 带界面运行(用户亲手点了「卸载」)才请服务退出防护;静默卸载(/S)不请求,防护开着就照旧被拒绝。
    ${IfNot} ${Silent}
        DetailPrint "请后台服务退出防护 ..."
        Push "BULWARK-UNINSTALL 1"
        Call un.RequestStandby
        Pop $0
        ${If} $0 == "OK"
            DetailPrint "  后台服务已退出防护。"
        ${ElseIf} $0 == "NOPIPE"
            DetailPrint "  后台服务没有在运行,或是不带这项功能的旧版本。"
        ${Else}
            DetailPrint "  后台服务没有答应($0)。"
        ${EndIf}
    ${EndIf}
    DetailPrint "解除自身防护(--prepare-replace) ..."
    ; 服务的输出是 UTF-8,原样显示在这里是乱码,所以只取返回码。
    nsExec::ExecToStack '"$INSTDIR\bulwark_service.exe" --prepare-replace'
    Pop $0
    Pop $R4
    DetailPrint "  --prepare-replace 返回:$0"
    ${If} $0 != 0
        MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "后台服务或内核驱动没能安全停止(代码 $0),卸载先停在这里,已安装的程序没有被改动。$\r$\n$\r$\n如果实时防护还开着:请打开${PRODUCT_NAME}的主界面,关闭「实时防护」,再点「重试」。$\r$\n点「取消」放弃本次卸载。" IDRETRY uninst_prepare
        Abort
    ${EndIf}

    ; 停止残留进程
    DetailPrint "停止 Bulwark 用户态组件 ..."
    nsExec::ExecToLog 'taskkill /F /IM bulwark_ui.exe'
    Pop $0
    nsExec::ExecToLog 'sc stop BulwarkService'
    Pop $0
    nsExec::ExecToLog 'taskkill /F /IM bulwark_service.exe'
    Pop $0
    nsExec::ExecToLog '"$INSTDIR\bulwark_service.exe" --uninstall'
    Pop $0
    DetailPrint "  --uninstall 返回:$0"
    ${If} $0 != 0
        MessageBox MB_ICONSTOP "后台服务注销失败(代码 $0)。卸载已中止，详情见日志。"
        Abort
    ${EndIf}
    nsExec::ExecToLog 'sc delete BulwarkService'
    Pop $0

    ; AMSI 反注册
    DetailPrint "反注册 AMSI 提供程序 ..."
    nsExec::ExecToLog '"${SYSNATIVE}\regsvr32.exe" /u /s "$INSTDIR\BulwarkAmsi.dll"'
    Pop $0
    ${If} $0 != 0
        MessageBox MB_ICONSTOP "AMSI 提供程序反注册失败(代码 $0)。卸载已中止。"
        Abort
    ${EndIf}

    ; 驱动卸载脚本:按用户勾选决定是否卸驱动 / 退出测试模式
    StrCpy $R1 "no"
    ${If} $UnDriverSel == ${BST_CHECKED}
        StrCpy $R1 "yes"
    ${EndIf}
    StrCpy $R2 "no"
    ${If} $UnTestModeSel == ${BST_CHECKED}
        StrCpy $R2 "yes"
    ${EndIf}

    DetailPrint "执行驱动卸载脚本(uninstall-driver.ps1 -RemoveDriver $R1 -DisableTestSigning $R2) ..."
    nsExec::ExecToLog '"${PS64}" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\scripts\uninstall-driver.ps1" -RemoveDriver $R1 -DisableTestSigning $R2'
    Pop $0
    DetailPrint "  uninstall-driver.ps1 返回:$0"
    ${If} $0 != 0
        MessageBox MB_ICONSTOP "驱动卸载未完成(代码 $0)。卸载已中止，程序文件仍保留以便重试。"
        Abort
    ${EndIf}

    ; 删除快捷方式
    DetailPrint "删除快捷方式 ..."
    SetShellVarContext all
    Delete "$DESKTOP\${PRODUCT_NAME}.lnk"
    Delete "$SMPROGRAMS\${PRODUCT_NAME}.lnk"
    Delete "$SMPROGRAMS\卸载 ${PRODUCT_NAME}.lnk"

    ; 删除文件
    ; AMSI DLL 可能仍被运行中的脚本宿主映射:先改名(已加载映像允许改名),
    ; 这样 RMDir 才能清掉安装目录。
    ClearErrors
    Rename /REBOOTOK "$INSTDIR\BulwarkAmsi.dll" "$INSTDIR\BulwarkAmsi.dll.locked"
    DetailPrint "删除安装目录 ..."
    RMDir /r /REBOOTOK "$INSTDIR"
    ${If} ${Errors}
        SetRebootFlag true
        DetailPrint "  部分已加载文件将在重启后删除。"
    ${EndIf}

    ; 删除注册表
    SetRegView 64
    DeleteRegKey HKLM "${PRODUCT_UNINST_KEY}"
    DeleteRegKey HKLM "${PRODUCT_REG_KEY}"
    SetRegView 32

    ; 清理了驱动或测试模式时才需要重启
    ${If} $UnDriverSel == ${BST_CHECKED}
    ${OrIf} $UnTestModeSel == ${BST_CHECKED}
        SetRebootFlag true
    ${EndIf}
SectionEnd
