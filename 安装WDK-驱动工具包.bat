@echo off
chcp 65001 >nul
echo ============================================
echo  安装 Windows Driver Kit (WDK) - 编译内核驱动用
echo ============================================
echo.
echo 本脚本需要管理员权限。若弹出 UAC，请点「是」。
echo 安装包已预下载，无需再等微软 CDN。
echo.

set "WDK_SETUP=%LOCALAPPDATA%\Temp\WinGet\Microsoft.WindowsWDK.10.0.26100.10.1.26100.6584\wdksetup.exe"
if not exist "%WDK_SETUP%" (
    set "WDK_SETUP=%USERPROFILE%\Downloads\wdksetup.exe"
)
if not exist "%WDK_SETUP%" (
    echo [错误] 未找到 wdksetup.exe
    echo 请先下载: https://go.microsoft.com/fwlink/?linkid=2249371
    pause
    exit /b 1
)

echo 使用安装器: %WDK_SETUP%
echo 开始安装（静默模式，约需 5-15 分钟）...
echo.

"%WDK_SETUP%" /quiet /norestart
set ERR=%ERRORLEVEL%

echo.
if exist "C:\Program Files (x86)\Windows Kits\10\Include\km\ntddk.h" (
    echo [成功] WDK 已安装！内核头文件已就位。
    echo.
    echo 现在可以编译驱动:
    echo   powershell -ExecutionPolicy Bypass -File scripts\build-driver.ps1 -Configuration Debug
) else if exist "C:\Program Files (x86)\Windows Kits\10\Include\km" (
    echo [成功] WDK 内核组件已安装。
) else (
    echo [提示] 安装器退出码: %ERR%
    echo 若仍缺少 Include\km，请检查是否取消了 UAC，或查看日志:
    echo   %LOCALAPPDATA%\Temp\wdk\
)

echo.
pause
