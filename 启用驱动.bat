@echo off
chcp 65001 >nul
set "BLW_ARGS=%*"
set "BLW_RETRY="
if /i "%~1"=="--elevated" (
    set "BLW_RETRY=1"
    call set "BLW_ARGS=%%BLW_ARGS:*--elevated=%%"
)

set "BLW_ADMIN="
reg query "HKU\S-1-5-19" >nul 2>&1
if not errorlevel 1 set "BLW_ADMIN=1"

set "BLW_NEEDPS="
if not defined BLW_ADMIN if defined BLW_RETRY set "BLW_NEEDPS=1"
if defined BLW_NEEDPS for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "[int]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"`) do if "%%A"=="1" set "BLW_ADMIN=1"

set "BLW_SELF=%~f0"
set "BLW_SELF=%BLW_SELF:'=''%"

if not defined BLW_ADMIN if defined BLW_RETRY (
    echo.
    echo Already elevated once, but administrator rights still cannot be confirmed.
    echo Stopping here instead of opening more windows.
    echo Right-click this file and choose "Run as administrator".
    echo If that fails too, another security product is blocking reg.exe / powershell.exe.
    echo.
    pause
    exit /b 1
)

if not defined BLW_ADMIN (
    echo Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%BLW_SELF%' -ArgumentList '--elevated %BLW_ARGS%' -Verb RunAs"
    if errorlevel 1 (
        echo.
        echo Elevation was cancelled or blocked. Nothing was changed.
        echo Right-click this file and choose "Run as administrator".
        echo.
        pause
    )
    exit /b
)

cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0启用驱动.ps1"
pause
