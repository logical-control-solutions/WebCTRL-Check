@echo off
setlocal

:: 1. Check for Administrator privileges; re-launch with UAC prompt if not elevated
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:: 2. Lock working directory to the folder containing this .bat file
cd /d "%~dp0"

set "PS_SCRIPT=%~dp0Invoke-WebCTRLCactusAudit.ps1"

if not exist "%PS_SCRIPT%" (
    echo [ERROR] Could not find "%PS_SCRIPT%"
    echo Make sure Invoke-WebCTRLCactusAudit.ps1 is in the same folder as this .bat file.
    pause
    exit /b 1
)

echo ======================================================================
echo Running WebCTRL / i-Vu Cactus Exploit Audit as Administrator...
echo ======================================================================
echo.

:: 3. Run the PowerShell script with ExecutionPolicy Bypass
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%"

echo.
echo ======================================================================
echo Audit finished. Press any key to close this window...
echo ======================================================================
pause >nul
endlocal
