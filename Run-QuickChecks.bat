@echo off
REM ============================================================================
REM IdentityFirst QuickChecks - Customer Menu
REM ============================================================================
REM Double-click to run! No commands needed.
REM ============================================================================

setlocal

echo.
echo ============================================================
echo   IdentityFirst QuickChecks
echo ============================================================
echo.
echo   1. Run Identity Checks
echo   2. Open Interactive Console
echo   3. Install Prerequisites
echo   4. Open Documentation
echo   5. Exit
echo.
echo ============================================================

set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" goto RunChecks
if "%choice%"=="2" goto Console
if "%choice%"=="3" goto Install
if "%choice%"=="4" goto Docs
if "%choice%"=="5" goto Exit

echo Invalid choice!
pause
goto :eof

:RunChecks
echo Running identity checks...
powershell -ExecutionPolicy Bypass -File "%~dp0Start-QuickChecks.ps1" -Run
goto :Finish

:Console
echo Starting interactive console...
powershell -ExecutionPolicy Bypass -File "%~dp0Start-QuickChecks.ps1" -Console
goto :Finish

:Install
echo Installing prerequisites...
powershell -ExecutionPolicy Bypass -File "%~dp0Install-Prerequisites.ps1"
goto :Finish

:Docs
echo Opening documentation...
if exist "%~dp0README.md" (
    start "" "%~dp0README.md"
) else if exist "%~dp0docs\README.md" (
    start "" "%~dp0docs\README.md"
) else (
    echo README not found! Check GitHub for documentation.
)
goto :Finish

:Finish
echo.
echo Done!
pause

:Exit
endlocal
exit /b 0
