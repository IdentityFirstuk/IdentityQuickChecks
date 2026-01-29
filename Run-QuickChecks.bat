@echo off
REM ============================================================================
REM IdentityFirst QuickChecks - Run Menu
REM ============================================================================
REM Simple menu for non-technical users
REM Just double-click this file!
REM ============================================================================

setlocal

echo.
echo ============================================================
echo   IdentityFirst QuickChecks
echo ============================================================
echo.
echo   1. Run All Checks
echo   2. Open Interactive Console
echo   3. Create Signing Certificate
echo   4. Sign All Scripts
echo   5. Run Tests
echo   6. Open Documentation
echo   7. Exit
echo.
echo ============================================================

set /p choice="Enter your choice (1-7): "

if "%choice%"=="1" goto RunAll
if "%choice%"=="2" goto Console
if "%choice%"=="3" goto CreateCert
if "%choice%"=="4" goto SignScripts
if "%choice%"=="5" goto RunTests
if "%choice%"=="6" goto OpenDocs
if "%choice%"=="7" goto Exit

echo Invalid choice!
pause
goto :eof

:RunAll
echo Running all identity checks...
powershell -ExecutionPolicy Bypass -File "%~dp0Start-QuickChecks.ps1" -Run
goto :Finish

:Console
echo Starting interactive console...
powershell -ExecutionPolicy Bypass -File "%~dp0Start-QuickChecks.ps1" -Console
goto :Finish

:CreateCert
echo Creating self-signed code signing certificate...
powershell -ExecutionPolicy Bypass -File "%~dp0Create-SelfSignedCert.ps1"
goto :Finish

:SignScripts
echo Signing all scripts...
powershell -ExecutionPolicy Bypass -File "%~dp0Sign-QuickChecks.ps1"
goto :Finish

:RunTests
echo Running test suite...
powershell -ExecutionPolicy Bypass -File "%~dp0Test-QuickChecks.ps1" -All
goto :Finish

:OpenDocs
echo Opening documentation...
if exist "%~dp0README.md" (
    start "" "%~dp0README.md"
) else if exist "%~dp0docs\README.md" (
    start "" "%~dp0docs\README.md"
) else (
    echo README not found!
)
goto :Finish

:Finish
echo.
echo Done!
pause

:Exit
endlocal
exit /b 0
