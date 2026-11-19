@echo off
rem ==== Build LolBypass.exe with the .NET Framework csc.exe compiler ====
setlocal
set "CSC=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
    echo [ERROR] csc.exe not found: %CSC%
    exit /b 1
)
cd /d "%~dp0"
echo Compiler: %CSC%
"%CSC%" /nologo /target:exe /out:LolBypass.exe /codepage:65001 /r:System.dll LolBypass.cs
if errorlevel 1 (
    echo [ERROR] Build failed.
    exit /b 1
)
echo [OK] Built: %~dp0LolBypass.exe
endlocal
exit /b 0
