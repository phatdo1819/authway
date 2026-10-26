@echo off
rem Draws the icons of assets\ and the pictures of the MSI package again, with the C# compiler of Windows: only
rem needed to change them
setlocal
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%~dp0..\target" mkdir "%~dp0..\target"
"%CSC%" -nologo -optimize+ -warnaserror+ -r:System.Drawing.dll -out:"%~dp0..\target\make-icons.exe" "%~dp0make-icons.cs" || exit /b 1
"%~dp0..\target\make-icons.exe" "%~dp0..\assets" || exit /b 1
echo icons and pictures written to assets\
