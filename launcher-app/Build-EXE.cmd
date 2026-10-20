@echo off
setlocal
if not exist "%~dp0NexoraLauncher.csproj" (
  echo Project files were not found next to this script.
  echo Extract the entire NEXORA-Launcher-project.zip first, then run this script from the extracted folder.
  pause
  exit /b 1
)
where dotnet >nul 2>nul
if errorlevel 1 (
  echo .NET 8 SDK was not found. Install Visual Studio 2022 with .NET desktop development, or install the .NET 8 SDK.
  pause
  exit /b 1
)
dotnet publish "%~dp0NexoraLauncher.csproj" -c Release -r win-x64 --self-contained true
if errorlevel 1 (
  echo Build failed. Review the error above.
  pause
  exit /b 1
)
echo.
echo The standalone EXE was published to:
echo %~dp0bin\Release\net8.0-windows\win-x64\publish\
pause
