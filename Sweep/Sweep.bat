@echo off
rem Sweep launcher - runs from any working directory.
setlocal
cd /d "%~dp0"

set "PYEXE="
where py >nul 2>&1 && set "PYEXE=py -3"
if not defined PYEXE (
  where python >nul 2>&1 && set "PYEXE=python"
)
if not defined PYEXE (
  echo Python 3 is required but was not found on PATH.
  echo Install it from https://www.python.org/downloads/windows/
  pause
  exit /b 1
)

%PYEXE% -m sweep %*
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo [sweep exited with code %RC%]
  pause
)
exit /b %RC%
