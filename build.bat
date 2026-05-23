@echo off
REM ==========================================================================
REM NetMon build script (Windows)
REM
REM Produces TWO binaries from the same source:
REM   netmon.exe   - console mode (shows logs in a terminal, easy to debug)
REM   netmonw.exe  - windowsgui mode (silent, no console window ever; use for
REM                  Task Scheduler / startup / running in the background)
REM
REM Requirements:
REM   1. Go toolchain on PATH                              (https://go.dev)
REM   2. Npcap SDK extracted somewhere on disk             (https://npcap.com)
REM   3. A C compiler on PATH (MinGW / TDM-GCC / mingw-w64)
REM
REM Override defaults by setting these env vars BEFORE running build.bat:
REM   NPCAP_SDK   - path to Npcap SDK root (containing Include\ and Lib\)
REM   GCC_BIN     - directory containing gcc.exe
REM ==========================================================================

setlocal EnableDelayedExpansion

REM ---- Resolve toolchain locations ----------------------------------------
if not defined NPCAP_SDK set "NPCAP_SDK=%~dp0npcap-sdk"
if not defined GCC_BIN   set "GCC_BIN=%~dp0gcc-mingw\bin"

if not exist "%NPCAP_SDK%\Include\pcap.h" (
  echo [build] ERROR: Npcap SDK not found at "%NPCAP_SDK%".
  echo         Download from https://npcap.com and extract, or set
  echo         NPCAP_SDK to the SDK root before running this script.
  exit /b 1
)
if not exist "%GCC_BIN%\gcc.exe" (
  echo [build] ERROR: gcc.exe not found in "%GCC_BIN%".
  echo         Install MinGW / TDM-GCC, or set GCC_BIN to its bin directory.
  exit /b 1
)
where go >nul 2>&1
if errorlevel 1 (
  echo [build] ERROR: 'go' not on PATH. Install Go from https://go.dev/dl/
  exit /b 1
)

REM ---- CGO environment -----------------------------------------------------
set "CGO_ENABLED=1"
set "CGO_CFLAGS=-I%NPCAP_SDK%\Include"
set "CGO_LDFLAGS=-L%NPCAP_SDK%\Lib\x64"
set "PATH=%GCC_BIN%;%PATH%"

echo [build] CGO_CFLAGS = %CGO_CFLAGS%
echo [build] CGO_LDFLAGS = %CGO_LDFLAGS%
echo [build] gcc        = %GCC_BIN%\gcc.exe
echo.

REM ---- go mod tidy (idempotent) -------------------------------------------
echo [build] go mod tidy ...
go mod tidy
if errorlevel 1 (
  echo [build] go mod tidy FAILED.
  exit /b 1
)

REM ---- Compile Windows resource (UAC manifest -> .syso) -------------------
REM     The .syso is auto-linked by `go build`; we get UAC prompts on launch.
if not exist "%GCC_BIN%\windres.exe" goto :rc_missing
echo [build] windres netmon.rc -^> netmon_windows_amd64.syso
"%GCC_BIN%\windres.exe" -i netmon.rc -O coff -o netmon_windows_amd64.syso
if errorlevel 1 goto :rc_failed
goto :rc_done
:rc_missing
echo [build] windres.exe not found - building without UAC manifest.
echo [build]   users will need: Right-click - Run as Administrator
goto :rc_done
:rc_failed
echo [build] windres FAILED - building without UAC manifest.
if exist netmon_windows_amd64.syso del /q netmon_windows_amd64.syso
:rc_done

REM ---- Console binary ------------------------------------------------------
echo [build] Building netmon.exe   (console mode) ...
go build -trimpath -ldflags "-s -w" -o netmon.exe .
if errorlevel 1 (
  echo [build] netmon.exe build FAILED.
  exit /b 1
)

REM ---- Silent GUI binary ---------------------------------------------------
echo [build] Building netmonw.exe  (windowsgui mode, no console popup) ...
go build -trimpath -ldflags "-s -w -H windowsgui" -o netmonw.exe .
if errorlevel 1 (
  echo [build] netmonw.exe build FAILED.
  exit /b 1
)

REM ---- Summary -------------------------------------------------------------
echo.
echo [build] Done.
for %%f in (netmon.exe netmonw.exe) do (
  for %%s in ("%%f") do echo         %%~zs bytes  %%f
)
echo.
echo Run as Administrator:
echo   netmon.exe                       (foreground, console output)
echo   netmonw.exe -autostart -open     (silent, captures + opens browser)

endlocal
