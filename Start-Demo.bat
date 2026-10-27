@echo off
rem Double-click to replay every lab scenario through the five detection rules on the Kusto emulator.
rem Needs Docker Desktop; the same replay as "docker compose run --rm replay" in the README.
title Identity Takeover Detection - scenario replay
cd /d "%~dp0"

where docker >nul 2>&1 || (
  echo Docker Desktop isn't installed. Opening the download page; install it, then run this again.
  start "" https://www.docker.com/products/docker-desktop/
  goto :end
)

docker info >nul 2>&1 && goto :run
echo Waiting for Docker Desktop to start...
if exist "%ProgramFiles%\Docker\Docker\Docker Desktop.exe" start "" "%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
for /l %%i in (1,1,60) do (
  timeout /t 5 /nobreak >nul
  docker info >nul 2>&1 && goto :run
)
echo Docker Desktop didn't start within 5 minutes. Start it yourself, then run this again.
goto :end

:run
echo The first run downloads the emulator (about 3.3 GB), which can take a while.
rem remove the last report so a failed run can't open stale results
del /q "replay-report\index.html" 2>nul
docker compose run --rm replay
if exist "replay-report\index.html" start "" "replay-report\index.html"
rem stop the emulator so it isn't left running in the background
docker compose down

:end
pause
