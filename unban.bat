@echo off
REM ---------------------------------------------------------------------------
REM unban.bat - prompt for an IP/CIDR and unban it via the honeypot admin API.
REM
REM Copyright (C) 2026  https://github.com/Leproide
REM
REM This program is free software: you can redistribute it and/or modify
REM it under the terms of the GNU General Public License as published by
REM the Free Software Foundation, either version 3 of the License, or
REM (at your option) any later version.
REM
REM This program is distributed in the hope that it will be useful,
REM but WITHOUT ANY WARRANTY; without even the implied warranty of
REM MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
REM GNU General Public License for more details.
REM
REM You should have received a copy of the GNU General Public License
REM along with this program. If not, see <https://www.gnu.org/licenses/>.
REM
REM Author: https://github.com/Leproide
REM ---------------------------------------------------------------------------

setlocal EnableDelayedExpansion

REM Honeypot admin endpoint (loopback). Override here if you changed HP_ADMIN_PORT.
set "HOST=127.0.0.1"
set "PORT=65432"

REM Ensure curl is available (built in on Windows 10/11 and Server 2019+).
where curl >nul 2>&1
if errorlevel 1 (
    echo [ERROR] curl not found in PATH.
    pause
    exit /b 1
)

:loop
echo.
set "IP="
set /p "IP=Enter IP or CIDR to unban (blank to quit): "

REM Strip surrounding double quotes if the user pasted them.
set "IP=%IP:"=%"

REM Empty input -> exit.
if "%IP%"=="" goto :done

echo Unbanning %IP% ...
curl -s "http://%HOST%:%PORT%/unban?ip=%IP%"
if errorlevel 1 (
    echo.
    echo [ERROR] Request failed. Is honeypot.py running with the admin endpoint enabled?
)
echo.
goto :loop

:done
endlocal
exit /b 0
