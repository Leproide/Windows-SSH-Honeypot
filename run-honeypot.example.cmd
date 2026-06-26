@echo off
REM ---------------------------------------------------------------------------
REM run-honeypot.example.cmd - example launcher: set parameters, then start.
REM
REM Copy this file to run-honeypot.cmd, fill in your values, and run it
REM (run-honeypot.cmd is git-ignored so your API key is never committed).
REM Run from an Administrator console so logs stay in this window and the
REM firewall changes do not require a UAC relaunch into a new window.
REM
REM Copyright (C) 2026  https://github.com/Leproide
REM
REM This program is free software: you can redistribute it and/or modify
REM it under the terms of the GNU General Public License as published by
REM the Free Software Foundation, either version 3 of the License, or
REM (at your option) any later version. See the LICENSE file for details.
REM
REM Author: https://github.com/Leproide
REM ---------------------------------------------------------------------------

REM --- Listener / behavior -----------------------------------------------------
set "HP_PORTS=22"
set "HP_BANNER=SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
set "HP_MAX=2000"
set "HP_FLUSH=5"
set "HP_BLOCK_OUT=1"
set "HP_AGGREGATE=1"
set "HP_REFRESH_ON_HIT=0"
set "HP_SYNC_ON_START=1"

REM --- Local admin endpoint (loopback only) ------------------------------------
set "HP_ADMIN=1"
set "HP_ADMIN_PORT=65432"

REM --- IPThreat.net reporting (leave key empty to disable) ---------------------
set "HP_IPTHREAT_KEY="
set "HP_IPTHREAT_FLAGS=BruteForce,PortScan"
set "HP_IPTHREAT_SYSTEM=SSH"

REM --- Telegram reporting (leave empty to disable) -----------------------------
set "HP_TG_TOKEN="
set "HP_TG_CHAT="

python "%~dp0honeypot.py"
