<#
.SYNOPSIS
    Live, color-coded tail of the honeypot log (tail -f equivalent for Windows).

.DESCRIPTION
    Follows honeypot.log and colors each line by type: errors red, bans/reports
    yellow, hits cyan, whitelisted gray, everything else green.

.PARAMETER Path
    Path to the log file. Defaults to honeypot.log next to this script.

.PARAMETER Tail
    Number of existing lines to show before following. Default 20.

.EXAMPLE
    .\Watch-Honeypot.ps1
    .\Watch-Honeypot.ps1 -Path "C:\honeypot\honeypot.log" -Tail 50

.NOTES
    Copyright (C) 2026  https://github.com/Leproide

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version. See <https://www.gnu.org/licenses/>.

    Author: https://github.com/Leproide
#>

[CmdletBinding()]
param(
    [string]$Path,
    [int]$Tail = 20
)

# Resolve a default log path robustly: $PSScriptRoot can be empty depending on
# how the script is launched, which would make Join-Path throw. Fall back to the
# script's own directory, then to the current directory.
if ([string]::IsNullOrWhiteSpace($Path)) {
    $base = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($base)) {
        $base = Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    if ([string]::IsNullOrWhiteSpace($base)) { $base = (Get-Location).Path }
    $Path = Join-Path $base 'honeypot.log'
}

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Host "Log file not found: $Path" -ForegroundColor Red
    Write-Host "Pass the right path, e.g.: .\Watch-Honeypot.ps1 -Path C:\honeypot\honeypot.log"
    exit 1
}

# Pick a color for a log line based on its content (most specific first).
# NOTE: matching is case-insensitive, so bare 'HIT' would also match
# "w-HIT-elisted". HIT is anchored with \b and Whitelisted is checked first.
function Get-LineColor {
    param([string]$Line)
    switch -Regex ($Line) {
        '\[ERROR\]'        { 'Red';      break }   # failures (incl. rejected reports)
        '\[WARNING\]'      { 'Magenta';  break }
        'Whitelisted'      { 'Gray';     break }   # ignored (whitelist)
        '\bHIT\b'          { 'Cyan';     break }   # incoming probe
        'reported|Flush'   { 'DarkYellow';   break }   # firewall flush / IPThreat submit
        default            { 'White' }             # normal INFO
    }
}

Write-Host "Following $Path  (Ctrl+C to stop)" -ForegroundColor White

# The honeypot writes the log as UTF-8; make the console and Get-Content match
# so characters like the em dash render correctly instead of mojibake.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
Get-Content -LiteralPath $Path -Wait -Tail $Tail -Encoding UTF8 | ForEach-Object {
    Write-Host $_ -ForegroundColor (Get-LineColor $_)
}
