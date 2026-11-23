& {
# ==============================================================================
# WebCTRL / i-Vu Cactus Exploit Audit Script (Read-Only - v6 Fleet Clean)
# Updates in v6:
#   - Added StartTime='2026-11-19 00:00:00' filter to Check 2A (Security 4688)
#   - Added StartTime='2026-11-19 00:00:00' filter to Check 2C (Defender 1116/1117)
#   - Excluded audit script & report filenames in Check 4B to prevent self-matches
#   - Preserves all v5 checks (ports 8995/8894/8968, Event 4104, Event 400, i80_*)
# ==============================================================================

$ErrorActionPreference = 'SilentlyContinue'
$timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$reportPath = "$env:USERPROFILE\Desktop\Cactus_Audit_$($env:COMPUTERNAME)_$timestamp.txt"

$script:HasAlert  = $false
$script:HasReview = $false

function Write-Section {
    param([string]$Title)
    $banner = "`n======================================================================`n[CHECK] $Title`n======================================================================"
    Write-Host $banner -ForegroundColor Cyan
    Add-Content -Path $reportPath -Value $banner
}

function Write-Log {
    param(
        [string]$Text,
        [ValidateSet('White','Green','Yellow','Red','Cyan','Gray')]
        [string]$Color = 'White'
    )
    if ($Color -eq 'Red')    { $script:HasAlert  = $true }
    if ($Color -eq 'Yellow') { $script:HasReview = $true }
    Write-Host $Text -ForegroundColor $Color
    Add-Content -Path $reportPath -Value $Text
}

Write-Log "Audit Started: $(Get-Date) | Host: $env:COMPUTERNAME" 'Green'

# ------------------------------------------------------------------------------
# 1. ACTIVE NETWORK CONNECTIONS & SUSPICIOUS DNS CACHE
# ------------------------------------------------------------------------------
Write-Section "1A. Active TCP Connections to Threat Actor IP (2.57.241.75) or Ports 8995/8894/8968"
$badConns = Get-NetTCPConnection | Where-Object {
    $_.RemoteAddress -eq '2.57.241.75' -or $_.RemotePort -in 8995,8894,8968
}
if ($badConns) {
    Write-Log "ALERT: Active connection to threat actor infrastructure detected!" 'Red'
    $table = ($badConns | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Format-Table -AutoSize | Out-String).Trim()
    Write-Log $table 'Red'
} else {
    Write-Log "PASS: No active TCP connections to 2.57.241.75 or ports 8995/8894/8968." 'Green'
}

Write-Section "1B. Active External TCP Connections Owned by Java / WebCTRL"
$javaProcs = Get-Process java*,cjgreen*
if ($javaProcs) {
    $extJavaConns = foreach ($proc in $javaProcs) {
        Get-NetTCPConnection -OwningProcess $proc.Id | Where-Object {
            $_.State -eq 'Established' -and
            $_.RemoteAddress -notmatch '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|::1|0\.0\.0\.0)'
        } | Select-Object @{N='Process';E={$proc.Name}},LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess
    }
    if ($extJavaConns) {
        Write-Log "REVIEW: External public TCP connections established by Java processes:" 'Yellow'
        $table = ($extJavaConns | Format-Table -AutoSize | Out-String).Trim()
        Write-Log $table 'Yellow'
    } else {
        Write-Log "PASS: No external public TCP connections owned by Java processes." 'Green'
    }
} else {
    Write-Log "INFO: No running java/cjgreen processes found." 'Gray'
}

Write-Section "1C. DNS Cache Check (Filtered for Threat Actor / Dynamic DNS)"
$suspiciousDns = Get-DnsClientCache | Where-Object {
    $_.Data -match '2\.57\.241\.75' -or $_.Entry -match 'ngrok|duckdns|interact\.sh|oast\.|burpcollaborator|pastebin|transfer\.sh'
} | Select-Object Entry, Data, TimeToLive
if ($suspiciousDns) {
    Write-Log "ALERT: Suspicious DNS cache entries detected:" 'Red'
    $table = ($suspiciousDns | Format-Table -AutoSize | Out-String).Trim()
    Write-Log $table 'Red'
} else {
    Write-Log "PASS: No threat actor IPs or staging domains in DNS cache." 'Green'
}

# ------------------------------------------------------------------------------
# 2. WINDOWS EVENT LOGS (Security 4688, PS 4104, Defender, System 7045, PS 400)
# ------------------------------------------------------------------------------
Write-Section "2A. Security Log (Event ID 4688 - Suspicious Process Creation Since Nov 19, 2026)"
$secEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime='2026-11-19 00:00:00'} |
    Where-Object {
        $_.Message -notmatch 'Get-WinEvent|Cactus_Audit|Invoke-WebCTRLCactusAudit' -and
        $_.Message -match 'java\.exe.*(cmd\.exe|powershell)|javaw\.exe.*(cmd\.exe|powershell)|==ROOTS2==|IP_MARK=|2\.57\.241\.75'
    } |
    Select-Object TimeCreated, Message -First 20
if ($secEvents) {
    Write-Log "ALERT: Suspicious process creation events found:" 'Red'
    foreach ($ev in $secEvents) {
        $snippet = ($ev.Message -split "`r?`n" | Select-Object -First 12) -join "`n"
        Write-Log "[$($ev.TimeCreated)]`n$snippet`n---" 'Red'
    }
} else {
    Write-Log "PASS/INFO: No suspicious process creation events in Security log since Nov 19, 2026." 'Green'
}

Write-Section "2B. PowerShell Operational Log (Event ID 4104 - Attacker Payloads)"
$psEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} |
    Where-Object {
        $_.Message -notmatch 'Get-WinEvent|Cactus_Audit_|Invoke-WebCTRLCactusAudit' -and
        $_.Message -match '==ROOTS2==|==LICFILES==|==LIC SEARCH==|IP_MARK=|CANDIDATE_ROOTS|UploadString\([''"]http://2\.57\.241\.75|UploadData\(\$V\+|bean_.*_80\.xml|ps3\.xml'
    } |
    Select-Object TimeCreated, Message -First 15
if ($psEvents) {
    Write-Log "ALERT: Attacker PowerShell recon/exfiltration payloads detected!" 'Red'
    foreach ($ev in $psEvents) {
        $preview = ($ev.Message -split "`r?`n" | Select-Object -First 12) -join "`n"
        Write-Log "=== EVENT AT $($ev.TimeCreated) ===`n$preview`n[... full script block saved to report ...]`n" 'Red'
        Add-Content -Path $reportPath -Value "`n--- FULL PAYLOAD AT $($ev.TimeCreated) ---`n$($ev.Message)`n"
    }
} else {
    Write-Log "PASS: No attacker PowerShell payloads found in Event ID 4104." 'Green'
}

Write-Section "2C. Windows Defender Operational Log (Detections 1116/1117 Since Nov 19, 2026)"
$defEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime='2026-11-19 00:00:00'} |
    Where-Object { $_.Id -in 1116,1117 } |
    Select-Object TimeCreated, Id, Message -First 15
if ($defEvents) {
    Write-Log "ALERT: Windows Defender malware detections found since Nov 19, 2026:" 'Red'
    foreach ($ev in $defEvents) {
        Write-Log "[$($ev.TimeCreated)] ID $($ev.Id): $($ev.Message)`n---" 'Red'
    }
} else {
    Write-Log "PASS: No Windows Defender malware detections found since Nov 19, 2026." 'Green'
}

Write-Section "2D. System Log (Event ID 7045 - New Services Installed Since Nov 19, 2026)"
$svcEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime='2026-11-19 00:00:00'}
if ($svcEvents) {
    Write-Log "REVIEW: New service(s) installed since Nov 19, 2026:" 'Yellow'
    foreach ($ev in $svcEvents) {
        Write-Log "[$($ev.TimeCreated)] $($ev.Message)`n---" 'Yellow'
    }
} else {
    Write-Log "PASS: No new Windows services installed since Nov 19, 2026." 'Green'
}

Write-Section "2E. Classic Windows PowerShell Log (Event ID 400 - Spawned Cradles)"
$ps400Events = Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell'; Id=400; StartTime='2026-11-19 00:00:00'} |
    Where-Object {
        $_.Message -notmatch 'Invoke-WebCTRLCactusAudit|Get-MpComputerStatus|Final result: 1' -and
        $_.Message -match 'HostApplication=.*powershell.*(-w\s+hidden|-windowstyle\s+hidden|-enc|-encodedcommand|DownloadString|DownloadData|2\.57\.241\.75|@@MARK@@)'
    } |
    Select-Object TimeCreated, Message -First 15
if ($ps400Events) {
    Write-Log "ALERT: Suspicious hidden/remote PowerShell cradle execution found in Event ID 400!" 'Red'
    foreach ($ev in $ps400Events) {
        $hostApp = ($ev.Message -split "`r?`n" | Where-Object { $_ -match 'HostApplication=' }) -join "`n"
        Write-Log "[$($ev.TimeCreated)] $($hostApp.Trim())" 'Red'
    }
} else {
    Write-Log "PASS: No suspicious PowerShell cradles found in Event ID 400." 'Green'
}

# ------------------------------------------------------------------------------
# 3. WINDOWS FIREWALL LOGS (If Enabled)
# ------------------------------------------------------------------------------
Write-Section "3. Windows Defender Firewall Log Check"
$fwLog = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
if (Test-Path $fwLog) {
    $fwHits = Select-String -Path $fwLog -Pattern "2\.57\.241\.75|8995|8894|8968"
    if ($fwHits) {
        Write-Log "ALERT: Firewall log matches found for threat actor IP/Ports:" 'Red'
        foreach ($hit in $fwHits) {
            Write-Log "Line $($hit.LineNumber): $($hit.Line)" 'Red'
        }
    } else {
        Write-Log "PASS: No matches in pfirewall.log." 'Green'
    }
} else {
    Write-Log "INFO: pfirewall.log not present (Windows Firewall file logging not enabled)." 'Gray'
}

# ------------------------------------------------------------------------------
# 4. WEBCTRL / i-Vu DIRECTORIES, CACTUS JAR, EXPLOIT LOGS, CONFIG SECRETS & STAGING
# ------------------------------------------------------------------------------
Write-Section "4. WebCTRL / i-Vu Installations, Logs, Config Secrets & Staging Files"

$candidateDirs = @()

Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'WebCTRL|i-Vu|cjgreen' -or $_.PathName -match 'WebCTRL|i-Vu' } | ForEach-Object {
    $cleanPath = ($_.PathName -replace '"','').Trim()
    if ($cleanPath -match '^([A-Za-z]:\\.+?\.(exe|bat|cmd))') {
        $exeDir = Split-Path -Parent $matches[1]
        if ((Split-Path -Leaf $exeDir) -eq 'bin') {
            $candidateDirs += Split-Path -Parent $exeDir
        } else {
            $candidateDirs += $exeDir
        }
    }
}

foreach ($drv in 'C','D','E') {
    if (Test-Path "$($drv):\") {
        Get-ChildItem -Path "$($drv):\" -Directory | Where-Object { $_.Name -match 'WebCTRL|i-Vu|Automated' } | ForEach-Object {
            $candidateDirs += $_.FullName
        }
        foreach ($pf in @("$($drv):\Program Files\Automated Logic","$($drv):\Program Files (x86)\Automated Logic","$($drv):\Program Files\Carrier","$($drv):\Program Files (x86)\Carrier")) {
            if (Test-Path $pf) {
                Get-ChildItem -Path $pf -Directory | ForEach-Object { $candidateDirs += $_.FullName }
            }
        }
    }
}

$webctrlDirs = $candidateDirs | Select-Object -Unique | Where-Object { Test-Path $_ }

if (-not $webctrlDirs) {
    Write-Log "REVIEW: Could not auto-detect WebCTRL/i-Vu directories on C:, D:, or E:." 'Yellow'
} else {
    foreach ($dir in $webctrlDirs) {
        Write-Log "`n--- Scanning Directory: $dir ---" 'Cyan'

        # 4A. Check if vulnerable cactus*.jar still exists
        $cactusJars = Get-ChildItem -Path $dir -Filter "*cactus*.jar" -Recurse
        if ($cactusJars) {
            Write-Log "ALERT (VULNERABLE): Cactus JAR(s) still present on disk!" 'Red'
            foreach ($jar in $cactusJars) {
                Write-Log "  -> $($jar.FullName) (Modified: $($jar.LastWriteTime))" 'Red'
            }
        } else {
            Write-Log "PASS: No cactus*.jar files present in $dir." 'Green'
        }

        # 4B. Search logs for Cactus exploit / Spring RCE / Threat Actor IP (excluding stack trace noise & self-files)
        $logHits = Get-ChildItem -Path $dir -Include *.txt,*.log -Recurse |
            Where-Object {
                $_.FullName -notmatch '\\\.install4j\\' -and
                $_.Name -notmatch 'Cactus_Audit|Invoke-WebCTRLCactusAudit'
            } |
            Select-String -Pattern "ServletRedirector|JspRedirector|FilterRedirector|ClassPathXmlApplicationContext|Cactus_Service|Cactus_TestClass|2\.57\.241\.75" |
            Where-Object { $_.Line -notmatch '^\s*at\s+' }
        if ($logHits) {
            Write-Log "ALERT: Exploit / probe indicators found in application logs ($($logHits.Count) key lines):" 'Red'
            foreach ($hit in ($logHits | Select-Object -First 30)) {
                Write-Log "  $($hit.Path):$($hit.LineNumber) -> $($hit.Line.Trim())" 'Red'
            }
            if ($logHits.Count -gt 30) {
                Write-Log "  ... ($($logHits.Count - 30) additional lines truncated; see report file)" 'Red'
            }
        } else {
            Write-Log "PASS: Zero exploit/probe matches in application logs." 'Green'
        }

        # 4C. Check first 300 lines of Tomcat/Web configs for exposed secrets
        $cfgSubPaths = @(
            "webserver\conf\server.xml",
            "webserver\conf\tomcat-users.xml",
            "webserver\conf\context.xml",
            "conf\server.xml",
            "conf\tomcat-users.xml",
            "programdata\conf\server.xml"
        )
        foreach ($sub in $cfgSubPaths) {
            $cfgFile = Join-Path $dir $sub
            if (Test-Path $cfgFile) {
                $lines = Get-Content -Path $cfgFile -TotalCount 300
                $secretHits = $lines | Select-String -Pattern 'keystorePass|truststorePass|<user\s+username='
                if ($secretHits) {
                    Write-Log "REVIEW: Credential/keystore attributes found in first 300 lines of $cfgFile (rotate if compromised):" 'Yellow'
                    foreach ($sh in $secretHits) {
                        Write-Log "  Line $($sh.LineNumber): $($sh.Line.Trim())" 'Yellow'
                    }
                }
            }
        }

        # 4D. Check webroot for recently created/modified .jsp, .jspx, or .jar files (last 30 days)
        $webroot = Join-Path $dir "webroot"
        if (Test-Path $webroot) {
            $recentWebFiles = Get-ChildItem -Path $webroot -Include *.jsp,*.jspx,*.jar -Recurse |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) }
            if ($recentWebFiles) {
                Write-Log "REVIEW: $($recentWebFiles.Count) file(s) in webroot created/modified in the last 30 days (verify dates match legitimate patches):" 'Yellow'
                $groupedDates = $recentWebFiles | Group-Object { $_.LastWriteTime.ToString('yyyy-MM-dd') }
                foreach ($grp in $groupedDates) {
                    Write-Log "  Date $($grp.Name): $($grp.Count) file(s) (e.g., $($grp.Group[0].FullName))" 'Yellow'
                }
            } else {
                Write-Log "PASS: No .jsp/.jspx/.jar files modified in webroot within the last 30 days." 'Green'
            }
        }
    }
}

# 4E. Check Windows & Service Account Temp Directories for Attacker Staging Folders (i80_*)
Write-Log "`n--- Checking Temp Directories for Attacker Staging Folders (i80_*) ---" 'Cyan'
$tempTargets = @("C:\Windows\Temp")
Get-ChildItem -Path "C:\Users" -Directory | ForEach-Object {
    $userTemp = Join-Path $_.FullName "AppData\Local\Temp"
    if (Test-Path $userTemp) { $tempTargets += $userTemp }
}
$stagingDirs = foreach ($tDir in ($tempTargets | Select-Object -Unique)) {
    Get-ChildItem -Path $tDir -Filter "i80_*" -Directory -Force
}
if ($stagingDirs) {
    Write-Log "ALERT: Attacker ps3 staging folder(s) found on disk!" 'Red'
    foreach ($sd in $stagingDirs) {
        $files = (Get-ChildItem -Path $sd.FullName -Force | Select-Object -ExpandProperty Name) -join ', '
        Write-Log "  -> $($sd.FullName) (Created: $($sd.CreationTime) | Contents: $files)" 'Red'
    }
} else {
    Write-Log "PASS: No i80_* attacker staging folders found in Temp directories." 'Green'
}

# ------------------------------------------------------------------------------
# 5. PERSISTENCE CHECK (Local Users & Scheduled Tasks >= Nov 19, 2026)
# ------------------------------------------------------------------------------
Write-Section "5A. Local User Accounts Audit"
$users = Get-LocalUser | Select-Object Name, Enabled, PasswordLastSet, LastLogon
$userTable = ($users | Format-Table -AutoSize | Out-String).Trim()
Write-Log $userTable 'White'

Write-Section "5B. Scheduled Tasks Created/Modified Since Nov 19, 2026"
$recentTasks = Get-ScheduledTask | Where-Object { $_.Date -gt '2026-11-19' } | Select-Object TaskName, TaskPath, Date
if ($recentTasks) {
    Write-Log "REVIEW: Scheduled tasks created/modified since Nov 19, 2026:" 'Yellow'
    $taskTable = ($recentTasks | Format-Table -AutoSize | Out-String).Trim()
    Write-Log $taskTable 'Yellow'
} else {
    Write-Log "PASS: No scheduled tasks created or modified since Nov 19, 2026." 'Green'
}

# ------------------------------------------------------------------------------
# FINAL SUMMARY BANNER
# ------------------------------------------------------------------------------
Write-Section "FINAL HOST VERDICT: $env:COMPUTERNAME"
if ($script:HasAlert) {
    Write-Log "STATUS: [ALERT - ACTION REQUIRED] Exploit indicators or vulnerable cactus*.jar found on $env:COMPUTERNAME!" 'Red'
} elseif ($script:HasReview) {
    Write-Log "STATUS: [REVIEW] No active compromise alerts, but review highlighted items above on $env:COMPUTERNAME." 'Yellow'
} else {
    Write-Log "STATUS: [CLEAN] No Cactus JARs, exploit logs, or compromise indicators found on $env:COMPUTERNAME." 'Green'
}
Write-Log "Full report saved to: $reportPath" 'Green'
}
