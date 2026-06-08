<#
.SYNOPSIS
    Downloads guard patrol scan records from a JWM WM-5000T device and clears device memory.

.DESCRIPTION
    Communicates with the JWM WM-5000T over serial (default COM4) using the reverse-
    engineered binary protocol at 19200 baud 8N1.

    Protocol (fully interleaved - one command/response at a time)
    -------------------------------------------------------------
    Block 1:  TX 55           -> RX 30B (header: 55 + 19 zeros + brand)
              TX E5           -> RX 1B  (echo)
              TX SetTime(10B) -> RX 11B (echo + 00)
              TX Status(4B)   -> RX 8B  (echo + response)

    Block 2:  TX 55           -> RX 30B (header)
              TX E5           -> RX 1B  (echo)
              TX Status(4B)   -> RX 8B  (echo + response)  [x2]
              TX Download(4B) -> RX 7B  (echo + N + 00 + ~N)

    Records:  For k=1..N:
              TX 00           -> RX 14B (null echo + 13B record data)
              TX 00 (final)   -> RX 1B  (null echo)

    Close:    TX SetTime2(10B)-> RX 11B (echo + 00)
              TX Close(4B)    -> RX 5B  (echo + 00)

    Record (13 bytes): [YY MM DD HH MM SS] [00 00 00] [B1 B2 B3] [CS]
    All timestamp bytes BCD, year offset 2000.
    Badge ID displayed as "000000" + hex(B1 B2 B3).
    CS = ~(sum bytes 0-11) & 0xFF.

.PARAMETER Port
    COM port. Default: COM4

.PARAMETER CsvPath
    Optional CSV output path.

.PARAMETER ReadTimeoutMs
    Timeout for first byte. Default: 10000

.PARAMETER DebugProtocol
    Show raw hex traces.

.EXAMPLE
    .\Get-JWMPatrolData.ps1

.EXAMPLE
    .\Get-JWMPatrolData.ps1 -Port COM3 -CsvPath C:\patrol\log.csv
#>

[CmdletBinding()]
param(
    [string]$Port          = 'COM4',
    [string]$CsvPath       = '',
    [int]   $ReadTimeoutMs = 10000,
    [switch]$DebugProtocol
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- Protocol constants -----------------------------------------------------

$BAUD_RATE    = 19200
$CMD_CLOSE    = [byte[]](0x55, 0xAA, 0x01, 0xA9)
$STATUS_CMD   = [byte[]](0x15, 0xEA, 0x01, 0xE9)
$DL_CMD       = [byte[]](0x25, 0xDA, 0x01, 0xD9)
$RECORD_SIZE  = 13
$IDLE_GAP_MS  = 500
$STEP_GAP_MS  = 50

# ---- Helpers ----------------------------------------------------------------

function ConvertTo-BCD ([int]$n) {
    if ($n -lt 0 -or $n -gt 99) { throw "BCD out of range: $n" }
    $ones = $n % 10
    $tens = [int](($n - $ones) / 10)
    return [byte](($tens -shl 4) -bor $ones)
}

function ConvertFrom-BCD ([byte]$b) {
    return [int](($b -shr 4) * 10 + ($b -band 0x0F))
}

function Build-TimeCommand ([datetime]$dt) {
    $yy  = ConvertTo-BCD ($dt.Year - 2000)
    $mm  = ConvertTo-BCD  $dt.Month
    $dd  = ConvertTo-BCD  $dt.Day
    $hh  = ConvertTo-BCD  $dt.Hour
    $mn  = ConvertTo-BCD  $dt.Minute
    $ss  = ConvertTo-BCD  $dt.Second
    $sum = 0x35 + 0x07 + [int]$yy + [int]$mm + [int]$dd + [int]$hh + [int]$mn + [int]$ss
    $cs  = [byte]((0xFF - ($sum -band 0xFF)) -band 0xFF)
    return [byte[]](0x35, 0xCA, 0x07, $yy, $mm, $dd, $hh, $mn, $ss, $cs)
}

function Join-Bytes ([byte[][]]$arrays) {
    $list = [System.Collections.Generic.List[byte]]::new()
    foreach ($a in $arrays) { $list.AddRange($a) }
    return $list.ToArray()
}

function Read-Burst ([System.IO.Ports.SerialPort]$sp, [string]$label, [int]$idleMs = $IDLE_GAP_MS) {
    $buf  = [System.Collections.Generic.List[byte]]::new()
    $dead = (Get-Date).AddMilliseconds($ReadTimeoutMs)
    $last = [datetime]::MinValue
    $started = $false
    while ($true) {
        $now = Get-Date
        if ($now -gt $dead) {
            if ($buf.Count -eq 0) { throw "Read-Burst timeout [$label] - no data within ${ReadTimeoutMs}ms" }
            break
        }
        if ($started -and ($now - $last).TotalMilliseconds -gt $idleMs) { break }
        $avail = $sp.BytesToRead
        if ($avail -gt 0) {
            $tmp = [byte[]]::new($avail)
            $null = $sp.Read($tmp, 0, $avail)
            $buf.AddRange($tmp)
            $last    = Get-Date
            $started = $true
        } else { Start-Sleep -Milliseconds 5 }
    }
    [byte[]]$result = $buf.ToArray()
    if ($DebugProtocol) {
        $hex = ($result | ForEach-Object { $_.ToString('X2') }) -join ' '
        Write-Host "  RX [$label] ($($result.Count)B) $hex" -ForegroundColor DarkGray
    }
    return $result
}

function Read-Exact ([System.IO.Ports.SerialPort]$sp, [int]$count, [string]$label) {
    if ($count -eq 0) { return [byte[]]::new(0) }
    $buf  = [byte[]]::new($count)
    $recv = 0
    $dead = (Get-Date).AddMilliseconds($ReadTimeoutMs)
    while ($recv -lt $count) {
        if ((Get-Date) -gt $dead) { throw "Read-Exact timeout [$label] $recv/$count" }
        $avail = $sp.BytesToRead
        if ($avail -gt 0) {
            $n     = $sp.Read($buf, $recv, [Math]::Min($avail, $count - $recv))
            $recv += $n
        } else { Start-Sleep -Milliseconds 5 }
    }
    return $buf
}

function Write-Bytes ([System.IO.Ports.SerialPort]$sp, [byte[]]$data, [string]$label) {
    if ($DebugProtocol) {
        $hex = ($data | ForEach-Object { $_.ToString('X2') }) -join ' '
        Write-Host "  TX [$label] ($($data.Length)B) $hex" -ForegroundColor DarkCyan
    }
    $sp.Write($data, 0, $data.Length)
}

# ---- Main -------------------------------------------------------------------

Write-Host ''
Write-Host 'JWM WM-5000T Guard Patrol Downloader' -ForegroundColor Cyan
Write-Host "Port: $Port  |  Baud: $BAUD_RATE  |  8N1" -ForegroundColor Cyan
Write-Host ('-' * 50)

$sp = New-Object System.IO.Ports.SerialPort(
    $Port, $BAUD_RATE,
    [System.IO.Ports.Parity]::None, 8,
    [System.IO.Ports.StopBits]::One
)
$sp.ReadTimeout  = -1
$sp.WriteTimeout = 3000
$sp.DtrEnable    = $false   # JWM software keeps DTR deasserted
$sp.RtsEnable    = $false   # JWM software keeps RTS deasserted

$records = [System.Collections.Generic.List[PSCustomObject]]::new()

try {
    $sp.Open()
    Start-Sleep -Milliseconds 300
    $sp.DiscardInBuffer()
    $sp.DiscardOutBuffer()
    Write-Host "Connected to $Port." -ForegroundColor Green

    # Fully interleaved protocol: one command at a time, read response before sending next.
    # This matches JWM software behavior observed in USB pcap (one bulk transfer per command).
    [byte[]]$timeCmd1 = Build-TimeCommand (Get-Date)

    # ---- Block 1 ----------------------------------------------------------------
    Write-Bytes $sp ([byte[]](0x55))       'B1-start'
    $null = Read-Burst $sp 'B1-header' $STEP_GAP_MS
    # Expect: 55 [00x19] [brand] = 30B

    Write-Bytes $sp ([byte[]](0xE5))       'B1-E5'
    $null = Read-Burst $sp 'B1-E5-echo' $STEP_GAP_MS
    # Expect: E5 = 1B

    Write-Bytes $sp $timeCmd1              'B1-time'
    $null = Read-Burst $sp 'B1-time-echo' $STEP_GAP_MS
    # Expect: time_echo(10B) + 00 = 11B

    Write-Bytes $sp $STATUS_CMD            'B1-status'
    $null = Read-Burst $sp 'B1-status-resp' $STEP_GAP_MS
    # Expect: echo(4B) + response(4B) = 8B

    # ---- Block 2 ----------------------------------------------------------------
    Write-Bytes $sp ([byte[]](0x55))       'B2-start'
    $null = Read-Burst $sp 'B2-header' $STEP_GAP_MS
    # Expect: 55 [00x19] [brand] = 30B

    Write-Bytes $sp ([byte[]](0xE5))       'B2-E5'
    $null = Read-Burst $sp 'B2-E5-echo' $STEP_GAP_MS
    # Expect: E5 = 1B

    Write-Bytes $sp $STATUS_CMD            'B2-status1'
    $null = Read-Burst $sp 'B2-status1-resp' $STEP_GAP_MS
    # Expect: echo(4B) + response(4B) = 8B

    Write-Bytes $sp $STATUS_CMD            'B2-status2'
    $null = Read-Burst $sp 'B2-status2-resp' $STEP_GAP_MS
    # Expect: echo(4B) + response(4B) = 8B

    # ---- Download command -------------------------------------------------------
    Write-Bytes $sp $DL_CMD                'DL-cmd'
    [byte[]]$rxDL = Read-Burst $sp 'DL-resp' $STEP_GAP_MS
    # Expect: DL-echo(4B) + N(1B) + 00(1B) + ~N(1B) = 7B
    # N is rxDL[4]

    [int]$N = 0
    if ($rxDL.Length -ge 5) {
        $N = [int]$rxDL[4]
        if ($N -gt 200 -or $N -lt 0) {
            Write-Warning "Unexpected record count byte 0x$($rxDL[4].ToString('X2')), treating as 0"
            $N = 0
        }
    } else {
        Write-Warning "Download response too short ($($rxDL.Length)B), expected >=5"
    }
    Write-Host "Device reports $N record(s)." -ForegroundColor Cyan

    # ---- Records ----------------------------------------------------------------
    # Each null TX prompts the device for one record.
    # RX per null: [00 null-echo] [13B record data] = 14B total.
    # Record layout: bytes 0-5=BCD timestamp, 6-8=zeros, 9-11=badge, 12=checksum.
    for ($k = 1; $k -le $N; $k++) {
        Write-Bytes $sp ([byte[]](0x00))   "null-$k"
        [byte[]]$rxRec = Read-Burst $sp "rec-$k" $STEP_GAP_MS
        # rxRec[0] = null echo (00), rxRec[1..13] = 13B record

        if ($rxRec.Length -lt 14) {
            Write-Warning "Record ${k}: short RX ($($rxRec.Length)B < 14), skipping"
            continue
        }
        [byte[]]$r = $rxRec[1..13]   # 13 bytes of record data

        [int]$sum = 0
        for ($j = 0; $j -lt 12; $j++) { $sum += [int]$r[$j] }
        $expCs = [byte]((0xFF - ($sum -band 0xFF)) -band 0xFF)
        if ($r[12] -ne $expCs) {
            Write-Warning "Record $k checksum mismatch (got 0x$($r[12].ToString('X2')) expected 0x$($expCs.ToString('X2')))"
        }

        $year  = 2000 + (ConvertFrom-BCD $r[0])
        $month = ConvertFrom-BCD $r[1]
        $day   = ConvertFrom-BCD $r[2]
        $hour  = ConvertFrom-BCD $r[3]
        $min   = ConvertFrom-BCD $r[4]
        $sec   = ConvertFrom-BCD $r[5]
        [datetime]$ts = [datetime]::new($year, $month, $day, $hour, $min, $sec)
        $badge = '000000{0:X2}{1:X2}{2:X2}' -f $r[9], $r[10], $r[11]
        $records.Add([PSCustomObject]@{
            Index     = $k
            BadgeID   = $badge
            Timestamp = $ts
        })
    }

    # ---- Trailing null (N+1 total nulls sent) -----------------------------------
    Write-Bytes $sp ([byte[]](0x00))       'null-final'
    $null = Read-Burst $sp 'null-final-echo' $STEP_GAP_MS
    # Expect: 00 = 1B

    # ---- Close session (wipes device memory) ------------------------------------
    [byte[]]$timeCmd2 = Build-TimeCommand (Get-Date)
    Write-Bytes $sp $timeCmd2              'close-time'
    $null = Read-Burst $sp 'close-time-echo' $STEP_GAP_MS
    # Expect: time_echo(10B) + 00 = 11B

    Write-Bytes $sp $CMD_CLOSE             'close-cmd'
    $null = Read-Burst $sp 'close-echo' $STEP_GAP_MS
    # Expect: close_echo(4B) + 00 = 5B

} catch {
    Write-Error "Protocol error: $_"
    exit 1
} finally {
    if ($sp -and $sp.IsOpen) {
        try { $sp.Close() } catch {}
        $sp.Dispose()
    }
}

# ---- Output -----------------------------------------------------------------

if ($records.Count -eq 0) {
    Write-Host 'No records found on device.' -ForegroundColor Yellow
} else {
    Write-Host ''
    Write-Host ('{0,-5}  {1,-14}  {2}' -f '#', 'Badge ID', 'Timestamp') -ForegroundColor Green
    Write-Host ('{0,-5}  {1,-14}  {2}' -f '-----', '--------------', '-----------------------') -ForegroundColor Green
    foreach ($rec in $records) {
        Write-Host ('{0,-5}  {1,-14}  {2:yyyy-MM-dd HH:mm:ss}' -f $rec.Index, $rec.BadgeID, $rec.Timestamp)
    }
    Write-Host ''
    Write-Host "$($records.Count) record(s) downloaded. Device memory cleared." -ForegroundColor Green
    if ($CsvPath) {
        $records | Select-Object -Property BadgeID, Timestamp |
            Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Saved to: $CsvPath" -ForegroundColor Cyan
    }
}

Write-Host ''
