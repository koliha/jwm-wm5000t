# JWM WM-5000T Guard Patrol Device – Serial Protocol Reference

Reverse-engineered from USB pcap captures and verified against live device downloads.

---

## Connection

| Parameter | Value |
|-----------|-------|
| Baud rate | 19200 |
| Data bits | 8 |
| Parity    | None |
| Stop bits | 1 |
| DTR       | Deasserted (LOW) |
| RTS       | Deasserted (LOW) |
| Flow ctrl | None |

On Windows the CP210X USB adapter appears as `COM4` (or similar).  
On Linux/Raspberry Pi it appears as `/dev/ttyUSB0`.

---

## Critical timing requirement

The protocol is **fully interleaved**: each command must be sent and its complete response read before the next command is sent. **Do not send all bytes in one bulk write.**

The device has an internal state-machine timeout of approximately 100ms. If the host does not send the next command within that window, the device resets its state and begins re-sending the 30-byte block header. This means:

- Reading with a long idle gap (≥150ms) causes the device to loop in block-header mode.
- Reading with too short a gap (≤10ms) truncates the block header before it finishes arriving.
- **50ms idle-silence threshold works reliably.**

---

## Command reference

All multi-byte commands use this checksum:  
`CS = (~(sum of all payload bytes)) & 0xFF`

| Name | Bytes (hex) | Notes |
|------|-------------|-------|
| BlockStart-1 | `55` | First byte of block preamble. Device responds with 30B block header. |
| BlockStart-2 | `E5` | Second byte of block preamble. Device echoes `E5`. |
| SetTime | `35 CA 07 YY MM DD HH MM SS CS` | 10 bytes. All date/time fields BCD-encoded (see below). CS covers `35 07 YY MM DD HH MM SS`. |
| StatusQuery | `15 EA 01 E9` | 4 bytes, no payload. |
| Download | `25 DA 01 D9` | 4 bytes. Triggers record delivery. |
| CloseSession | `55 AA 01 A9` | 4 bytes. Ends session and **wipes device memory**. |

### BCD encoding

All date/time values are packed BCD: tens digit in the high nibble, units digit in the low nibble.

```
bcd_encode(n) = ((n // 10) << 4) | (n % 10)
bcd_decode(b) = (b >> 4) * 10 + (b & 0x0F)
```

Examples: `13` → `0x13`, `46` → `0x46`, `2026` → year field = `0x26` (i.e. year − 2000).

### SetTime checksum

```
sum = 0x35 + 0x07 + YY + MM + DD + HH + MN + SS
CS  = (~sum) & 0xFF
```

---

## Session sequence

### Block 1

| Step | TX | Expected RX |
|------|----|-------------|
| 1 | `55` (1B) | 30B: `55 [00×19] [brand 10B]` |
| 2 | `E5` (1B) | 1B: `E5` |
| 3 | SetTime (10B) | 11B: echo + `00` |
| 4 | StatusQuery (4B) | 8B: echo + 4B status response |

### Block 2

| Step | TX | Expected RX |
|------|----|-------------|
| 5 | `55` (1B) | 30B: `55 [00×19] [brand 10B]` |
| 6 | `E5` (1B) | 1B: `E5` |
| 7 | StatusQuery (4B) | 8B: echo + 4B status response |
| 8 | StatusQuery (4B) | 8B: echo + 4B status response |
| 9 | Download (4B) | 7B: echo + `N` + `00` + `~N` |

`N` = number of stored records (byte index 4 of the 7B response).  
`~N` = `(~N) & 0xFF` — use as a sanity check.

### Record download (repeat N times)

| Step | TX | Expected RX |
|------|----|-------------|
| 10 (×N) | `00` (1B) | 14B: `00` (null echo) + 13B record |

### Trailing null

| Step | TX | Expected RX |
|------|----|-------------|
| 11 | `00` (1B) | 1B: `00` |

N+1 null bytes are sent in total (one per record, plus one trailing).

### Close session

| Step | TX | Expected RX |
|------|----|-------------|
| 12 | SetTime (10B) | 11B: echo + `00` |
| 13 | CloseSession (4B) | 5B: echo + `00` |

After step 13, device memory is wiped.

---

## Block header format

Sent by the device in response to `55` (steps 1 and 5):

```
Byte 0:    55
Bytes 1-19: 00 00 00 ... (19 zero bytes)
Bytes 20-29: brand string (10 bytes, ASCII, e.g. "FFFFZJWZWS")
```

Total: 30 bytes. The brand bytes are device-specific and do not change between sessions. They can be used to verify the device is present and responding.

---

## Record format

Each record is **13 bytes**:

```
Offset  Size  Description
------  ----  -----------
0       1     Year (BCD, add 2000)
1       1     Month (BCD)
2       1     Day (BCD)
3       1     Hour (BCD)
4       1     Minute (BCD)
5       1     Second (BCD)
6-8     3     Always 00 00 00
9       1     Badge ID byte 1
10      1     Badge ID byte 2
11      1     Badge ID byte 3
12      1     Checksum
```

### Checksum verification

```
CS = (~(sum of bytes 0–11)) & 0xFF
```

Verify that byte 12 equals this value.

### Badge ID

The device stores the last 3 bytes of the iButton serial number. Full display format:

```
000000 + hex(byte9) + hex(byte10) + hex(byte11)
```

Example: bytes `F4 09 39` → badge ID `000000F40939`.

---

## Why the 14-byte "record" appears in raw captures

When reading the assembled serial RX stream (e.g. from a USB sniffer), records appear to be 14 bytes because the null echo from the *next* null TX immediately follows each 13-byte record in the byte stream:

```
[null-echo-k (1B)] [record-k data (13B)] [null-echo-k+1 (1B)] [record-k+1 data (13B)] ...
```

The 14th byte is not part of the record; it is the echo of the following null TX.

---

## Captured command bytes (reference)

From a verified 2-record session:

```
TX (combined):
55 E5 35 CA 07 26 06 05 13 46 12 27 15 EA 01 E9
55 E5 15 EA 01 E9 15 EA 01 E9 25 DA 01 D9
00 00 00
35 CA 07 26 06 05 13 46 16 23 55 AA 01 A9

RX (combined, 149 bytes):
55 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 46 46 46 46 5A 4A 57 5A 57 53  <- B1 header
E5                                                                                           <- E5 echo
35 CA 07 26 06 05 13 46 12 27 00                                                            <- SetTime echo + 00
15 EA 01 E9 53 19 32 61                                                                     <- Status echo + response
55 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 46 46 46 46 5A 4A 57 5A 57 53  <- B2 header
E5                                                                                           <- E5 echo
15 EA 01 E9 53 19 32 61                                                                     <- Status1 echo + response
15 EA 01 E9 53 19 32 61                                                                     <- Status2 echo + response
25 DA 01 D9                                                                                 <- DL echo
02 00 FD                                                                                    <- count: N=2
00 26 06 05 13 46 03 00 00 00 F4 09 39 3C                                                  <- null echo + record 1
00 26 06 05 13 46 06 00 00 00 F3 F6 AD D9                                                  <- null echo + record 2
00                                                                                           <- trailing null echo
35 CA 07 26 06 05 13 46 16 23 00                                                            <- SetTime2 echo + 00
55 AA 01 A9 00                                                                               <- Close echo + 00
```
