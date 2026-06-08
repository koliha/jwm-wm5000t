#!/usr/bin/env python3
"""
JWM WM-5000T Guard Patrol Downloader

Downloads badge scan records from a JWM WM-5000T guard patrol device
and clears device memory.

Requires:  pip install pyserial
Usage:     python3 get_jwm_patrol_data.py [--port /dev/ttyUSB0] [--csv out.csv] [--debug]

On a Raspberry Pi the CP210X USB-to-serial adapter usually appears as
/dev/ttyUSB0.  Install pyserial with:  sudo pip3 install pyserial
You may also need to add your user to the dialout group:
    sudo usermod -aG dialout $USER   (then log out and back in)

Protocol notes
--------------
The protocol is fully interleaved: one command is sent and its response
is fully read before the next command is sent.  The device state machine
resets if the host takes more than ~100ms between steps, so STEP_GAP_S
(50ms idle-silence threshold) is critical -- do not increase it.

Session sequence:
  Block 1:  TX 55          -> RX 30B (header: 55 + 19 zeros + brand)
            TX E5          -> RX 1B  (echo)
            TX SetTime(10B)-> RX 11B (echo + 00)
            TX Status(4B)  -> RX 8B  (echo + response)
  Block 2:  TX 55          -> RX 30B
            TX E5          -> RX 1B
            TX Status(4B)  -> RX 8B  (x2)
            TX Download(4B)-> RX 7B  (echo + N + 00 + ~N)
  Records:  for k in 1..N:
              TX 00        -> RX 14B (null echo + 13B record)
            TX 00 (final)  -> RX 1B
  Close:    TX SetTime(10B)-> RX 11B
            TX Close(4B)   -> RX 5B  (wipes device memory)

Record format (13 bytes):
  [YY MM DD HH MM SS] [00 00 00] [B1 B2 B3] [CS]
  All timestamp bytes BCD, year offset 2000.
  Badge ID = "000000" + hex(B1 B2 B3)
  CS = ~(sum bytes 0-11) & 0xFF
"""

import argparse
import csv
import sys
import time
from datetime import datetime

try:
    import serial
except ImportError:
    sys.exit("pyserial is required:  pip install pyserial")

# ---- Protocol constants -------------------------------------------------------

BAUD_RATE    = 19200
STEP_GAP_S   = 0.050   # 50ms idle-silence threshold per step (CRITICAL - see notes above)
READ_TIMEOUT = 10.0    # seconds before raising TimeoutError on a silent port

STATUS_CMD   = bytes([0x15, 0xEA, 0x01, 0xE9])
DL_CMD       = bytes([0x25, 0xDA, 0x01, 0xD9])
CMD_CLOSE    = bytes([0x55, 0xAA, 0x01, 0xA9])

# ---- Helpers ------------------------------------------------------------------

def bcd_encode(n):
    if not 0 <= n <= 99:
        raise ValueError(f"BCD out of range: {n}")
    return ((n // 10) << 4) | (n % 10)


def bcd_decode(b):
    return (b >> 4) * 10 + (b & 0x0F)


def build_time_cmd(dt):
    yy = bcd_encode(dt.year - 2000)
    mm = bcd_encode(dt.month)
    dd = bcd_encode(dt.day)
    hh = bcd_encode(dt.hour)
    mn = bcd_encode(dt.minute)
    ss = bcd_encode(dt.second)
    cs = (~(0x35 + 0x07 + yy + mm + dd + hh + mn + ss)) & 0xFF
    return bytes([0x35, 0xCA, 0x07, yy, mm, dd, hh, mn, ss, cs])


def read_burst(sp, label, idle_s=STEP_GAP_S, debug=False):
    """Read bytes until idle_s seconds of silence, or READ_TIMEOUT seconds total."""
    buf = bytearray()
    deadline = time.monotonic() + READ_TIMEOUT
    last_rx = None

    while True:
        now = time.monotonic()
        if now >= deadline:
            if not buf:
                raise TimeoutError(f"[{label}] no data within {READ_TIMEOUT:.0f}s")
            break
        if last_rx is not None and (now - last_rx) >= idle_s:
            break
        waiting = sp.in_waiting
        if waiting:
            buf.extend(sp.read(waiting))
            last_rx = time.monotonic()
        else:
            time.sleep(0.005)

    result = bytes(buf)
    if debug:
        print(f"  RX [{label}] ({len(result)}B) {result.hex(' ').upper()}")
    return result


def send_recv(sp, tx_data, label, debug=False):
    if debug:
        print(f"  TX [{label}] ({len(tx_data)}B) {tx_data.hex(' ').upper()}")
    sp.write(tx_data)
    return read_burst(sp, label, debug=debug)


# ---- Main download logic ------------------------------------------------------

def download_records(port, csv_path=None, debug=False):
    print()
    print("JWM WM-5000T Guard Patrol Downloader")
    print(f"Port: {port}  |  Baud: {BAUD_RATE}  |  8N1")
    print("-" * 50)

    sp = serial.Serial(
        port=port,
        baudrate=BAUD_RATE,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        timeout=None,        # we manage timing ourselves via in_waiting
        write_timeout=3.0,
        dsrdtr=False,
        rtscts=False,
        xonxoff=False,
    )

    records = []
    try:
        sp.dtr = False       # JWM software keeps DTR deasserted (LOW)
        sp.rts = False       # JWM software keeps RTS deasserted (LOW)
        time.sleep(0.3)
        sp.reset_input_buffer()
        sp.reset_output_buffer()
        print(f"Connected to {port}.")

        time_cmd1 = build_time_cmd(datetime.now())

        # ---- Block 1 ----
        send_recv(sp, bytes([0x55]), 'B1-start',   debug)
        send_recv(sp, bytes([0xE5]), 'B1-E5',      debug)
        send_recv(sp, time_cmd1,    'B1-time',     debug)
        send_recv(sp, STATUS_CMD,   'B1-status',   debug)

        # ---- Block 2 ----
        send_recv(sp, bytes([0x55]), 'B2-start',   debug)
        send_recv(sp, bytes([0xE5]), 'B2-E5',      debug)
        send_recv(sp, STATUS_CMD,   'B2-status1',  debug)
        send_recv(sp, STATUS_CMD,   'B2-status2',  debug)

        # ---- Download command ----
        rx_dl = send_recv(sp, DL_CMD, 'DL-cmd', debug)
        if len(rx_dl) < 5:
            raise RuntimeError(f"Download response too short ({len(rx_dl)}B, expected >=5)")

        n = rx_dl[4]
        if n > 200:
            print(f"Warning: unexpected record count 0x{n:02X}, treating as 0", file=sys.stderr)
            n = 0
        print(f"Device reports {n} record(s).")

        # ---- Records ----
        # Each null TX prompts the device for one record.
        # RX: [00 null-echo] [13B record data] = 14B total.
        for k in range(1, n + 1):
            rx_rec = send_recv(sp, bytes([0x00]), f'null-{k}', debug)
            if len(rx_rec) < 14:
                print(f"Warning: record {k} short RX ({len(rx_rec)}B < 14), skipping",
                      file=sys.stderr)
                continue

            r = rx_rec[1:14]   # skip null echo byte, take 13 bytes of record
            expected_cs = (~sum(r[:12])) & 0xFF
            if r[12] != expected_cs:
                print(f"Warning: record {k} checksum mismatch "
                      f"(got 0x{r[12]:02X} expected 0x{expected_cs:02X})", file=sys.stderr)

            ts = datetime(
                2000 + bcd_decode(r[0]),
                bcd_decode(r[1]),
                bcd_decode(r[2]),
                bcd_decode(r[3]),
                bcd_decode(r[4]),
                bcd_decode(r[5]),
            )
            badge = f"000000{r[9]:02X}{r[10]:02X}{r[11]:02X}"
            records.append({"index": k, "badge_id": badge, "timestamp": ts})

        # ---- Trailing null (N+1 total nulls sent) ----
        send_recv(sp, bytes([0x00]), 'null-final', debug)

        # ---- Close session (wipes device memory) ----
        time_cmd2 = build_time_cmd(datetime.now())
        send_recv(sp, time_cmd2, 'close-time', debug)
        send_recv(sp, CMD_CLOSE, 'close-cmd',  debug)

    finally:
        sp.close()

    # ---- Output ----
    if not records:
        print("No records found on device.")
    else:
        print()
        print(f"{'#':<5}  {'Badge ID':<14}  Timestamp")
        print(f"{'-----':<5}  {'-----':<14}  -----------------------")
        for rec in records:
            print(f"{rec['index']:<5}  {rec['badge_id']:<14}  "
                  f"{rec['timestamp']:%Y-%m-%d %H:%M:%S}")
        print()
        print(f"{len(records)} record(s) downloaded. Device memory cleared.")

        if csv_path:
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["badge_id", "timestamp"])
                writer.writeheader()
                for rec in records:
                    writer.writerow({
                        "badge_id":  rec["badge_id"],
                        "timestamp": rec["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    })
            print(f"Saved to: {csv_path}")

    print()
    return records


# ---- Entry point --------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Download records from a JWM WM-5000T guard patrol device",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--port", default="/dev/ttyUSB0",
        help="Serial port (default: /dev/ttyUSB0)",
    )
    parser.add_argument(
        "--csv", metavar="PATH",
        help="Save records to a CSV file",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Print raw TX/RX hex traces",
    )
    args = parser.parse_args()

    try:
        download_records(args.port, csv_path=args.csv, debug=args.debug)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
