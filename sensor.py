#!/usr/bin/env python3
"""
Python USB driver for Synaptics/Kensington WBF biometric sensor.

Target: 0x047d:0x00f2 (VeriMark DT Fingerprint Key)
Protocol:
  - USB vendor-specific control transfers for setup exchange
    (bmRequestType 0x40=OUT, 0xc0=IN, requests 0x16/0x17/0x19/0x1a/0x14)
  - After setup, TLS 1.2 ECDHE handshake over control transfers
  - Encrypted application data (AES-128-CBC-HMAC-SHA256) over control transfers
    (uses 0x06/0x07 for encrypted read/write after TLS setup)

Usage:
  python3 sensor.py init        # initial exchange only
  python3 sensor.py list-db     # requires TLS
"""

import struct
import sys
import os
import time

try:
    import usb.core
    import usb.util
except ImportError:
    print("Install pyusb: pip install pyusb")
    sys.exit(1)

SENSOR_VID = 0x047d
SENSOR_PID = 0x00f2
USB_TIMEOUT = 5000

PROTO_TRACE = os.environ.get("PROTO_TRACE")
def proto_log(dir_, layer, data):
    if PROTO_TRACE:
        print(f"[proto] {dir_} dev {layer} len={len(data)} {data.hex()}")

# Control request codes (vendor-specific)
REQ_START  = 0x19   # OUT: start session (wValue=1)
REQ_ACK    = 0x1a   # IN:  read ACK byte
REQ_CMD    = 0x16   # OUT: send command data
REQ_RESP   = 0x17   # IN:  read response data
REQ_READY  = 0x14   # IN:  check ready (returns 0000 when TLS ready)
REQ_ENC_WRITE = 0x06  # OUT: encrypted write (used after TLS)
REQ_ENC_READ  = 0x07  # IN:  encrypted read (used after TLS)
REQ_END    = 0x1b   # OUT: end session

BM_REQ_OUT = 0x40   # Vendor, Host-to-Device, Device
BM_REQ_IN  = 0xc0   # Vendor, Device-to-Host, Device

class SyncSensor:
    def __init__(self, vid=SENSOR_VID, pid=SENSOR_PID):
        self.dev = None
        self.vid = vid
        self.pid = pid

    def find_device(self):
        self.dev = usb.core.find(idVendor=self.vid, idProduct=self.pid)
        if self.dev is None:
            raise RuntimeError(f"Sensor {self.vid:04x}:{self.pid:04x} not found")

    def claim(self):
        cfg = self.dev.get_active_configuration()
        # Detach kernel drivers from both interfaces
        for intf_num in [0, 1]:
            try:
                self.dev.detach_kernel_driver(intf_num)
            except Exception:
                pass
        try:
            self.dev.set_configuration()
        except Exception:
            pass
        usb.util.claim_interface(self.dev, 0)
        usb.util.claim_interface(self.dev, 1)

    def ctrl_out(self, request, value=0, index=0, data=b""):
        bm = BM_REQ_OUT
        wLength = len(data)
        proto_log(">>>", "ctrl_setup",
                  bytes([bm, request]) + struct.pack("<HHH", value, index, wLength))
        if data:
            proto_log(">>>", "enc", data)
        return self.dev.ctrl_transfer(bm, request, value, index, data, timeout=USB_TIMEOUT)

    def ctrl_in(self, request, length, value=0, index=0):
        bm = BM_REQ_IN
        proto_log(">>>", "ctrl_setup",
                  bytes([bm, request]) + struct.pack("<HHH", value, index, length))
        data = bytes(self.dev.ctrl_transfer(bm, request, value, index, length, timeout=USB_TIMEOUT))
        proto_log("<<<", "enc", data)
        return data

    def close(self):
        if self.dev:
            try:
                usb.util.dispose_resources(self.dev)
            except Exception:
                pass

# ---------------------------------------------------------------------------
# Protocol: initial unencrypted exchange (control transfers)
# ---------------------------------------------------------------------------

def initial_exchange(sensor):
    """
    Unencrypted setup exchange over vendor-specific control transfers.
    Returns True when device signals ready for TLS (0000).
    """
    print("[init] starting initial exchange...")

    # Step 1: Start session + read ACK
    sensor.ctrl_out(REQ_START, value=1)
    ack = sensor.ctrl_in(REQ_ACK, length=1, index=1)
    if ack == b"\x01":
        print("[init] ACK received")
    else:
        print(f"[init] expected ACK 01, got {ack.hex()}")
        return False

    # Step 2: Device info request
    sensor.ctrl_out(REQ_CMD, value=1, data=b"\x01\x00\x00\x00\x00\x00\x00\x00")
    resp = sensor.ctrl_in(REQ_RESP, length=0x26)
    serial = resp[14:22].hex() if len(resp) >= 22 else "?"
    print(f"[init] device info ({len(resp)}B): serial={serial}")

    # Step 3: Read certificate (part 1)
    sensor.ctrl_out(REQ_CMD, value=1, data=b"\x8e\x09\x00\x02" + b"\x00" * 20)
    resp = sensor.ctrl_in(REQ_RESP, length=0x10, index=0x80)
    print(f"[init] cert resp 1 ({len(resp)}B): {resp.hex()[:60]}...")

    # Step 4: Read certificate (part 2)
    sensor.ctrl_out(REQ_CMD, value=1, data=b"\x8e\x1a\x00\x02" + b"\x00" * 20)
    resp = sensor.ctrl_in(REQ_RESP, length=0x10, index=0x80)
    print(f"[init] cert resp 2 ({len(resp)}B): {resp.hex()[:60]}...")

    # Step 5: Cert ACK
    sensor.ctrl_out(REQ_CMD, value=1, data=b"\x19\x00\x00\x00\x00\x00\x00\x00")
    resp = sensor.ctrl_in(REQ_RESP, length=0x44)
    print(f"[init] cert ACK ({len(resp)}B): {resp.hex()[:60]}...")

    # Step 6: Ready check
    ready = sensor.ctrl_in(REQ_READY, length=2)
    if ready == b"\x00\x00":
        print("[init] ready for TLS!")
        return True
    else:
        print(f"[init] expected 0000, got {ready.hex()}")
        return False

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(sensor):
    initial_exchange(sensor)

def cmd_list_db(sensor):
    if not initial_exchange(sensor):
        return
    print("[list-db] TLS handshake not yet implemented")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    sensor = SyncSensor()
    try:
        sensor.find_device()
        sensor.claim()
    except RuntimeError as e:
        print(f"Error: {e}")
        sys.exit(1)

    try:
        if cmd == "init":
            cmd_init(sensor)
        elif cmd == "list-db":
            cmd_list_db(sensor)
        else:
            print(f"Unknown command: {cmd}")
    finally:
        sensor.close()

if __name__ == "__main__":
    main()
