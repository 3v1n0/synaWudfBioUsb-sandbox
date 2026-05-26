#!/usr/bin/env python3
"""
Parse proto-trace.log and reconstruct the sensor protocol flow.
Reads [proto] lines, groups into transactions, and attempts to
identify known structs in the plaintext buffers.

Usage:
  PROTO_TRACE=1 ...wine b.exe <cmd>
  ./proto-parse.py [-f /tmp/opencode/proto-trace.log]
"""

import struct
import sys
import re
from collections import OrderedDict

TRACE_FILE = "/tmp/opencode/proto-trace.log"

# ---------------------------------------------------------------------------
# Struct definitions (from sandbox project)
# ---------------------------------------------------------------------------

def parse_winbio_identity(data, offset=0):
    """WINBIO_IDENTITY (0x4c bytes)"""
    id_type = struct.unpack_from("<I", data, offset)[0]
    if id_type == 3:  # GUID type
        guid = struct.unpack_from("<IHH8s", data, offset + 4)
        return {"Type": "GUID", "Data": f"{guid[0]:08x}-{guid[1]:04x}-{guid[2]:04x}-{guid[3].hex()}"}
    elif id_type == 0:
        return {"Type": "Null"}
    elif id_type == 1:
        return {"Type": "Wildcard"}
    else:
        return {"Type": id_type, "Raw": data[offset+4:offset+0x4c].hex()}

STRUCTS = {
    # WINBIO_BLANK_PAYLOAD (8 bytes)
    8: [
        ("BLANK_PAYLOAD", lambda d, o: {
            "PayloadSize": struct.unpack_from("<I", d, o)[0],
            "WinBioHresult": struct.unpack_from("<i", d, o+4)[0],
        }),
    ],
    # WINBIO_SET_INDICATOR (8 bytes)
    8: [
        ("SET_INDICATOR", lambda d, o: {
            "PayloadSize": struct.unpack_from("<I", d, o)[0],
            "Indicator": "ON" if struct.unpack_from("<I", d, o+4)[0] else "OFF",
        }),
    ],
    # WINBIO_GET_INDICATOR (12 bytes)
    12: [
        ("GET_INDICATOR", lambda d, o: {
            "PayloadSize": struct.unpack_from("<I", d, o)[0],
            "WinBioHresult": struct.unpack_from("<i", d, o+4)[0],
            "Indicator": "ON" if struct.unpack_from("<I", d, o+8)[0] else "OFF",
        }),
    ],
    # WINBIO_DIAGNOSTICS (20 bytes minimum)
    20: [
        ("SENSOR_STATUS", lambda d, o: {
            "PayloadSize": struct.unpack_from("<I", d, o)[0],
            "WinBioHresult": struct.unpack_from("<i", d, o+4)[0],
            "SensorStatus": struct.unpack_from("<I", d, o+8)[0],
        }),
    ],
    # WINBIO_CAPTURE_PARAMETERS (28 bytes)
    28: [
        ("CAPTURE_PARAMS", lambda d, o: {
            "PayloadSize": struct.unpack_from("<I", d, o)[0],
            "Purpose": d[o+4],
            "Format": f"{struct.unpack_from('<H', d, o+8)[0]:04x}:{struct.unpack_from('<H', d, o+10)[0]:04x}",
        }),
    ],
    # WINBIO_HOST_UPDATE_ENROLLMENT_WIRE (0x48 = 72 bytes)
    72: [
        ("UPDATE_ENROLLMENT", lambda d, o: {
            "TemplateStatus": struct.unpack_from("<i", d, o)[0],
            "PercentComplete": struct.unpack_from("<I", d, o+0x28)[0],
            "RejectDetail": struct.unpack_from("<I", d, o+0x2c)[0],
            "Fingerprint": {
                "General": struct.unpack_from("<I", d, o+0x30)[0],
                "Center": struct.unpack_from("<I", d, o+0x34)[0],
                "Top": struct.unpack_from("<I", d, o+0x38)[0],
                "Bottom": struct.unpack_from("<I", d, o+0x3c)[0],
                "Left": struct.unpack_from("<I", d, o+0x40)[0],
                "Right": struct.unpack_from("<I", d, o+0x44)[0],
            },
        }),
    ],
    # WINBIO_HOST_CHECK_FOR_DUPLICATE_WIRE (0x50 = 80 bytes)
    80: [
        ("CHECK_DUPLICATE", lambda d, o: {
            "Identity": parse_winbio_identity(d, o),
            "SubFactor": d[o+0x4c],
            "Duplicate": d[o+0x4d],
        }),
    ],
    # WINBIO_HOST_DELETE_RECORD_WIRE (0x50 = 80 bytes)
    80: [
        ("DELETE_RECORD", lambda d, o: {
            "Identity": parse_winbio_identity(d, o),
            "SubFactor": d[o+0x4c],
        }),
    ],
    # WINBIO_IDENTIFY_FEATURE_SET_OUTPUT_WIRE (0x54 = 84 bytes)
    84: [
        ("IDENTIFY_OUTPUT", lambda d, o: {
            "Identity": parse_winbio_identity(d, o),
            "SubFactor": d[o+0x4c],
            "EngineHresult": struct.unpack_from("<i", d, o+0x50)[0],
        }),
    ],
    # WINBIO_HOST_GET_TEMPLATE_INPUT_WIRE (0x54 = 84 bytes)
    84: [
        ("GET_TEMPLATE_INPUT", lambda d, o: {
            "Identity": parse_winbio_identity(d, o),
            "SubFactor": d[o+0x4c],
            "TemplateId": struct.unpack_from("<I", d, o+0x50)[0],
        }),
    ],
    # WINBIO_HOST_COMMIT_ENROLLMENT_INPUT_WIRE (0x60 = 96 bytes)
    96: [
        ("COMMIT_ENROLLMENT_INPUT", lambda d, o: {
            "Identity": parse_winbio_identity(d, o),
            "SubFactor": d[o+0x4c],
            "PayloadBlobSize": struct.unpack_from("<Q", d, o+0x50)[0],
        }),
    ],
}

def guess_struct(data):
    """Try to identify known struct by data length + content."""
    n = len(data)
    if n in STRUCTS:
        for name, parser in STRUCTS[n]:
            try:
                fields = parser(data, 0)
                return name, fields
            except:
                pass
    return None, None


# ---------------------------------------------------------------------------
# Trace parser
# ---------------------------------------------------------------------------

LINE_RE = re.compile(
    r"^\[proto\]\s+(?P<dir>>>|<<<|\.\.\.)\s+dev\s+(?P<layer>\w+)\s+len=(?P<len>\d+)\s+(?P<hex>[0-9a-fA-F]+)"
)

def parse_line(line):
    m = LINE_RE.match(line)
    if not m:
        return None
    raw = bytes.fromhex(m.group("hex"))
    if len(raw) != int(m.group("len")):
        return None
    dir_str = f"{m.group('dir')} dev"
    return {
        "dir": dir_str,
        "layer": m.group("layer"),
        "len": len(raw),
        "data": raw,
    }


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def fmt_hex(data, maxbytes=64):
    s = data[:maxbytes].hex()
    if len(data) > maxbytes:
        s += f"...({len(data)} bytes total)"
    return s

def fmt_hr(hr):
    """Format Windows HRESULT in readable form."""
    names = {
        0x00000000: "S_OK",
        0x80070002: "UNKNOWN",
        0x80098010: "WINBIO_E_DEVICE_BUSY",
        0x8009801e: "WINBIO_E_DUPLICATE_ENROLLMENT",
    }
    return names.get(hr, f"0x{hr:08x}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    path = sys.argv[2] if len(sys.argv) > 2 and sys.argv[1] == "-f" else TRACE_FILE

    try:
        with open(path) as f:
            lines = [parse_line(l) for l in f if l.startswith("[proto]")]
    except FileNotFoundError:
        print(f"Trace file not found: {path}")
        print("Run with PROTO_TRACE=1 first, or specify: ./proto-parse.py -f <file>")
        sys.exit(1)

    lines = [l for l in lines if l]
    if not lines:
        print("No [proto] lines found in", path)
        sys.exit(0)

    print(f"Parsed {len(lines)} trace lines from {path}")
    print()

    # Walk the trace and group into transactions.
    # A transaction is: request [plain+enc] -> response [enc+plain]
    # But ordering is interleaved, so we match by proximity.
    #
    # Typical host->device: [>>> plain ... >>> enc]  (plain then enc, nearby)
    # Typical device->host: [<<< enc ... <<< plain]  (enc then plain, nearby)
    #
    # We consume the trace sequentially.  At each step:
    #   >>> plain -> expect >>> enc soon after -> that's a host command
    #   >>> enc   -> if no plain nearby, it's an unencrypted control cmd
    #   <<< enc   -> expect <<< plain soon after -> that's a device response
    #   <<< plain -> orphan (shouldn't happen, but handle gracefully)

    i = 0
    n = len(lines)
    tx_idx = 0

    def peek(j, d, layer):
        return j < n and lines[j]["dir"] == d and lines[j]["layer"] == layer

    def consume_enc_response(j):
        """Consume <<< lines starting at j, return new index."""
        while j < n and lines[j]["dir"] == "<<< dev":
            if lines[j]["layer"] == "enc":
                print(f"  DEVICE -> HOST enc ({lines[j]['len']}B)")
                print(f"    Wire: {fmt_hex(lines[j]['data'])}")
            elif lines[j]["layer"] == "plain":
                name, fields = guess_struct(lines[j]["data"])
                print(f"  DEVICE -> HOST plain ({lines[j]['len']}B)")
                if name:
                    print(f"    Struct: {name}")
                    for k, v in fields.items():
                        if isinstance(v, dict):
                            print(f"      {k}:")
                            for sk, sv in v.items():
                                print(f"        {sk}: {sv}")
                        else:
                            print(f"      {k}: {v}")
                else:
                    print(f"    Raw: {fmt_hex(lines[j]['data'])}")
                    if lines[j]['len'] >= 4:
                        hr = struct.unpack_from("<i", lines[j]['data'], 0)[0]
                        if hr == 0 or hr < 0:
                            print(f"    HRESULT: {fmt_hr(hr)}")
            j += 1
        return j

    while i < n:
        l = lines[i]
        tag = (l["dir"], l["layer"])

        # Host command with plaintext - most informative
        if tag == (">>> dev", "plain"):
            tx_idx += 1
            print(f"--- TX #{tx_idx} ------------------------------------------------------------")
            name, fields = guess_struct(l["data"])
            print(f"  HOST -> DEVICE plain ({l['len']}B)")
            if name:
                print(f"    Struct: {name}")
                for k, v in fields.items():
                    if isinstance(v, dict):
                        print(f"      {k}:")
                        for sk, sv in v.items():
                            print(f"        {sk}: {sv}")
                    else:
                        print(f"      {k}: {v}")
            else:
                print(f"    Raw: {fmt_hex(l['data'])}")
                if l['len'] >= 1:
                    print(f"    cmd=0x{l['data'][0]:02x}")

            # Next >>> enc that follows immediately
            if peek(i+1, ">>> dev", "enc"):
                print(f"  HOST -> DEVICE enc ({lines[i+1]['len']}B)")
                print(f"    Wire: {fmt_hex(lines[i+1]['data'])}")
                i = consume_enc_response(i+2)
            else:
                i = consume_enc_response(i+1)
            print()

        # Host-to-device enc only (no plain) - unencrypted control
        elif tag == (">>> dev", "enc"):
            tx_idx += 1
            print(f"--- TX #{tx_idx} (control) -------------------------------------------------")
            print(f"  HOST -> DEVICE enc ({l['len']}B)")
            print(f"    Wire: {fmt_hex(l['data'])}")
            i = consume_enc_response(i+1)
            print()

        # Key material / metadata (neutral direction)
        elif tag[0] == "... dev" and tag[1] in ("ecdh-secret", "tls-prf", "secret", "key", "iv"):
            print(f"  KEY {tag[1]} ({l['len']}B): {l['data'].hex()}")
            i += 1
            print()

        # Device-to-host enc (could be event or unsolicited)
        elif tag == ("<<< dev", "enc"):
            tx_idx += 1
            print(f"--- TX #{tx_idx} (device -> host) ------------------------------------------")
            print(f"  DEVICE -> HOST enc ({l['len']}B)")
            print(f"    Wire: {fmt_hex(l['data'])}")
            # Look ahead for matching <<< plain
            if peek(i+1, "<<< dev", "plain"):
                name, fields = guess_struct(lines[i+1]["data"])
                print(f"  DEVICE -> HOST plain ({lines[i+1]['len']}B)")
                if name:
                    print(f"    Struct: {name}")
                    for k, v in fields.items():
                        print(f"      {k}: {v}")
                else:
                    print(f"    Raw: {fmt_hex(lines[i+1]['data'])}")
                i += 2
            else:
                i += 1
            print()

        # Orphaned plain (shouldn't happen)
        elif tag == ("<<< dev", "plain"):
            tx_idx += 1
            print(f"--- TX #{tx_idx} (orphan plain) --------------------------------------------")
            name, fields = guess_struct(l["data"])
            print(f"  DEVICE -> HOST plain ({l['len']}B)")
            if name:
                print(f"    Struct: {name}")
                for k, v in fields.items():
                    print(f"      {k}: {v}")
            else:
                print(f"    Raw: {fmt_hex(l['data'])}")
            i += 1
            print()

        else:
            print(f"  ??? unexpected tag: {tag}")
            i += 1


if __name__ == "__main__":
    main()
