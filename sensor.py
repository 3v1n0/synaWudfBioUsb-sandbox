#!/usr/bin/env python3
"""
Python USB driver for Synaptics/Kensington WBF biometric sensor (047d:00f2).

Protocol summary:
  Phase 1: REQ_START + init_cmds (retried only if device still booting)
  Phase 2: REQ_READY -- returns 0000 (challenge is optional)
  Phase 3: TLS 1.2 handshake over custom USB framing
  Phase 4: Encrypted IOCTL biometric commands (AES-256-GCM)

Key derivation (confirmed from native Wine trace):
  Cipher suite: 0xc02e (driver uses AES-256-GCM internally)
  ECDH(client_ephemeral, device_pub_ECK1) -> ecdh_x (32 bytes)
  master = PRF_SHA384(ecdh_x, "master secret", cli_rand + srv_rand, 48)
  key_mat = PRF_SHA384(master, "key expansion", cli_rand + srv_rand, 72)
    client_enc = km[0:32]    AES-256 key
    server_enc = km[32:64]   AES-256 key
    client_iv4 = km[64:68]   4-byte implicit IV prefix
    server_iv4 = km[68:72]   4-byte implicit IV prefix
  GCM nonce (12 bytes) = implicit_iv4(4) + explicit_random(8)
  TLS record body = explicit_random(8) + ciphertext + tag(16)
  AAD = seq_num(8) + content_type(1) + TLS_VER(2) + plain_len(2)
  verify_data = PRF_SHA384(master, "client finished", hs_hash_sha256, 12)

Certificate body (402 bytes total, device reads 400):
  [0:2]    run_marker = cli_rand[4:6]
  [2:402]  PairingData tag=1 verbatim (400 bytes):
             [0:142]   host public key blob (see below)
             [140:142] sep 00 02
             [142:144] u16le len 20 00 (= 32)
             [144:176] pub_key32 (32 bytes, from device pairing)
             [176:400] zero padding

host public key blob (142 bytes):
  [0:4]    3f5f1700
  [4:36]   ECS2 public X (LE, 32 bytes)
  [36:72]  zero padding (36 bytes)
  [72:104] ECS2 public Y (LE, 32 bytes)
  [104:142] zero padding (38 bytes)

PairingData (local file or Wine registry):
  tag=1: 400-byte host cert body (host public key blob + header + pub_key + zeros)
  tag=2: 32-byte ECS2 private key D (LE)
  tag=3: 400-byte device cert body (same structure as tag 1)
  tag=4: 420-byte unknown
  tag=0: 2-byte unknown

USB wValue map (confirmed from windows driver trace):
  Init cmds (plain):  OUT CH_INIT=1  / IN CH_PLAIN=0 (cert reads: IN CH_IN_CERT=0x8000)
  ClientHello:        OUT CH_TLS=4   / IN CH_PLAIN=0
  Bundle (rest of hs):OUT CH_PLAIN=0 / IN CH_PLAIN=0
  GET_RECORD_COUNT:   OUT CH_SENSOR=6 / IN CH_PLAIN=0
  STORAGE_QUERY_INIT: OUT CH_STORE=7  / IN CH_PLAIN=0
  STORAGE_QUERY_ALL:  OUT CH_DATA=2   / IN CH_PLAIN=0
  FETCH_RECORD:       OUT CH_DATA=2   / IN CH_PLAIN=0

Class hierarchy:
  Sensor        -- USB transport layer (ctrl_out / ctrl_in)
  SensorTLS     -- extends Sensor; adds TLS 1.2 handshake
  BiometricSensor -- extends SensorTLS; adds fingerprint commands

Usage:
  lxc exec kensington-playground -- python3 sensor.py list-db
  SENSOR_TRACE=1 ... python3 sensor.py list-db
"""

import os, sys, struct, hashlib, hmac as _hmac, re, ssl
import enum, getpass
from datetime import datetime
from collections import namedtuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

try:
    import usb.core
except ImportError:
    print("Install pyusb: pip install pyusb")
    sys.exit(1)


# ---------------------------------------------------------------------------
# TLS Alert error
# ---------------------------------------------------------------------------

class TlsAlertError(RuntimeError):
    """Device returned a TLS alert during handshake or encrypted session."""

    @staticmethod
    def desc_name(code):
        try:
            return ssl.AlertDescription(code).name
        except ValueError:
            return f'0x{code:02x}'

    @staticmethod
    def level_name(level):
        return {TLS_ALERT_WARNING: 'warning',
                TLS_ALERT_FATAL:   'fatal'}.get(level, f'level={level}')

    def __init__(self, level, code, extra=""):
        msg = (f"TLS Alert: {TlsAlertError.level_name(level)}"
               f" {TlsAlertError.desc_name(code)}")
        if extra:
            msg += f" {extra}"
        super().__init__(msg)
        self.level = level
        self.code = code


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

USB_ID       = os.environ.get("USB_ID", "047d:00f2")
USB_TIMEOUT  = 10000   # ms
SENSOR_TRACE = os.environ.get("SENSOR_TRACE", "0") == "1"

# Deterministic RNG for replay/comparison against windows driver trace
_DET_RNG = os.environ.get("PROTO_DETERMINISTIC_RNG", "0") == "1"
_det_ctr = 0

def _rand(n):
    global _det_ctr
    if not _DET_RNG:
        return os.urandom(n)
    VALS = [
        bytes.fromhex(
            '11706a5ba84658230d9017644cfe77ab'
            '4e21f028d347d48c59cb44f1c67cce80'),
        bytes.fromhex(
            '4d3739abead420f73aa76ae680f875f9'
            'db593ac59c7471ab1740dc0e4a8976f2'),
        bytes.fromhex('a865ca0589a97663'),
    ]
    for v in VALS:
        if len(v) == n and _det_ctr < len(VALS):
            val = VALS[_det_ctr]; _det_ctr += 1
            return val
    return bytes(n)

# ---------------------------------------------------------------------------
# USB request codes
# ---------------------------------------------------------------------------

# Parsed result of a LOAD_TEMPLATE (a103) response.
TemplateInfo   = namedtuple('TemplateInfo',   ['guid', 'sid', 'label', 'subfactor'])
RecordInfo     = namedtuple('RecordInfo',     ['handle'])
SelectInfo     = namedtuple('SelectInfo',     ['handle', 'guid'])
CaptureStatus  = namedtuple('CaptureStatus',  ['sensor_status', 'reject_detail'])
CaptureData    = namedtuple('CaptureData',    ['sensor_status', 'reject_detail', 'ctx', 'raw'])
SensorStatus   = namedtuple('SensorStatus',   ['mode', 'sample', 'quality', 'context'])
EnrollStatus   = namedtuple('EnrollStatus',   ['status', 'guid', 'sample_cnt',
                                               'progress_sum', 'samples_used', 'size_flag'])
MatchResult    = namedtuple('MatchResult',    ['status', 'guid', 'score', 'index',
                                               'strength', 'template_update'])
TemplateStatus = namedtuple('TemplateStatus', ['status', 'percent_complete', 'reject_detail'])

StatusExt      = namedtuple('StatusExt',      ['progress'])
EntryInfo      = namedtuple('EntryInfo',      ['flags', 'record_ref'])
RecordToEntry  = namedtuple('RecordToEntry',  ['entry_handle'])
DeleteResult   = namedtuple('DeleteResult',   ['status'])
DeviceInfo     = namedtuple('DeviceInfo',     ['serial', 'firmware_major', 'firmware_minor', 'raw'])
CertSection    = namedtuple('CertSection',    ['section', 'raw'])
BootStatus     = namedtuple('BootStatus',     ['state', 'raw'])

# DeleteResult.status values
DELETE_STATUS_EMPTY = 0x00000100   # entry had no data
DELETE_STATUS_OK    = 0x00000300   # entry deleted successfully

NULL_GUID = b'\x00' * 16   # 16 zero bytes -- "no GUID" sentinel

# Finger position enum, matching libfprint FpFinger values.
class FpFinger(enum.IntEnum):
    UNKNOWN      = 0
    LEFT_THUMB   = 1
    LEFT_INDEX   = 2
    LEFT_MIDDLE  = 3
    LEFT_RING    = 4
    LEFT_LITTLE  = 5
    RIGHT_THUMB  = 6
    RIGHT_INDEX  = 7
    RIGHT_MIDDLE = 8
    RIGHT_RING   = 9
    RIGHT_LITTLE = 10

REQ_START        = 0x19   # OUT -- phase 1 init signal
REQ_INIT_ACK     = 0x1a   # IN  -- phase 1 init acknowledgment
REQ_CMD          = 0x16   # OUT -- send command
REQ_RESP         = 0x17   # IN  -- read response
REQ_READY        = 0x14   # IN  -- ready check (also used as REQ_SHUTDOWN_ACK)
REQ_SHUTDOWN     = 0x1b   # OUT -- vendor shutdown
REQ_SHUTDOWN_ACK = 0x14   # IN  -- shutdown acknowledgment (same code as REQ_READY)
BM_OUT, BM_IN = 0x40, 0xc0

# Pairing-data TLV tag numbers
TLV_CLIENT_CERT    = 1  # 400-byte host certificate (client TLS cert body)
TLV_CLIENT_PRIVKEY = 2  # 32-byte host ECDSA private key D (LE)
TLV_DEVICE_CERT    = 3  # 400-byte device certificate (contains ECK1 pubkey)

# ---------------------------------------------------------------------------
# TLS constants
# ---------------------------------------------------------------------------

TLS_VER       = b'\x03\x03'
TLS_HANDSHAKE = 0x16
TLS_CHANGE_CS = 0x14
TLS_APP_DATA  = 0x17
TLS_ALERT     = 0x15

# ---------------------------------------------------------------------------
# TLS constants
# ---------------------------------------------------------------------------

TLS_VER       = b'\x03\x03'
TLS_HANDSHAKE = 0x16
TLS_CHANGE_CS = 0x14
TLS_APP_DATA  = 0x17
TLS_ALERT     = 0x15

# TLS alert levels (RFC 5246 section 7.2)
TLS_ALERT_WARNING = 1
TLS_ALERT_FATAL   = 2

# TLS handshake message types (RFC 5246 section 7.4)
TLS_HS_CLIENT_HELLO        = 0x01
TLS_HS_SERVER_HELLO        = 0x02
TLS_HS_CERTIFICATE         = 0x0b
TLS_HS_CERTIFICATE_REQUEST = 0x0d
TLS_HS_SERVER_HELLO_DONE   = 0x0e
TLS_HS_CERTIFICATE_VERIFY  = 0x0f
TLS_HS_CLIENT_KEY_EXCHANGE = 0x10
TLS_HS_FINISHED            = 0x14

# Cipher suites advertised in ClientHello (exact order matches Windows driver)
CS_ECDH_ECDSA_AES256_CBC_SHA      = b'\xc0\x05'
CS_ECDHE_ECDSA_AES256_GCM_SHA384  = b'\xc0\x2e'  # selected by device
CS_RSA_AES256_CBC_SHA256           = b'\x00\x3d'
CS_DHE_PSK_AES256_CBC_SHA          = b'\x00\x8d'
CS_PSK_AES256_CBC_SHA              = b'\x00\xa8'
CS_DHE_PSK_AES256_CBC_SHA256       = b'\x00\xa9'

CIPHER_SUITE = CS_ECDHE_ECDSA_AES256_GCM_SHA384  # alias used in key derivation

# 4-byte IOCTL framing header prepended to TLS records sent to device
IOCTL_HDR = b'\x44\x00\x00\x00'

# ---------------------------------------------------------------------------
# App-layer command descriptors
#
# All commands sent via tls_send() follow one of these structural shapes:
#
#   FIXED   -- entire payload is a constant blob, no arguments
#   HANDLE  -- 2-byte opcode + 3 zero pad + 16-byte handle/GUID argument
#   PARAM   -- command with a single small integer parameter at a fixed offset
#
# The 'value' field is the TLS channel selector (REQ_CMD wValue):
#   2 = data-plane  (engine, storage queries, capture, match, enroll)
#   6 = sensor ctrl (status, counters, update-check, ack)
#   7 = storage/session admin (init, commit, finalise, close)

#
# Each Cmd instance exposes a build() method returning the payload bytes.
# ---------------------------------------------------------------------------

class Cmd:
    """Descriptor for a fixed-layout app-layer command."""

    def __init__(self, opcode, channel, body=b'', label="", sep=b'\x00\x00\x00'):
        """
        opcode -- 1 or 2 bytes identifying the command (cmd + subcmd)
        channel  -- TLS channel selector (2, 6 or 7)
        body   -- fixed payload bytes that follow sep+opcode (may be empty)
        label  -- default trace label; can be overridden in send()
        sep    -- separator between opcode and body/arg, meaning unknown.
                  Defaults to 3 zero bytes (_SEP3), present in almost all
                  commands.  Pass b'' for commands with no separator, or a
                  custom value (e.g. SENSOR_STATUS uses b'\x00\x20\x00').
        """
        self.opcode = opcode
        self.channel = channel
        self.body   = body
        self.label  = label
        self.sep    = sep

    def build(self, arg=b''):
        """Return the full payload bytes.
        Layout: opcode | sep | body | arg
        sep is omitted when both body and arg are empty (opcode-only cmds)."""
        sep = self.sep if (self.body or arg) else b''
        return self.opcode + sep + self.body + arg

    def send(self, dev, arg=b'', label=None, ctype=TLS_APP_DATA):
        """Build and send via dev.tls_send(); returns response.
        label overrides the default cmd label when provided and non-empty."""
        return dev.tls_send(self.build(arg), channel=self.channel,
                            label=label if label else self.label,
                            ctype=ctype)


# USB wValue channel selectors (OUT direction unless noted)
CH_PLAIN   = 0        # unencrypted transfers: all IN reads, TLS bundle OUT
CH_INIT    = 1        # plain init commands OUT
CH_DATA    = 2        # data-plane app commands OUT
CH_TLS     = 4        # ClientHello / TLS handshake start OUT
CH_SENSOR  = 6        # sensor/engine control OUT
CH_STORE   = 7        # storage/admin commands OUT
CH_IN_CERT = 0x8000   # IN direction for cert-section reads during init

# --- Sensor / engine control (value=6) ---
CMD_GET_RECORD_COUNT     = Cmd(b'\x82', CH_SENSOR,
                               b'\x00\x00\x00\x02\x07',
                               label="GET_RECORD_COUNT")
CMD_SENSOR_STATUS        = Cmd(b'\x87', CH_SENSOR,
                               b'\x01\x00\x00\x00',
                               label="SENSOR_STATUS", sep=b'\x00\x20\x00')
CMD_UPDATE_ENROLL_CHECK  = Cmd(b'\x80\x0c', CH_SENSOR,
                               b'\x01\x00\x00\x00'
                               b'\x01\x00\x00\x08\x01\x01\x01\x00',
                               label="UPDATE_ENROLL_CHECK")
CMD_UPDATE_IDENT_CHECK   = Cmd(b'\x80\x14', CH_SENSOR,
                               b'\x01\x00\x00\x00'
                               b'\x01\x00\x00\x08\x01\x01\x01\x00',
                               label="UPDATE_IDENT_CHECK")
CMD_UPDATE_ACK           = Cmd(b'\x81', CH_SENSOR, label="UPDATE_ACK")

# --- Storage queries / fetch (value=2, handle arg) ---
CMD_FETCH_FIRST          = Cmd(b'\x9f\x01', CH_DATA,  b'\x00' * 16,
                               label="FETCH_FIRST")
CMD_STORAGE_QUERY_ALL    = Cmd(b'\x9f\x02', CH_DATA,  b'\xff' * 16,
                               label="STORAGE_QUERY_ALL")
CMD_FETCH_RECORD         = Cmd(b'\x9f\x03', CH_DATA,
                               label="FETCH_RECORD")        # + guid/handle
CMD_SELECT_ENTRY         = Cmd(b'\xa0\x01', CH_DATA,
                               label="SELECT_ENTRY")        # + entry handle
CMD_SELECT_RECORD        = Cmd(b'\xa0\x03', CH_DATA,
                               label="SELECT_RECORD")       # + record handle
CMD_LOAD_TEMPLATE        = Cmd(b'\xa1\x03', CH_DATA,
                               label="LOAD_TEMPLATE")       # + record handle
CMD_RECORD_TO_ENTRY      = Cmd(b'\xa2\x01', CH_DATA,
                               label="RECORD_TO_ENTRY")     # + record handle
CMD_DELETE_ENTRY         = Cmd(b'\xa3\x01', CH_DATA,
                               label="DELETE_ENTRY")        # + entry handle

# --- Enroll lifecycle (value=2) ---
CMD_ENROLL_BEGIN         = Cmd(b'\x96\x01', CH_DATA,
                               b'\x00\x00\x00\x00\x00\x00\x00\x00',
                               label="ENROLL_BEGIN")
CMD_ENROLL_STATUS        = Cmd(b'\x96\x02', CH_DATA,
                               b'\x00\x00\x00', label="ENROLL_STATUS", sep=b'')
CMD_ENGINE_COMMIT_ACK    = Cmd(b'\x96\x04', CH_DATA,
                               b'\x00\x00\x00', label="ENGINE_COMMIT_ACK", sep=b'')
CMD_MATCH_RESULT         = Cmd(b'\x99\x01', CH_DATA,
                               b'\x00\x00\x00\x00\x00\x00\x00\x00',
                               label="MATCH_RESULT")

# --- Storage / admin (value=7) ---
CMD_STORAGE_QUERY_INIT   = Cmd(b'\x9e\x01', CH_STORE, label="STORAGE_QUERY_INIT")
# Storage wipe finalise sequence (a401/a402/a403, Windows driver clear-db compat)
CMD_STORAGE_WIPE_1       = Cmd(b'\xa4\x01', CH_STORE, label="STORAGE_WIPE_1")
CMD_STORAGE_WIPE_2       = Cmd(b'\xa4\x02', CH_STORE, label="STORAGE_WIPE_2")
CMD_STORAGE_WIPE_3       = Cmd(b'\xa4\x03', CH_STORE, label="STORAGE_WIPE_3")
# TLS session teardown -- must be sent as a TLS Alert record, not app data
CMD_CLOSE_NOTIFY         = Cmd(b'\x00\x01', CH_STORE, label="CLOSE_NOTIFY")

# --- Query / template (value=2, fixed 125-byte payloads) ---
CMD_QUERY_ENROLL_NEEDS   = Cmd(b'\x39', CH_DATA,
                               bytes.fromhex(
                                   '00710200ffff0000057f0020000000'
                                   '007f7f000000000000ffff0000057f00'
                                   '20000000007f7f000000000000ffff00'
                                   '00057f0020000000007f7f0000000000'
                                   '00000000000000000000000000000000'
                                   '00000000000000000000000000000000'
                                   '00000000000000000000000000000000'
                                   '00000000000000000000000000'),
                               label="QUERY_ENROLL_NEEDS", sep=b'')
CMD_QUERY_ENROLL_SIMPLE  = Cmd(b'\x39', CH_DATA,
                               bytes.fromhex(
                                   '000000000000000020000000'
                                   '00000000000000000000000000000000'
                                   '20000000000000000000000000000000'
                                   '00000000200000000000000000000000'
                                   '00000000000000002000000000000000'
                                   '00000000000000000000000020000000'
                                   '00000000000000000000000000000000'
                                   '20000000000000000000000000'),
                               label="QUERY_ENROLL_SIMPLE")
CMD_ENROLL_TEMPLATE      = Cmd(b'\x39', CH_DATA,
                               bytes.fromhex(
                                   'f4010000f4010000077f0020000000'
                                   '007f7f00000000000000000000000000'
                                   '20000000000000000000000000f40100'
                                   '00007f00200000000000000000000000'
                                   '00000000000000002000000000000000'
                                   '00000000000000000000000000000000'
                                   '00000000000000000000000000000000'
                                   '00000000000000000000000000'),
                               label="ENROLL_TEMPLATE", sep=b'')

# STORAGE_COMMIT (9603) payload is variable-length (built by _build_commit_payload)
CMD_STORAGE_COMMIT       = Cmd(b'\x96\x03', CH_STORE, label="STORAGE_COMMIT", sep=b'')

# CAPTURE_DATA: 86 <subfactor> 00*15 <subfactor> 00*19 (37B)
# subfactor is a WINBIO_ANSI_381_POS_* subtype; payload built by capture_data()
# Full 37-byte payload: 86 06 00*15 06 00*19
# Byte[1] and byte[17] are an opaque mode field (not a SubFactor).
# Empirically confirmed values:
#   0x02 -- works but LED only lights on finger touch, not on arm
#   0x04 -- works, LED lights immediately when sensor is armed
#   0x06 -- works, LED lights immediately when armed (driver default)
# Values 0x01,0x03,0x05,0x07,0x08,0x10,0x20,0x40,0x80 all rejected.
# Driver hardcodes eventMask=0x180 in CCaptureImage producing 0x06.
CMD_CAPTURE_DATA         = Cmd(b'\x86', CH_DATA,
                               body=b'\x00' * 13 + b'\x06' + b'\x00' * 19,
                               sep=b'\x06\x00\x00', label="CAPTURE_DATA")
# STATUS_EXT param=4: 86 00 <00*31> 04000000 (37B)
CMD_STATUS_EXT_4         = Cmd(b'\x86', CH_DATA,
                               b'\x00' * 31 + b'\x04\x00\x00\x00',
                               label="STATUS_EXT(param=4)", sep=b'\x00')
# STATUS_EXT param=1: 86 00 0000 01000000 00*12 01000000 00*13 (37B)
CMD_STATUS_EXT_1         = Cmd(b'\x86', CH_DATA,
                               b'\x00\x00'
                               + b'\x01\x00\x00\x00' + b'\x00' * 12
                               + b'\x01\x00\x00\x00' + b'\x00' * 13,
                               label="STATUS_EXT(param=1)", sep=b'\x00')



# ---------------------------------------------------------------------------
# Identity key (P_SHA256 D) - for challenge signature only
# ---------------------------------------------------------------------------

# Derived from P_SHA256(hardcoded_constants, "HS_KEY_PAIR_GEN")
# key=first16_hardcoded, seed=last16_hardcoded+aaaa, hash=SHA256
def _derive_identity_key():
    import hashlib, hmac
    blob = bytes.fromhex(
        '717cd72d0962bc4a2846138dbb2c2419'
        '2512a76407065f383846139d4bec2033')
    k = blob[:16]
    s = blob[16:] + bytes([0xaa, 0xaa])
    label = b'HS_KEY_PAIR_GEN'
    seed_in = label + s
    a = hmac.new(k, seed_in, hashlib.sha256).digest()
    res = b''
    while len(res) < 32:
        res += hmac.new(k, a + seed_in, hashlib.sha256).digest()
        a = hmac.new(k, a, hashlib.sha256).digest()
    return res[:32]  # D as LE bytes

IDENTITY_D_LE = _derive_identity_key()
IDENTITY_D_BE = bytes(reversed(IDENTITY_D_LE))

from ecdsa import NIST256p

# Device static ECDH public key is obtained from Tag3 (device cert)
# during the challenge/pairing flow - never hardcoded.

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def _log(msg, *args):
    """Print sensor-detail trace (only if SENSOR_TRACE=1)."""
    if SENSOR_TRACE:
        print(f"[sensor] {msg}", *args)

def _hexdump(label, data, maxlen=256):
    if not SENSOR_TRACE:
        return
    s = data[:maxlen].hex()
    if len(data) > maxlen:
        s += f"...({len(data)}B)"
    print(f"  {label}: {s}")

# ---------------------------------------------------------------------------
# PairingData store (local file, fallback to Wine registry)
# ---------------------------------------------------------------------------

PAIRING_FILE = (os.environ.get("PAIRING_FILE")
                or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "pairing.dat"))
WINE_DPAPI_SECRET = b"I'm hunting wabbits"


def _save_pairing_tlv(tlvs):
    """Save TLV dict {tag: bytes} to local pairing.dat."""
    data = b''
    for tag in sorted(tlvs):
        val = tlvs[tag]
        data += struct.pack('<HI', tag, len(val)) + val
    try:
        with open(PAIRING_FILE, 'wb') as fh:
            fh.write(data)
        _log(f"Saved PairingData to {PAIRING_FILE}")
        return True
    except OSError as exc:
        _log(f"WARN: could not save {PAIRING_FILE}: {exc}")
        return False


def _parse_pairing_tlv(raw):
    """Parse TLV blob -> {tag: bytes}."""
    off, out = 0, {}
    while off + 6 <= len(raw):
        tag    = struct.unpack_from('<H', raw, off)[0]
        length = struct.unpack_from('<I', raw, off + 2)[0]
        out[tag] = raw[off + 6: off + 6 + length]
        off += 6 + length
    return out


def _load_pairing_from_file():
    try:
        return _parse_pairing_tlv(open(PAIRING_FILE, 'rb').read())
    except OSError:
        return None


def _load_pairing_blob_from_registry(reg_path=None):
    wine_prefix = os.environ.get("WINEPREFIX",
                                  os.path.expanduser("~/.wine"))
    path = (reg_path
            or os.environ.get("PAIRING_REG")
            or os.path.expanduser(f"{wine_prefix}/user.reg"))
    try:
        lines = open(path, "r", encoding="utf-8",
                     errors="ignore").read().splitlines()
    except OSError:
        return None
    marker = '"56FB88ED27E90000"=hex:'
    start = -1
    for i, line in enumerate(lines):
        if marker.lower() in line.lower():
            start = i
            first = line.split(marker, 1)[1].strip()
            break
    if start < 0:
        return None
    chunks = [first]
    for j in range(start + 1, len(lines)):
        nxt = lines[j]
        if not nxt.startswith("  "):
            break
        chunks.append(nxt.strip().lstrip())
        if not nxt.rstrip().endswith("\\"):
            break
    csv = "".join(chunks).replace("\\", "")
    vals = [v for v in csv.split(",")
            if v and re.fullmatch(r"[0-9a-fA-F]{2}", v)]
    return bytes(int(v, 16) for v in vals)


def _parse_wine_pairing_wrapper(blob):
    if not blob or len(blob) < 16:
        return None
    ver, zero, len1, len2 = struct.unpack_from("<IIII", blob, 0)
    if ver != 1:
        return None
    total = 16 + len1 + len2
    if total > len(blob):
        return None
    return {"blob1": blob[16:16 + len1],
            "blob2": blob[16 + len1:16 + len1 + len2]}


def _parse_wine_protectdata_blob(blob):
    if not blob or len(blob) < 64:
        return None
    i = 0
    def u32():
        nonlocal i
        if i + 4 > len(blob):
            raise ValueError
        v = struct.unpack_from("<I", blob, i)[0]; i += 4
        return v
    try:
        u32(); i += 16; u32(); i += 16; u32()
        desc_len = u32(); i += desc_len
        u32(); u32(); data0_len = u32(); i += data0_len
        u32(); u32(); u32()
        salt_len = u32(); salt = blob[i:i + salt_len]; i += salt_len
        cipher_len = u32(); cipher = blob[i:i + cipher_len]; i += cipher_len
        fp_len = u32(); i += fp_len
    except (ValueError, struct.error):
        return None
    return {"salt": salt, "cipher": cipher}


def _derive_wine_3des_key(username_bytes, salt):
    h = hashlib.sha1()
    h.update(username_bytes); h.update(WINE_DPAPI_SECRET); h.update(salt)
    base = h.digest()
    pad1 = bytes((0x36 ^ (base[k] if k < len(base) else 0)) for k in range(64))
    pad2 = bytes((0x5C ^ (base[k] if k < len(base) else 0)) for k in range(64))
    return (hashlib.sha1(pad1).digest() + hashlib.sha1(pad2).digest())[:24]


def _wine_unprotect_blob(blob, username_bytes):
    parsed = _parse_wine_protectdata_blob(blob)
    if not parsed:
        return None
    key = _derive_wine_3des_key(username_bytes, parsed["salt"])
    dec = Cipher(algorithms.TripleDES(key), modes.CBC(b"\x00" * 8),
                 backend=default_backend()).decryptor()
    pt = dec.update(parsed["cipher"]) + dec.finalize()
    if pt:
        pad = pt[-1]
        if 1 <= pad <= 8 and pt.endswith(bytes([pad]) * pad):
            pt = pt[:-pad]
    return pt


def _decrypt_pairing_data(blob):
    wrapped = _parse_wine_pairing_wrapper(blob)
    if not wrapped:
        return None
    user = os.environ.get("DPAPI_USER", os.environ.get("USER", "ubuntu"))
    username_bytes = user.encode("ascii", errors="ignore") + b"\x00"
    return _wine_unprotect_blob(wrapped["blob1"], username_bytes)


def load_pairing_data():
    """
    Load PairingData TLV dict from local file or Wine registry.
    Returns {tag: bytes} or None.
    """
    use_wine = "USE_WINE_PAIRING_DATA" in os.environ

    if not use_wine:
        tlvs = _load_pairing_from_file()
        if tlvs is not None:
            return tlvs
        return None

    blob = _load_pairing_blob_from_registry()
    if blob:
        plain = _decrypt_pairing_data(blob)
        if plain:
            return _parse_pairing_tlv(plain)
    return None


def get_pairing_fields(tlvs):
    """
    Unpack pairing-data TLV dict into structured fields.

    Returns (host_pubkey, client_privkey_le, client_cert,
             dev_x_be, dev_y_be, client_pubkey_x_le)
    or None if Tag1 is missing/invalid.
    Device ECDH static key must be present in Tag 3.
    """
    client_cert = tlvs.get(TLV_CLIENT_CERT)
    if not client_cert or len(client_cert) < 142:
        return None
    if client_cert[:4] != b'\x3f\x5f\x17\x00':
        return None
    host_pubkey          = client_cert[:142]
    client_privkey_le = tlvs.get(TLV_CLIENT_PRIVKEY, b'\x00' * 32)
    client_pubkey_x_le = (client_cert[144:176]
                          if len(client_cert) >= 176 else b'\x00' * 32)
    # Device ECDH static key from Tag 3 (device certificate)
    device_cert = tlvs.get(TLV_DEVICE_CERT)
    dev_x_be, dev_y_be = dev_key_from_tag3(device_cert)
    return (host_pubkey, client_privkey_le, client_cert,
            dev_x_be, dev_y_be, client_pubkey_x_le)


def dev_key_from_tag3(tag3):
    """
    Extract device ECDH static key (x_be, y_be) from a 400-byte Tag3 blob.
    Tag3 layout matches Tag1: header(4) + X_LE(32) + Y_LE(32) + padding.
    Raises ValueError if tag3 is missing or invalid.
    """
    if not tag3 or len(tag3) < 142 or tag3[:4] != b'\x3f\x5f\x17\x00':
        raise ValueError(
            f"Invalid device cert tag3: {len(tag3) if tag3 else 0}B, "
            f"header={tag3[:4].hex() if tag3 else 'none'}")
    x_le = tag3[4:36]
    off  = 36
    while off < 142 and tag3[off] == 0:
        off += 1
    y_le = tag3[off:off + 32] if off < 142 else b'\x00' * 32
    if len(x_le) < 32:
        x_le = x_le + b'\x00' * (32 - len(x_le))
    if len(y_le) < 32:
        y_le = y_le + b'\x00' * (32 - len(y_le))
    return x_le[::-1], y_le[::-1]


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def prf(secret, label, seed, length):
    """TLS 1.2 PRF with SHA-384."""
    s = label.encode() + seed
    out, A = b'', _hmac.new(secret, s, hashlib.sha384).digest()
    while len(out) < length:
        out += _hmac.new(secret, A + s, hashlib.sha384).digest()
        A    = _hmac.new(secret, A, hashlib.sha384).digest()
    return out[:length]


def tls_encrypt(key, implicit_iv4, seq_num, content_type, plaintext):
    """Encrypt plaintext using AES-256-GCM. Returns record body bytes."""
    explicit = _rand(8)
    nonce    = implicit_iv4 + explicit
    aad      = (struct.pack('>Q', seq_num)
                + bytes([content_type]) + TLS_VER
                + struct.pack('>H', len(plaintext)))
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce),
                 backend=default_backend()).encryptor()
    enc.authenticate_additional_data(aad)
    ct  = enc.update(plaintext) + enc.finalize()
    return explicit + ct + enc.tag


def tls_decrypt(key, implicit_iv4, seq_num, content_type, body):
    """Decrypt TLS record body using AES-256-GCM. Returns plaintext."""
    explicit, ct, tag = body[:8], body[8:-16], body[-16:]
    nonce = implicit_iv4 + explicit
    aad   = (struct.pack('>Q', seq_num)
             + bytes([content_type]) + TLS_VER
             + struct.pack('>H', len(ct)))
    dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag, min_tag_length=16),
                 backend=default_backend()).decryptor()
    dec.authenticate_additional_data(aad)
    return dec.update(ct) + dec.finalize_with_tag(tag)


def make_tls_record(content_type, data):
    return bytes([content_type]) + TLS_VER + struct.pack('>H', len(data)) + data


def make_hs_message(msg_type, body):
    return bytes([msg_type]) + struct.pack('>I', len(body))[1:] + body


def ecdh_pubkey(priv_be):
    priv = ec.derive_private_key(int.from_bytes(priv_be, 'big'),
                                 ec.SECP256R1(), default_backend())
    n = priv.public_key().public_numbers()
    return n.x.to_bytes(32, 'big') + n.y.to_bytes(32, 'big')


def ecdh_shared(priv_be, peer_x_be, peer_y_be):
    priv = ec.derive_private_key(int.from_bytes(priv_be, 'big'),
                                 ec.SECP256R1(), default_backend())
    peer = ec.EllipticCurvePublicNumbers(
        int.from_bytes(peer_x_be, 'big'),
        int.from_bytes(peer_y_be, 'big'),
        ec.SECP256R1()).public_key(default_backend())
    return priv.exchange(ec.ECDH(), peer)


def sign_ecdsa_sha256(priv_d_be, digest32):
    """Sign digest32 with P-256 private key. Returns DER signature.

    The device requires the bundle to be exactly 616 bytes.  The bundle
    contains the ECDSA signature as part of the handshake TLS record; its
    DER-encoded size varies (70-72 bytes) depending on whether r and/or s
    need a leading 0x00 padding byte.  Only a 71-byte signature yields the
    required 616-byte bundle.  We re-try with fresh nonces until we get
    the right length (expected ~1-2 attempts, P(71B) ≈ 0.5).
    """
    priv = ec.derive_private_key(int.from_bytes(priv_d_be, 'big'),
                                 ec.SECP256R1(), default_backend())
    for _ in range(50):
        sig = priv.sign(digest32, ec.ECDSA(ec_utils.Prehashed(hashes.SHA256())))
        if len(sig) == 71:
            return sig
    return sig


# ---------------------------------------------------------------------------
# TLS session state (keys + sequence numbers + handshake hash)
# ---------------------------------------------------------------------------

class TLSState:
    def __init__(self):
        self.client_enc_key = None
        self.server_enc_key = None
        self.client_iv4     = None
        self.server_iv4     = None
        self.client_seq     = 0
        self.server_seq     = 0
        self.hs_hash        = hashlib.sha256()

    def feed_hs(self, data):
        self.hs_hash.update(data)

    def hs_digest(self):
        return self.hs_hash.digest()

    def setup_keys(self, master, cli_rand, srv_rand):
        """Derive AES-256-GCM key material from master secret."""
        km = prf(master, 'key expansion', cli_rand + srv_rand, 72)
        self.client_enc_key = km[0:32]
        self.server_enc_key = km[32:64]
        self.client_iv4     = km[64:68]
        self.server_iv4     = km[68:72]

    def encrypt(self, content_type, plaintext):
        body = tls_encrypt(self.client_enc_key, self.client_iv4,
                           self.client_seq, content_type, plaintext)
        self.client_seq += 1
        return body

    def decrypt(self, content_type, body):
        pt = tls_decrypt(self.server_enc_key, self.server_iv4,
                         self.server_seq, content_type, body)
        self.server_seq += 1
        return pt


# ---------------------------------------------------------------------------
# Sensor -- USB transport layer
# ---------------------------------------------------------------------------

class Sensor:
    """
    Raw USB control transfer layer. Handles device enumeration and the
    3-round init sequence (REQ_START + 4 cmds + REQ_READY).
    """

    def __init__(self):
        self.dev = None

    def find_device(self):
        vid, pid = [int(x, 16) for x in USB_ID.split(':')]
        self.dev = usb.core.find(idVendor=vid, idProduct=pid)
        if self.dev is None:
            raise RuntimeError(f"Device {USB_ID} not found")
        self.dev.reset()
        try:
            self.dev.set_configuration()
        except usb.core.USBError:
            pass
        # Claim both HID (intf 0) and vendor (intf 1) upfront so the
        # device expects both interfaces active from the start.
        self._claim_both_interfaces()

    def ctrl_out(self, req, channel=0, data=b'', label=""):
        _log(f">>> {label} {BM_OUT:02x}{req:02x}{channel:04x} "
             f"data={data[:64].hex()}")
        try:
            self.dev.ctrl_transfer(BM_OUT, req, channel, 0, data,
                                   timeout=USB_TIMEOUT)
        except Exception as exc:
            _log(f"  ERROR: {exc}")
            raise

    def ctrl_in(self, req, length, channel=0, label=""):
        _log(f"<<< {label} {BM_IN:02x}{req:02x}{channel:04x} len={length}")
        try:
            resp = bytes(self.dev.ctrl_transfer(BM_IN, req, channel, 0,
                                                length, timeout=USB_TIMEOUT))
            _log(f"  resp ({len(resp)}B): {resp[:64].hex()}")
            return resp
        except Exception as exc:
            _log(f"  ERROR: {exc}")
            raise

    INTERRUPT_EP = 0x83  # interrupt IN endpoint (intf 1, vendor)

    def _claim_both_interfaces(self):
        """Claim intf 0 (HID) and intf 1 (vendor) so both endpoints
        are usable on the main handle.  Must be called before any
        TLS commands -- claiming mid-stream breaks the device."""
        import usb.util
        for ifnum in (0, 1):
            try:
                if self.dev.is_kernel_driver_active(ifnum):
                    self.dev.detach_kernel_driver(ifnum)
            except:
                pass
            try:
                usb.util.claim_interface(self.dev, ifnum)
                _log(f"claimed intf {ifnum}")
            except usb.core.USBError as exc:
                _log(f"claim intf {ifnum}: {exc}")

    def read_interrupt(self, timeout=60000):
        """Read from interrupt endpoint. Polls in short slices so that
        Ctrl+C (KeyboardInterrupt) is delivered promptly without needing
        a finger touch to unblock the call.

        Returns bytes on success, None on timeout.
        Raises KeyboardInterrupt on SIGINT.
        """
        slice_ms = 200
        remaining = timeout
        while True:
            t = min(slice_ms, remaining)
            try:
                resp = bytes(self.dev.read(self.INTERRUPT_EP, 64, timeout=t))
                _log(f"INTERRUPT ({len(resp)}B): {resp.hex()}")
                return resp
            except usb.core.USBError as exc:
                if exc.errno == 110:  # ETIMEDOUT -- slice expired, loop
                    remaining -= t
                    if remaining <= 0:
                        _log("INTERRUPT timeout")
                        return None
                    continue
                if exc.errno in (4, 19):
                    raise KeyboardInterrupt from exc
                raise

    # --- Init protocol ---

    def _cmd_device_info(self, n):
        """
        Send device info query -> 38B response.

        Response layout (38 bytes):
          [0:2]   status (0x0000 = ok)
          [10]    firmware major version
          [11]    firmware minor version
          [18:24] serial number (6 bytes, formatted as %02X each)

        Returns DeviceInfo(serial, firmware_major, firmware_minor, raw).
        Also stores serial and firmware_version on self.
        """
        self.ctrl_out(REQ_CMD, channel=CH_INIT,
                      data=bytes.fromhex('0100000000000000'),
                      label=f"DEV_INFO(r{n})")
        r = self.ctrl_in(REQ_RESP, 0x26, label=f"DEV_INFO(r{n})")
        if r and len(r) >= 24:
            di = DeviceInfo(serial=r[18:24].hex().upper(),
                            firmware_major=r[10],
                            firmware_minor=r[11],
                            raw=r)
            self.firmware_version = (di.firmware_major, di.firmware_minor)
            self.serial = di.serial
            _log(f"  {di}")
            return di
        return DeviceInfo(serial=None, firmware_major=None, firmware_minor=None, raw=r)

    def _cmd_cert_section(self, n, section):
        """
        Read certificate section (8e <section> 00 02 ...).
        Returns CertSection(section, raw).
        """
        data = bytes([0x8e, section, 0, 2]) + b'\x00' * 20
        self.ctrl_out(REQ_CMD, channel=CH_INIT, data=data,
                      label=f"CERT_SECT_{section:02x}(r{n})")
        r = self.ctrl_in(REQ_RESP, 4096, channel=CH_IN_CERT,
                         label=f"CERT_SECT_{section:02x}(r{n})")
        return CertSection(section=section, raw=r)

    def _cmd_bootstrap_status(self, n):
        """
        Send bootstrap status query (19...) -> 68B response.
        Returns BootStatus(state, raw); state == 0x02 means still booting.
        """
        self.ctrl_out(REQ_CMD, channel=CH_INIT,
                      data=bytes.fromhex('1900000000000000'),
                      label=f"BOOT_STATUS(r{n})")
        r = self.ctrl_in(REQ_RESP, 0x44, label=f"BOOT_STATUS(r{n})")
        state = r[0] if r else None
        return BootStatus(state=state, raw=r)

    def _init_round(self, n):
        """
        One init round: REQ_START + 4 plain commands.
        Returns the bootstrap status response (68B).
        """
        self.ctrl_out(REQ_START, channel=CH_INIT, label=f"REQ_START(r{n})")
        ack = self.ctrl_in(REQ_INIT_ACK, 1, label=f"REQ_INIT_ACK(r{n})")
        assert ack == b'\x01', f"ACK={ack.hex()}"

        self._cmd_device_info(n)
        self._cmd_cert_section(n, 0x09)
        self._cmd_cert_section(n, 0x1a)
        boot = self._cmd_bootstrap_status(n)
        _log(f"  {boot}")
        return boot

    def init_device(self):
        """
        Run one init round (REQ_START + 4 plain commands).
        Retried up to 3 times only if the device signals it is still
        booting (bootstrap status first byte == 0x02), mirroring the
        driver's vfmDeviceInitialize state=2 retry path.
        """
        for i in range(3):
            boot = self._init_round(i)
            if not boot.raw or boot.state != 0x02:
                break
            _log(f"Device still booting (attempt {i+1}), retrying...")
        _log("Init phases done")

    def req_ready(self):
        return self.ctrl_in(REQ_READY, 2, label="REQ_READY")

    def send_challenge(self, host_pubkey, sign_privkey_be):
        """
        Send 408-byte pairing challenge.

        The challenge proves ownership of the host ECS2 signing key.
        Device responds with 802 bytes: status(2) + client_cert(400)
        + device_cert(400).  Returns (client_cert, device_cert).
        """
        sig = sign_ecdsa_sha256(sign_privkey_be,
                                hashlib.sha256(host_pubkey).digest())
        challenge = b'\x93' + host_pubkey + b'\x47\x00' + sig
        challenge += b'\x00' * (408 - len(challenge))
        assert len(challenge) == 408
        _hexdump("Challenge", challenge)
        self.ctrl_out(REQ_CMD, channel=CH_INIT, data=challenge,
                      label="CHALLENGE")
        resp = self.ctrl_in(REQ_RESP, 802, label="CHALLENGE_RESP")
        if resp is None or len(resp) < 402:
            raise RuntimeError(
                f"Challenge response too short: {len(resp) if resp else 0}B")
        status = struct.unpack('<H', resp[:2])[0]
        if status != 0:
            raise RuntimeError(
                f"Challenge rejected: status=0x{status:04x}")
        client_cert  = resp[2:402]
        device_cert  = resp[402:802] if len(resp) >= 802 else None
        _log(f"Challenge accepted, client_cert={client_cert[:8].hex()}...")
        if device_cert:
            _log(f"  device_cert={device_cert[:8].hex()}...")
        return client_cert, device_cert


# ---------------------------------------------------------------------------
# SensorTLS -- extends Sensor with TLS 1.2 handshake
# ---------------------------------------------------------------------------

class SensorTLS(Sensor):
    """
    Adds TLS 1.2 handshake on top of the raw USB transport.
    After connect(), self.tls holds the established TLSState.
    """

    def __init__(self):
        super().__init__()
        self.tls             = None
        self._pairing        = None  # set by connect(); used by restart_session()
        self.serial          = None  # set by _cmd_device_info()
        self.firmware_version = None # set by _cmd_device_info(); tuple (major, minor)

    def connect(self, host_pubkey, client_privkey_be, client_pubkey_x_le,
                client_cert, dev_x_be, dev_y_be):
        """
        Perform the full TLS 1.2 handshake with the device.

        Parameters:
          host_pubkey           -- 142-byte host EC key blob (TLV_CLIENT_CERT[0:142])
          client_privkey_be  -- 32-byte host ECDSA private key D (BE) for CertVerify
          client_pubkey_x_le -- 32-byte host ECDSA public key X coord (LE)
          client_cert        -- 400-byte client certificate body (TLV_CLIENT_CERT)
                                None = build from host_pubkey + pubkey
          dev_x_be           -- 32-byte device ECDH static pub X (BE)
          dev_y_be           -- 32-byte device ECDH static pub Y (BE)
        """
        state    = TLSState()
        cli_rand = _rand(32)
        _log(f"cli_rand={cli_rand.hex()}")

        # ----- Ephemeral ECDH key pair -----
        eck2_d = _rand(32)
        pub    = ecdh_pubkey(eck2_d)
        eph_x, eph_y = pub[:32], pub[32:]
        _log(f"eph_x={eph_x.hex()}")

        # ----- ClientHello -----
        # Extensions: ext_len=0x000c (12 bytes) covering two extensions.
        # supported_groups(0x0004)+ec_point_formats(0x000b).
        # CH HS body = 71 bytes, total CH = 84 bytes (matched to windows driver trace).
        sess_id   = b'\x07' + b'\x00' * 7
        suites    = b''.join([
            CS_ECDH_ECDSA_AES256_CBC_SHA,
            CS_ECDHE_ECDSA_AES256_GCM_SHA384,
            CS_RSA_AES256_CBC_SHA256,
            CS_DHE_PSK_AES256_CBC_SHA,
            CS_PSK_AES256_CBC_SHA,
            CS_DHE_PSK_AES256_CBC_SHA256,
        ])
        # Extensions: ext_len=0x000a (10) is a device quirk -- it covers
        # supported_groups (6B) + ec_point_formats type+len (4B) only.
        # The ec_point_formats data (\x01\x00) sits outside ext_len field.
        # CH HS body = 71 bytes, total CH = 84 bytes (matched to windows driver trace).
        ext_inner = b'\x00\x04\x00\x02\x00\x17\x00\x0b\x00\x02'  # 10B
        ch_body = (TLS_VER + cli_rand + sess_id
                   + struct.pack('>H', len(suites)) + suites
                   + b'\x00'                          # compression: length=0
                   + struct.pack('>H', len(ext_inner)) + ext_inner
                   + b'\x01\x00')                     # ec_point_formats data
        ch_hs  = make_hs_message(TLS_HS_CLIENT_HELLO, ch_body)
        ch_rec = make_tls_record(TLS_HANDSHAKE, ch_hs)
        state.feed_hs(ch_hs)
        _hexdump("CH record", ch_rec)

        # Send CH: value=4 with 44000000 IOCTL header (confirmed windows driver trace)
        self.ctrl_out(REQ_CMD, channel=CH_TLS,
                      data=IOCTL_HDR + ch_rec,
                      label="TLS_OUT(CH)")
        raw_sh = self.ctrl_in(REQ_RESP, 0x400, label="TLS_IN(CH)")
        if raw_sh and raw_sh[0] == TLS_ALERT:
            raise TlsAlertError(raw_sh[1], raw_sh[2],
                                f"ClientHello rejected: {raw_sh.hex()}")

        # ----- Parse ServerHello + CertReq + ServerHelloDone -----
        srv_rand = None
        off      = 0
        while off + 5 <= len(raw_sh):
            rtype = raw_sh[off]
            rlen  = struct.unpack_from('>H', raw_sh, off + 3)[0]
            rbody = raw_sh[off + 5: off + 5 + rlen]
            off  += 5 + rlen
            if rtype != TLS_HANDSHAKE:
                continue
            hoff = 0
            while hoff < len(rbody):
                ht   = rbody[hoff]
                hl   = struct.unpack_from('>I',
                           b'\x00' + rbody[hoff+1:hoff+4])[0]
                hmsg = rbody[hoff: hoff + 4 + hl]
                state.feed_hs(hmsg)
                if ht == TLS_HS_SERVER_HELLO:
                    srv_rand = hmsg[6:38]
                elif ht == TLS_HS_CERTIFICATE_REQUEST:
                    pass
                elif ht == TLS_HS_SERVER_HELLO_DONE:
                    pass
                hoff += 4 + hl
        if srv_rand is None:
            raise RuntimeError("ServerHello not received or parsed")
        _log(f"srv_rand={srv_rand.hex()}")

        # ----- Key derivation -----
        shared_x = ecdh_shared(eck2_d, dev_x_be, dev_y_be)
        master   = prf(shared_x, 'master secret', cli_rand + srv_rand, 48)
        state.setup_keys(master, cli_rand, srv_rand)
        _hexdump("master secret", master)

        # ----- Client Certificate -----
        # cert_body = run_marker(2) + host_pubkey(142) + u16le(32)(2)
        #             + pub_key32(32) + zeros(222) = 400 bytes.
        # The paired path uses the full client cert (400B) + run_marker
        # = 402B (extra 2 zeros are harmless; device uses the inner
        # cert_length = 400 and ignores trailing padding).
        run_marker = cli_rand[4:6]
        if client_cert is not None:
            cert_body = run_marker + client_cert   # 2+400 = 402
            assert len(cert_body) == 402, f"paired cert_body={len(cert_body)}"
        else:
            pub_key   = client_pubkey_x_le or b'\x00' * 32
            cert_body = (run_marker + host_pubkey
                         + b'\x00\x02'
                         + struct.pack('<H', 32)   # u16le(32) = 20 00
                         + pub_key + b'\x00' * 220)  # 2+142+2+2+32+220 = 400
            assert len(cert_body) == 400, f"fresh cert_body={len(cert_body)}"

        # Client cert body is always 400 bytes (0x190)
        CERT_BODY_LEN = struct.pack('>I', 400)[1:]  # 3-byte big-endian = \x00\x01\x90
        cert_hs = make_hs_message(TLS_HS_CERTIFICATE,
                      CERT_BODY_LEN + CERT_BODY_LEN + cert_body)
        state.feed_hs(cert_hs)
        _hexdump("Cert HS", cert_hs)

        # ----- ClientKeyExchange -----
        ec_point_uncompressed = b'\x04'
        cke_hs = make_hs_message(TLS_HS_CLIENT_KEY_EXCHANGE,
                                 ec_point_uncompressed + eph_x + eph_y)
        state.feed_hs(cke_hs)

        # ----- CertificateVerify -----
        hs_dig = state.hs_digest()
        _hexdump("HS hash for CertVerify", hs_dig)
        sig_der = sign_ecdsa_sha256(client_privkey_be, hs_dig)
        cv_hs   = make_hs_message(TLS_HS_CERTIFICATE_VERIFY, sig_der)
        state.feed_hs(cv_hs)

        # ----- ChangeCipherSpec + Finished -----
        verify  = prf(master, 'client finished', state.hs_digest(), 12)
        fin_hs  = make_hs_message(TLS_HS_FINISHED, verify)

        hs_rec  = make_tls_record(TLS_HANDSHAKE, cert_hs + cke_hs + cv_hs)
        ccs_rec = make_tls_record(TLS_CHANGE_CS, b'\x01')

        # Encrypted epoch begins at seq=0 after CCS
        state.client_seq = 0
        fin_cipher = state.encrypt(TLS_HANDSHAKE, fin_hs)
        state.client_seq = 1   # next encrypted record is seq=1
        fin_rec = make_tls_record(TLS_HANDSHAKE, fin_cipher)

        # Send bundle: value=0 per windows driver trace (wVal=0x0000 confirmed)
        burst = IOCTL_HDR + hs_rec + ccs_rec + fin_rec
        _hexdump("bundle", burst)
        self.ctrl_out(REQ_CMD, channel=CH_PLAIN, data=burst,
                      label="TLS_OUT(BUNDLE)")
        # Device should respond immediately (windows driver does no delay)
        raw_sfin = self.ctrl_in(REQ_RESP, 0x200, label="TLS_IN(BUNDLE)")

        # ----- Server CCS + Finished -----
        state.server_seq = 0
        off = 0
        while off + 5 <= len(raw_sfin):
            stype = raw_sfin[off]
            slen  = struct.unpack_from('>H', raw_sfin, off + 3)[0]
            sbody = raw_sfin[off + 5: off + 5 + slen]
            off  += 5 + slen
            if stype == TLS_ALERT:
                raise TlsAlertError(sbody[0], sbody[1] if len(sbody) > 1 else 0,
                                    f"Bundle response: {sbody.hex()}")
            if stype == TLS_HANDSHAKE:
                try:
                    srv_fin = state.decrypt(TLS_HANDSHAKE, sbody)
                    _hexdump("Server Finished", srv_fin)
                except Exception as exc:
                    _log(f"  Server Finished decrypt failed: {exc}")

        self.tls = state
        self._pairing = dict(
            host_pubkey=host_pubkey,
            client_privkey_be=client_privkey_be,
            client_pubkey_x_le=client_pubkey_x_le,
            client_cert=client_cert,
            dev_x_be=dev_x_be,
            dev_y_be=dev_y_be,
        )
        _log("TLS handshake complete")

    def tls_send(self, plain, channel, label="", ctype=TLS_APP_DATA):
        """Encrypt plain as TLS record (ctype), send, decrypt response."""
        assert self.tls is not None, "call connect() first"
        _log(f"  tx seq={self.tls.client_seq} plain_len={len(plain)}")
        body = self.tls.encrypt(ctype, plain)
        rec  = make_tls_record(ctype, body)
        # Pad to 8-byte alignment (native format)
        pad  = (-len(rec)) % 8
        self.ctrl_out(REQ_CMD, channel=channel,
                      data=rec + bytes(pad), label=f"TLS_OUT({label})")
        raw = self.ctrl_in(REQ_RESP, 4096, label=f"TLS_IN({label})")
        if not raw:
            return None
        if len(raw) < 5:
            _log(f"  TLS({label}) short response ({len(raw)}B): {raw.hex()}")
            return None
        if raw[0] == TLS_ALERT:
            rlen  = struct.unpack('>H', raw[3:5])[0]
            rbody = raw[5: 5 + rlen]
            try:
                pt = self.tls.decrypt(TLS_ALERT, rbody)
                alert = TlsAlertError(pt[0], pt[1])
                if pt[0] == TLS_ALERT_FATAL:
                    raise alert
                _log(f"  {alert}")  # warning (e.g. close_notify) -- not an error
            except TlsAlertError:
                raise
            except Exception as exc:
                raise RuntimeError(f"TLS Alert (decrypt failed): {raw.hex()}") from exc
            return None
        rtype = raw[0]
        rlen  = struct.unpack('>H', raw[3:5])[0]
        rbody = raw[5: 5 + rlen]
        if len(rbody) < rlen:
            _log(f"  TLS({label}) truncated body: need {rlen} got {len(rbody)}")
            return None
        try:
            pt = self.tls.decrypt(rtype, rbody)
            _log(f"  TLS({label}) resp: {pt.hex()}")
            return pt
        except Exception as exc:
            _log(f"  TLS({label}) decrypt failed: {exc}")
            return None

    def close(self):
        """Send REQ_SHUTDOWN + TLS close_notify (matches windows driver)."""
        try:
            self.dev.ctrl_transfer(BM_OUT, REQ_SHUTDOWN, 0, 0, [],
                                   timeout=1000)
            # Post-shutdown read uses REQ_SHUTDOWN_ACK (0x14)
            self.dev.ctrl_transfer(BM_IN, REQ_SHUTDOWN_ACK, 0, 0, 2,
                                   timeout=1000)
        except Exception as exc:
            _log(f"  REQ_SHUTDOWN: {exc}")
        if self.tls is not None:
            try:
                self.close_notify()
            except Exception:
                pass
        self.tls = None

    def restart_session(self):
        """
        Re-establish the TLS session on the existing USB handle after a
        clean shutdown (e.g. discard_enrollment).  Mirrors what windows driver does
        after discard: immediately re-runs init + new TLS handshake on the
        same USB device handle without any USB reset or re-enumeration.

        Requires a prior connect() call so that self._pairing is populated.
        """
        if self._pairing is None:
            raise RuntimeError(
                "No pairing data stored -- call connect() first")
        self.tls = None
        print("  Re-initialising device...")
        self.init_device()
        print("  Re-establishing TLS session...")
        self.connect(**self._pairing)
        print("  Session ready.")

    def cancel_session(self):
        """
        Cancel an in-progress operation (identify, enroll, etc.) and
        turn off the sensor LED immediately via dev.reset().

        REQ_SHUTDOWN is NOT sent here -- it belongs only in close().
        Sending it mid-session causes a pipe error on Linux.
        """
        print("  Resetting USB device...")
        try:
            self.dev.reset()
        except Exception as exc:
            _log(f"  dev.reset(): {exc}")


# ---------------------------------------------------------------------------
# BiometricSensor -- extends SensorTLS with fingerprint commands
# ---------------------------------------------------------------------------

class BiometricSensor(SensorTLS):
    """
    High-level fingerprint database commands over the encrypted TLS channel.

    Command value codes (from windows driver trace):
      GET_RECORD_COUNT  -> value=6
      STORAGE_QUERY_INIT -> value=7
      STORAGE_QUERY_ALL  -> value=2
      FETCH_RECORD       -> value=2
    """

    def get_storage_count(self):
        """
        Full storage query sequence to obtain enrolled GUIDs.
        Returns list of 16-byte GUIDs.
        Raises RuntimeError on device error.
        """
        resp = CMD_GET_RECORD_COUNT.send(self)
        if resp is None or len(resp) < 2:
            raise RuntimeError("GET_RECORD_COUNT: no response")
        status = struct.unpack('<H', resp[:2])[0]
        if status != 0:
            raise RuntimeError(f"GET_RECORD_COUNT failed: 0x{status:04x}")
        self.storage_query_init(1)
        self.storage_query_init(2)
        return self.storage_query_all()

    def storage_query_init(self, n):
        """Send STORAGE_QUERY_INIT (40B response, [0:2] = status).
        Raises RuntimeError on device error."""
        resp = CMD_STORAGE_QUERY_INIT.send(self, label=f"QUERY_INIT_{n}")
        if resp is None or len(resp) < 2:
            raise RuntimeError(f"STORAGE_QUERY_INIT_{n}: no response")
        status = struct.unpack_from('<H', resp, 0)[0]
        if status != 0:
            raise RuntimeError(f"STORAGE_QUERY_INIT_{n} failed: 0x{status:04x}")

    def storage_query_all(self):
        """
        Send STORAGE_QUERY_ALL wildcard.
        Returns list of 16-byte GUIDs for all allocated storage slots.
        """
        resp = CMD_STORAGE_QUERY_ALL.send(self, label="QUERY_ALL")
        if not resp or len(resp) < 4:
            return []
        slot_count = struct.unpack('<H', resp[2:4])[0]
        guids, off = [], 4
        while off + 16 <= len(resp):
            guids.append(resp[off: off + 16])
            off += 16
        _log(f"QUERY_ALL: {len(guids)} slots (header claims {slot_count})")
        assert len(guids) == slot_count, f"slot count mismatch: {len(guids)} vs {slot_count}"
        return guids

    def fetch_record(self, guid):
        """
        Fetch a record handle by GUID (9f03).
        Returns RecordInfo(handle) or None if not found / wrong namespace.
        handle is None if the slot exists but belongs to another pairing.
        """
        r = CMD_FETCH_RECORD.send(self, guid, label=f"FETCH_{guid[:4].hex()}")
        if not r or len(r) < 20 or r[:2] != b'\x00\x00':
            return None
        handle = r[4:20]
        if handle == NULL_GUID:
            return None
        return RecordInfo(handle=handle)

    def load_template(self, handle):
        """
        Send LOAD_TEMPLATE (a103) for a record handle and parse the response.

        Response layout (133 bytes):
          [0:2]    status (u16 LE, 0x0000 = ok)
          [2:14]   fixed header (matches commit header sans opcode)
          [14:30]  GUID (16B)
          [30:]    payload region -- format detected by marker at [30:40]:
            WinBIO format (COMMIT_IDENTITY_PREFIX at [30:40]):
              [30:40]  identity prefix
              [40:56]  SID (16B)
              [56:112] reserved zeros + pad
              [112:118] TLV1 (020001000000)
              [118:]   label TLV: 0203 00 <len LE32> <label+NUL>
            libfprint format (no COMMIT_IDENTITY_PREFIX):
              [30:]    NUL-terminated UTF-8 fprint ID string, zero-padded

        Returns TemplateInfo(guid, sid, label, subfactor) or None on error.
        sid and subfactor are None for libfprint-format templates.
        """
        r = CMD_LOAD_TEMPLATE.send(self, handle)
        if not r or len(r) < 56:
            return None
        guid = r[14:30]
        if r[30:40] == self.COMMIT_IDENTITY_PREFIX:
            # WinBIO format
            sid       = r[40:56]
            subfactor = r[116] if len(r) >= 117 else 0
            label     = None
            idx       = r.find(b'\x02\x03', 110)
            if idx >= 0 and len(r) >= idx + 7:
                llen  = int.from_bytes(r[idx+3:idx+7], 'little')
                raw   = r[idx+7:idx+7+llen]
                label = raw.rstrip(b'\x00').decode('utf-8', errors='replace') or None
        else:
            # libfprint format: NUL-terminated UTF-8 ID string from [30:]
            sid       = None
            subfactor = None
            raw       = r[30:]
            nul       = raw.find(b'\x00')
            label     = raw[:nul].decode('utf-8', errors='replace') if nul >= 0 else \
                        raw.decode('utf-8', errors='replace')
            label     = label or None
        return TemplateInfo(guid=guid, sid=sid, label=label, subfactor=subfactor)

    def select_record(self, handle, label="SELECT_RECORD"):
        """
        Send SELECT_RECORD (a003) for a record handle and parse the response.

        Response layout (52 bytes):
          [0:2]   status (u16 LE, 0x0000 = ok)
          [2:4]   flags
          [4:20]  secondary handle (16B)
          [20:36] GUID (16B)
          [36:52] extra (counts / timestamps, not yet decoded)

        Returns SelectInfo(handle, guid) or None on error.
        """
        r = CMD_SELECT_RECORD.send(self, handle, label=label)
        if not r or len(r) < 36 or r[:2] != b'\x00\x00':
            return None
        return SelectInfo(handle=r[4:20], guid=r[20:36])

    def list_enrolled(self):
        """
        Full list-db sequence. Returns list of (guid, record_data) for
        all non-empty slots. Prints results to stdout.
        """
        guids = self.get_storage_count()
        print(f"Storage count: {len(guids)}")
        if not guids:
            print("No storage slots found.")
            return []

        enrolled = []
        for guid in guids:
            rec = self.fetch_record(guid)
            if rec:
                enrolled.append((guid, rec))

        if not enrolled:
            print("No enrolled fingerprints found.")
        else:
            print(f"Enrolled fingerprints ({len(enrolled)}):")
            for guid, rec in enrolled:
                tmpl      = self.load_template(rec.handle) if rec else None
                label_str = f"  label='{tmpl.label}'" if tmpl and tmpl.label else ""
                sf_str    = f"  subfactor=0x{tmpl.subfactor:02x}" if tmpl and tmpl.subfactor is not None else ""
                print(f"  {guid.hex()}{label_str}{sf_str}")

        return enrolled

    def list_all(self):
        """
        Comprehensive enumeration: shows ALL records, entries, and
        their relationships.  Exposes the firmware's storage layout.

        Three handle namespaces exist:
          - 9f01 FETCH_FIRST → entry handles (storage containers)
          - 9f02 STORAGE_QUERY_ALL → GUIDs → 9f03 → record handles
          - 9f03(entry) → entry-internal slot handles (opaque)

        Record handles (from 9f03 with a GUID) work with a003/a103.
        Entry-internal slot handles (from 9f03 with an entry handle)
        return 0304 with a003/a103 and are NOT resolvable to GUIDs.

        a302 DELETE_RECORD is not supported (returns 8306).
        MATCH_RESULT can return GUIDs not present in 9f02 enumeration.
        """
        import struct

        # 1. Record count via 8200
        count_resp = CMD_GET_RECORD_COUNT.send(self, label="GET_COUNT")
        _log(f"GET_RECORD_COUNT ({len(count_resp) if count_resp else 0}B):"
             f" {count_resp.hex() if count_resp else 'None'}")

        # 2. Storage query init + query all
        self.storage_query_init(1)
        self.storage_query_init(2)
        guids = self.storage_query_all()
        print(f"\nRecords (STORAGE_QUERY_ALL via 9f02): {len(guids)}")
        for i, guid in enumerate(guids):
            rec  = self.fetch_record(guid)
            r3   = self.select_record(rec.handle) if rec else None
            tmpl = self.load_template(rec.handle) if rec else None
            guid_from_a003 = r3.guid if r3 else None
            label_str = f" label='{tmpl.label}'" if tmpl and tmpl.label else ""
            sf_str    = f" subfactor=0x{tmpl.subfactor:02x}" if tmpl and tmpl.subfactor is not None else ""
            print(f"  [{i}] GUID {guid.hex()}{label_str}{sf_str}")
            print(f"       9f03 -> handle {rec.handle.hex() if rec else 'N/A'}"
                  f" | a003 -> {guid_from_a003.hex() if guid_from_a003 else 'N/A'}"
                  f" | a103 -> {tmpl.guid.hex() if tmpl else 'N/A'}")
            if guid_from_a003 and guid_from_a003 != guid:
                print(f"       WARN: a003 GUID mismatch!")
            if tmpl and tmpl.guid != guid:
                print(f"       WARN: template GUID mismatch!")

        # 3. FETCH_FIRST entries + 9f03(entry) for per-entry slots
        entries = self._list_entries()
        print(f"\nEntries (FETCH_FIRST via 9f01): {len(entries)}")
        for i, ent in enumerate(entries):
            # 9f03(entry) returns slot handles if entry has data
            r = CMD_FETCH_RECORD.send(self, ent)
            n_slots = 0; slot_handles = []
            if r and len(r) >= 4:
                n_slots = struct.unpack('<H', r[2:4])[0]
                slot_handles = [r[4+j*16:4+(j+1)*16]
                                for j in range(n_slots)]
            print(f"  [{i}] handle={ent.hex()}"
                  f" slots={n_slots}"
                  f" slot_handles={[h.hex() for h in slot_handles]}")
            if n_slots > 0:
                ei = self.select_entry(ent)
                print(f"       a001(entry)={ei}"
                      f" ({12}B)")
                # Show that slot handles are NOT resolvable to GUIDs
                for j, sh in enumerate(slot_handles[:2]):
                    rx = CMD_SELECT_RECORD.send(self, sh)
                    print(f"       slot[{j}]: a003 ->"
                          f" {rx.hex() if rx else 'None'}")

        # 4. Detect manager entries (a001 = all zeros)
        managers = self._find_managers(entries)
        if managers:
            print(f"\nManager entries (a001=all-zeros, one per GUID slot):"
                  f" {len(managers)}")
            for i, m in enumerate(managers):
                idx = next((j for j, e in enumerate(entries) if e == m), -1)
                print(f"  [{i}] entry[{idx}] handle={m.hex()}")

        summary_count = 0
        for e in entries:
            rr = CMD_FETCH_RECORD.send(self, e)
            if rr and len(rr) >= 4:
                cc = struct.unpack('<H', rr[2:4])[0]
                if cc > 0:
                    summary_count += 1
        print(f"\nSummary:")
        print(f"  GUIDs from 9f02: {len(guids)}")
        print(f"  Managers: {len(managers)}")
        print(f"  Entries with data: {summary_count} / {len(entries)}")
        print(f"  a302 DELETE_RECORD: NOT SUPPORTED (returns 8306)")
        print(f"  Hidden GUIDs: only discoverable via MATCH_RESULT")
        print(f"  (requires physical finger press on sensor)")
        return guids


    # --- Enroll protocol ---

    def enroll_begin(self):
        """Begin enrollment (value=0x0002). Returns raw response."""
        return CMD_ENROLL_BEGIN.send(self)

    # Quality bitmask → WINBIO_SENSOR_STATUS mapping
    # (from decompiled FUN_18000d054 at line 8331)
    QUALITY_MAP = {
        0x00:       (0, 0),     # WINBIO_SENSOR_ACCEPT
        0x02:       (5, 0x07),  # WINBIO_SENSOR_REJECT
        0x04:       (9, 0x07),
        0x10:       (6, 0x07),
        0x8000:     (8, 0x07),
        0x20000:    (3, 0x07),  # DRY finger
        0x40000:    (4, 0x07),  # WET finger
        0x80000000: (7, 0x07),  # BAD capture
    }

    @staticmethod
    def _quality_to_status(quality):
        """Map quality bitmask to (sensor_status, reject_detail).

        The quality bitmask is the first DWORD of the image data header.
        Multiple bits may be set; we return the first matching entry.
        """
        if quality == 0:
            return 1, 0  # ACCEPT
        for bit, (ss, rd) in sorted(BiometricSensor.QUALITY_MAP.items()):
            if bit and quality & bit:
                return ss, rd
        return 2, 7  # generic reject

    def capture_data(self):
        """
        Send CAPTURE_DATA (value=0x0002) and parse the 66-byte response.

        Returns CaptureData(sensor_status, reject_detail, ctx, raw):
          sensor_status -- 1=finger detected, 2=no finger, 3=error/short resp
          reject_detail -- 0 or 7 (no finger)
          ctx           -- LE u16 from resp[-2:], used as enrollment context
          raw           -- full response bytes (or None on TLS error)

        The marker at [18:22] (LE u32) tells if a finger was detected:
          6 = WINBIO_I_MORE_DATA = finger detected
          0 = no finger / hardware rejected
        37-byte fixed payload: 86 06 00*15 06 00*19.
        The 0x06 byte is an opaque device-internal mode field.
        """
        raw = CMD_CAPTURE_DATA.send(self)
        if raw is None or len(raw) < 22:
            return CaptureData(sensor_status=3, reject_detail=0, ctx=0, raw=raw)
        marker = struct.unpack_from('<I', raw, 18)[0]
        if marker == 6:
            sensor_status, reject_detail = 1, 0   # finger detected
        else:
            sensor_status, reject_detail = 2, 7   # no finger
        ctx = struct.unpack('<H', raw[-2:])[0] if len(raw) >= 2 else 0
        cd = CaptureData(sensor_status=sensor_status,
                         reject_detail=reject_detail,
                         ctx=ctx, raw=raw)
        _log(f"  {cd}")
        return cd

    def _print_sensor_status(self, ctx=0, label=""):
        """Query and print human-readable SensorStatus."""
        ss = self.get_sensor_status(ctx)
        mode_str = {1: "armed", 2: "data_rdy"}.get(ss.mode, f"0x{ss.mode:04x}")
        print(f"  {label}SensorStatus(mode={mode_str},"
              f" sample={ss.sample},"
              f" quality=0x{ss.quality:04x},"
              f" context={ss.context})")

    def get_sensor_status(self, ctx=0):
        """
        Query sensor status (CH_SENSOR, 9 bytes).
        ctx is the enrollment context byte extracted from CAPTURE_DATA
        response[-2:] (LE u16).

        Structure (from trace analysis):
          [0:2]   LE16 = 0x0000           (status)
          [2:4]   LE16 = 0x0001           (response type)
          [4:6]   LE16 = 0x0000
          [6:8]   LE16 = sensor mode      (1=armed, 2=data captured)
          [8:10]  LE16 = sample counter   (per-enrollment 1..N, 0 in identify)
          [10:12] LE16 = quality metric   (firmware-specific bitmask)
          [12:16] LE32 = context value
          [16:18] padding

        Returns SensorStatus(mode, sample, quality, context).
        """
        cmd = Cmd(CMD_SENSOR_STATUS.opcode + bytes([ctx]),
                  CMD_SENSOR_STATUS.channel,
                  body=CMD_SENSOR_STATUS.body,
                  sep=CMD_SENSOR_STATUS.sep,
                  label=f"{CMD_SENSOR_STATUS.label}(ctx={ctx})")
        resp = cmd.send(self)
        if resp is None or len(resp) < 12:
            return SensorStatus(0, 0, 0, 0)
        mode    = struct.unpack_from('<H', resp,  6)[0]
        sample  = struct.unpack_from('<H', resp,  8)[0]
        quality = struct.unpack_from('<H', resp, 10)[0]
        context = struct.unpack_from('<I', resp, 12)[0] if len(resp) >= 16 else 0
        return SensorStatus(mode, sample, quality, context)

    def update_enrollment_check(self):
        """
        Send UPDATE_ENROLLMENT check (value=0x0006).
        17-byte payload: 800c + zeros + flags + subfactor.
        """
        return CMD_UPDATE_ENROLL_CHECK.send(self)

    def update_enrollment_ack(self):
        """Send ack byte (81) after enrollment update (value=0x0006)."""
        return CMD_UPDATE_ACK.send(self, label="UPDATE_ENROLL_ACK")

    def query_enrollment_needs(self):
        """
        Query device's enrollment requirements (value=0x0002).
        125-byte payload: 39 00 71 02 ...
        """
        return CMD_QUERY_ENROLL_NEEDS.send(self)

    def query_status_ext(self, param=4):
        """
        Extended status query (value=0x0002, 37 bytes).
        86 00 <00*15> <param> <00*19>
        param=4 for initial/post capture, param=1 for quality check.
        Returns StatusExt(progress) where progress is the LE16 counter
        from the last 2 bytes of the 66-byte response.
        """
        cmd = CMD_STATUS_EXT_4 if param == 4 else CMD_STATUS_EXT_1
        resp = cmd.send(self)
        if resp is None or len(resp) < 2:
            return StatusExt(0)
        progress = struct.unpack('<H', resp[-2:])[0]
        return StatusExt(progress)

    def query_enrollment_simple(self):
        """
        Simplified enrollment query (value=0x0002, 125 bytes).
        39 00 ... (zeros with periodic 0x20 pattern).
        """
        return CMD_QUERY_ENROLL_SIMPLE.send(self)

    # -- Commit / finalization protocol ---

    COMMIT_HEADER = bytes.fromhex(
        '000000000000007d0000000000100000')

    COMMIT_IDENTITY_PREFIX = bytes.fromhex(
        '01004c00000002000000')

    COMMIT_PAD = bytes.fromhex(
        '0000000000000000')

    COMMIT_TLV1 = bytes.fromhex(
        '020001000000')

    def _enroll_label_bytes(self, label_str):
        """
        Build identity label TLV for commit payload.
        Wire format: tag(2B LE=0x0203) + 0x00 + len(4B LE) + label + NUL.
        Max label_str length: 7 chars (8B with NUL fits in fixed 136B payload).
        """
        assert len(label_str) <= 7, f"label too long: {label_str!r}"
        raw = label_str.encode("utf-8", errors="replace") + b"\x00"
        return b'\x02\x03\x00' + struct.pack('<I', len(raw)) + raw

    def _build_commit_payload_winbio(self, guid, sid, label, subfactor=None):
        """
        Build WinBIO-format commit payload (136 bytes).
        guid      -- 16 bytes from enroll_status response
        sid       -- 16 bytes (generated)
        label     -- string for identity label (max 7 chars)
        subfactor -- TLV1 value byte (default 0 = WINBIO_SUBTYPE_ANY);
                     set via COMMIT_SUBFACTOR env var for testing
        """
        if subfactor is None:
            subfactor = int(os.environ.get('COMMIT_SUBFACTOR', '0'), 0)
        tlv1 = b'\x02\x00\x01\x00' + bytes([subfactor]) + b'\x00'
        payload = (self.COMMIT_HEADER
                   + b'\x00' + guid
                   + self.COMMIT_IDENTITY_PREFIX
                   + sid
                   + b'\x00' * 48
                   + self.COMMIT_PAD
                   + tlv1
                   + self._enroll_label_bytes(label))
        # Pad to 136 bytes (total wire = 138 with 2-byte opcode 9603).
        assert len(payload) <= 136, f"commit payload too large: {len(payload)}"
        return payload + b'\x00' * (136 - len(payload))

    def _build_commit_payload_fprint(self, guid, finger=FpFinger.UNKNOWN,
                                     username=None):
        """
        Build libfprint-format commit payload (136 bytes).

        The 119 bytes after COMMIT_HEADER+sep+GUID are a NUL-terminated
        UTF-8 string in libfprint ID format, zero-padded:
          FP1-{YYYYMMDD}-{finger_hex1}-{rand8_hex_upper}-{username}

        guid     -- 16 bytes from enroll_status response
        finger   -- FpFinger enum value (default UNKNOWN=0)
        username -- str (default: current OS username, truncated to 32 chars)
        """
        if username is None:
            username = getpass.getuser()[:32]
        date_str  = datetime.now().strftime('%Y%m%d')
        rand_part = os.urandom(4).hex().upper()
        fp_id     = (f"FP1-{date_str}-{int(finger):x}"
                     f"-{rand_part}-{username}")
        id_bytes  = fp_id.encode('utf-8') + b'\x00'
        # 136 - 17 (COMMIT_HEADER=16 + sep=1 + guid=16 wait... recount)
        # COMMIT_HEADER=16, sep=1, guid=16 -> prefix=33; free=136-33=103
        free = 136 - len(self.COMMIT_HEADER) - 1 - 16
        assert len(id_bytes) <= free, \
            f"fprint ID too long ({len(id_bytes)}B > {free}B): {fp_id!r}"
        payload = (self.COMMIT_HEADER
                   + b'\x00' + guid
                   + id_bytes
                   + b'\x00' * (free - len(id_bytes)))
        assert len(payload) == 136, f"commit payload size wrong: {len(payload)}"
        return payload

    def _build_commit_payload(self, guid, finger=FpFinger.UNKNOWN,
                              username=None):
        """
        Dispatch to WinBIO or libfprint commit payload builder.
        WinBIO format is used when COMMIT_WINBIO=1 is set, or when
        USE_WINE_PAIRING_DATA is set (pairing came from Wine registry,
        so b.exe compatibility is expected).
        Default is libfprint format.
        """
        if os.environ.get('COMMIT_WINBIO') or os.environ.get('USE_WINE_PAIRING_DATA'):
            sid   = _rand(16)
            label = (f"FP{os.urandom(2).hex()}")[:7]
            return self._build_commit_payload_winbio(guid, sid, label)
        return self._build_commit_payload_fprint(guid, finger, username)

    def get_enroll_status(self):
        """
        Send status_query enrollment status query.

        Returns EnrollStatus(status, guid, sample_cnt, progress_sum,
                             samples_used, size_flag) or None:
          status:     LE16 at [0:2]  (0 = ok/continuing)
          guid:       bytes at [2:18] (16B, None if not complete)
          sample_cnt: LE16 at [22:24] (None if unavailable)
          progress_sum: LE16 at [24:26] (None if unavailable)
          samples_used: LE16 at [52:54] (None if unavailable)
          size_flag:    LE32 at [48:52] (None if unavailable)

        progress_sum and sample_cnt plateau when the device has
        extracted enough data and enrollment is ready to finalize.
        """
        resp = CMD_ENROLL_STATUS.send(self)
        if resp is None:
            return None
        rlen = len(resp)
        status       = struct.unpack_from('<H', resp, 0)[0] if rlen >= 2 else 0xffff
        guid         = resp[2:18] if rlen >= 18 else NULL_GUID
        if guid == NULL_GUID:
            guid = None
        sample_cnt   = struct.unpack_from('<H', resp, 22)[0] if rlen >= 24 else None
        progress_sum = struct.unpack_from('<H', resp, 24)[0] if rlen >= 54 else None
        samples_used = struct.unpack_from('<H', resp, 52)[0] if rlen >= 54 else None
        size_flag    = struct.unpack_from('<I', resp, 48)[0] if rlen >= 54 else None
        return EnrollStatus(status, guid, sample_cnt, progress_sum, samples_used, size_flag)

    def storage_commit(self, payload):
        """
        Send 9603 commit payload (CH_STORE, storage layer).
        Saves identity (GUID, SID, label) to device storage.
        Returns response bytes or None.
        """
        return CMD_STORAGE_COMMIT.send(self, arg=payload)

    def engine_commit_ack(self):
        """
        Send 9604 commit ack (value=2, engine/sensor layer).
        Releases enrollment session resources on the engine side
        after storage_commit() has saved the identity.
        Returns response bytes or None.
        """
        return CMD_ENGINE_COMMIT_ACK.send(self)

    def discard_enrollment(self):
        """
        Abort an in-progress enrollment session.

        Sends 9604 (ENGINE_COMMIT_ACK) to abort on the device side,
        then calls cancel_session() to reset the USB device and turn
        off the LED.
        """
        print("  Sending enrollment abort (9604)...")
        try:
            self.engine_commit_ack()
        except Exception:
            pass
        self.cancel_session()

    def delete_record(self, entry):
        """
        Select + delete a single record by its 16-byte entry data.

        The entry can be obtained from _list_entries() (9f01) or
        from get_storage_count() GUIDs.
        Returns True on success.
        """
        if self.select_entry(entry) is None:
            return False
        dr = self.delete_entry(entry)
        return dr is not None and dr.status == DELETE_STATUS_OK

    def _find_managers(self, entries):
        """Given a list of 16-byte entry handles from FETCH_FIRST,
        return the subset whose a001 record_ref is all zeros
        (manager entries). Each manager owns exactly one GUID slot."""
        managers = []
        for ent in entries:
            ei = self.select_entry(ent)
            if ei is not None and ei.record_ref == b'\x00' * 8:
                managers.append(ent)
        return managers

    def _is_accessible_guid(self, guid):
        """Check if a GUID is accessible in the current TLS session.
        9f03 returns status=0000 + 16B record handle (20B total) for
        accessible GUIDs; shorter responses (e.g. 4B 00000000) mean
        the GUID belongs to a different pairing namespace."""
        rec = self.fetch_record(guid)
        return rec is not None

    def _record_to_entry(self, record_handle):
        """Map a record handle to its associated entry handle via a201.

        a201(record_handle16B) -> 20B response:
          [0:4]  status (0000 0000 = OK)
          [4:20] entry handle (16B)

        Returns RecordToEntry(entry_handle) or None on failure.
        """
        r = CMD_RECORD_TO_ENTRY.send(self, record_handle)
        if r is None or len(r) < 20 or r[:4] != b'\x00\x00\x00\x00':
            return None
        return RecordToEntry(r[4:20])

    def select_entry(self, entry):
        """Select an entry handle via a001.
        Returns EntryInfo(flags, record_ref) or None on error.
          flags      -- LE32 at [0:4]  (0x00000001 = occupied)
          record_ref -- bytes [4:12]   (first 8B of record handle, zeros = manager)
        """
        r = CMD_SELECT_ENTRY.send(self, entry)
        if r is None or len(r) < 12:
            return None
        flags      = struct.unpack_from('<I', r, 0)[0]
        record_ref = r[4:12]
        return EntryInfo(flags, record_ref)

    def delete_entry(self, entry, label="DELETE_ENTRY"):
        """Delete an entry handle via a301.
        Returns DeleteResult(status) or None on error.
          status == DELETE_STATUS_OK    (0x00000300) -> deleted successfully
          status == DELETE_STATUS_EMPTY (0x00000100) -> entry was already empty
        """
        r = CMD_DELETE_ENTRY.send(self, entry, label=label)
        if r is None or len(r) < 4:
            return None
        return DeleteResult(struct.unpack_from('<I', r, 0)[0])

    def delete_record_by_guid(self, guid, force=False):
        """Attempt to delete a single record by GUID.

        The device firmware provides no API to map a GUID to its
        owning manager entry.  The only known working approach is a
        destructive probe: delete each manager entry in turn and
        check whether the target GUID disappears -- but this
        irrecoverably deletes any other GUIDs whose manager happens
        to be probed first.

        By default this method refuses to proceed and returns False
        with a clear error.  Pass force=True to allow the destructive
        probe.  Only GUIDs accessible in the current TLS session can
        be deleted.

        Returns True on success; False otherwise.
        """
        self.storage_query_init(1)
        self.storage_query_init(2)
        all_guids = self.storage_query_all()

        if guid not in all_guids:
            print(f"  ERROR: GUID {guid.hex()} not found in device storage")
            return False

        # Verify GUID is accessible in the current pairing namespace
        r = self.fetch_record(guid)
        if not r:
            print(f"  ERROR: GUID {guid.hex()} belongs to a different"
                  f" pairing session -- cannot delete.")
            return False

        if not force:
            print(
                f"  ERROR: cannot delete a single GUID safely.\n"
                f"\n"
                f"  The device provides no API to map a GUID to its\n"
                f"  owning manager entry.  The only known working method\n"
                f"  is a destructive probe that deletes manager entries\n"
                f"  one by one until the target GUID disappears -- any\n"
                f"  other GUID whose manager is probed first will be\n"
                f"  irrecoverably lost.\n"
                f"\n"
                f"  To delete ALL accessible GUIDs in this session's\n"
                f"  namespace safely, use: clear-local-db\n"
                f"\n"
                f"  To proceed with the destructive probe anyway, pass\n"
                f"  --force to the delete-record command."
            )
            return False

        # --- Destructive probe (force=True) ---
        print(f"  WARNING: destructive probe -- other GUIDs may be"
              f" deleted as a side-effect.")
        entries = self._list_entries()
        managers = self._find_managers(entries)
        _log(f"  {len(managers)} managers found; probing...")
        for mgr in managers:
            dr = self.delete_entry(mgr, label="PROBE_DELETE")
            if dr is None or dr.status != DELETE_STATUS_OK:
                continue
            self.storage_query_init(1)
            self.storage_query_init(2)
            after = self.storage_query_all()
            if guid not in after:
                _log(f"  manager {mgr.hex()} owned target GUID -- removed")
                return True
            _log(f"  manager {mgr.hex()} deleted a different GUID")
        print(f"  ERROR: probe exhausted -- target GUID not removed")
        return False

    def probe_guid(self, guid):
        """Non-destructive probe: trace the a201 chain for a GUID
        and try a003 on all managers to find which one knows the GUID.

        Does NOT delete anything.
        """
        print(f"Probing {guid.hex()}...")

        self.storage_query_init(1)
        self.storage_query_init(2)
        all_guids = self.storage_query_all()

        r = self.fetch_record(guid)
        if not r:
            print("  Not accessible (wrong namespace or not found)")
            return
        record_handle = r.handle
        print(f"  record_handle : {record_handle.hex()}")

        # a201 chain
        r2 = self._record_to_entry(record_handle)
        if r2 is not None:
            entry1 = r2.entry_handle
            ei1 = self.select_entry(entry1)
            is_mgr1 = (ei1 is not None and ei1.record_ref == b'\x00' * 8)
            print(f"  entry1 (a201) : {entry1.hex()}  manager={is_mgr1}")
            print(f"  a001(entry1)  : {ei1}")

            r4 = self._record_to_entry(entry1)
            if r4 is not None:
                entry2 = r4.entry_handle
                ei2 = self.select_entry(entry2)
                is_mgr2 = (ei2 is not None and ei2.record_ref == b'\x00' * 8)
                print(f"  entry2 (chain): {entry2.hex()}  manager={is_mgr2}")
                print(f"  a001(entry2)  : {ei2}")
            else:
                print(f"  a201(entry1)  : None (no chain)")

        # Try a003 on each manager -- a003 returns GUID at [16:32] for records;
        # if it works on managers too, we can identify manager->GUID mapping.
        # Also try: a201(manager) -> intermediate entry -> a001 to get record ref.
        # This gives manager -> record_handle[0:8] -> GUID mapping.
        print("\n  Scanning managers with a003/a201 chain:")
        entries = self._list_entries()
        managers = self._find_managers(entries)
        # Build record_handle prefix map for accessible GUIDs
        rh_prefix_to_guid = {}
        for g in all_guids:
            rh_r = self.fetch_record(g)
            if rh_r:
                rh_prefix_to_guid[rh_r.handle[:8]] = g
        for mgr in managers:
            r_a3 = self.select_record(mgr, label="A003_mgr")
            a201_r = self._record_to_entry(mgr)
            owner_guid = None
            if a201_r is not None:
                mid_entry = a201_r.entry_handle
                ei_mid = self.select_entry(mid_entry)
                if ei_mid is not None:
                    owner_guid = rh_prefix_to_guid.get(ei_mid.record_ref)
            print(f"    mgr {mgr.hex()[:16]}..."
                  f"  a003={'guid='+r_a3.guid.hex() if r_a3 else 'None'}"
                  f"  owner_guid={owner_guid.hex() if owner_guid else 'unknown'}")

    def probe_managers(self):
        """Map every manager entry to its owned GUID (non-destructive).

        Strategy: each manager has satellite entries whose a001[4:12]
        == manager[0:8].  One of those satellites, when followed via
        a201, reaches an entry whose a001[4:12] matches the
        record_handle[0:8] of an accessible GUID.

        Prints the manager->GUID table; also shows unresolved managers
        (belonging to foreign namespaces whose record handles we cannot
        fetch).  Does NOT delete anything.
        """
        from collections import defaultdict

        # --- entries first (before any 9f02/9f03 which shift cursor) ---
        entries = self._list_entries()
        print(f"  {len(entries)} total entries")

        managers, non_mgr = [], []
        for ent in entries:
            ei = self.select_entry(ent)
            if ei is None:
                pass
            elif ei.record_ref == b'\x00' * 8:
                managers.append(ent)
            else:
                non_mgr.append((ent, ei.record_ref))
        print(f"  {len(managers)} managers, {len(non_mgr)} non-manager entries")

        ref_to_ents = defaultdict(list)
        for ent, ref in non_mgr:
            ref_to_ents[ref].append(ent)

        # --- now fetch GUIDs and record handles ---
        self.storage_query_init(1)
        self.storage_query_init(2)
        all_guids = self.storage_query_all()
        guid_to_rh = {}
        for g in all_guids:
            rr = self.fetch_record(g)
            if rr:
                guid_to_rh[g] = rr.handle
        rh_prefix_to_guid = {rh[:8]: g for g, rh in guid_to_rh.items()}
        print(f"  {len(all_guids)} GUIDs, {len(guid_to_rh)} accessible")

        # --- map each manager to a GUID ---
        # Strategy:
        #   GUID -> rh -> direct_entry (a001[4:12] == rh[0:8])
        #   manager -> satellites (entries whose a001[4:12] == mgr[0:8])
        #   If any satellite == direct_entry, that manager owns the GUID.
        # This works because non-manager entries whose ref == rh[0:8] are
        # the record's "slot" entries, and one of them is a satellite of
        # the owning manager.
        print("\n  Manager -> GUID mapping:")
        mgr_to_guid = {}

        # Build: entry_handle -> manager that has it as a satellite
        entry_to_mgr = {}
        for mgr in managers:
            for sat in ref_to_ents.get(mgr[:8], []):
                entry_to_mgr[bytes(sat)] = mgr

        for g, rh in guid_to_rh.items():
            # Find all entries directly referencing this record_handle
            direct_entries = ref_to_ents.get(rh[:8], [])
            found_mgr = None
            for de in direct_entries:
                mgr = entry_to_mgr.get(bytes(de))
                _log(f"    GUID {g.hex()[:8]} de={de.hex()[:16]}"
                     f" mgr={mgr.hex()[:16] if mgr is not None else 'None'}")
                if mgr is not None:
                    found_mgr = mgr
                    break
            if found_mgr is not None:
                mgr_to_guid[bytes(found_mgr)] = g
                print(f"    {found_mgr.hex()[:16]}...  -> {g.hex()[:8]}"
                      f"  (via direct entry {de.hex()[:16]})")
            else:
                print(f"    ??? no manager found for GUID {g.hex()[:8]}"
                      f"  (direct_entries={len(direct_entries)})")

        # Report managers not yet assigned (foreign namespace)
        for mgr in managers:
            if bytes(mgr) not in mgr_to_guid:
                print(f"    {mgr.hex()[:16]}...  -> foreign/unknown")

        # --- also report direct rh-prefix matches in entry refs ---
        print("\n  Direct rh-prefix matches in entry refs:")
        for g, rh in guid_to_rh.items():
            matched = ref_to_ents.get(rh[:8], [])
            print(f"    {g.hex()[:8]}  rh={rh.hex()[:16]}  "
                  f"direct_entry_matches={len(matched)}")

        return mgr_to_guid

    def close_notify(self):
        """Send TLS close_notify alert. Returns response."""
        return CMD_CLOSE_NOTIFY.send(self, ctype=TLS_ALERT)

    def reset_ownership(self):
        """
        Unpair device: clear local PairingData and reset device state.

        Replicates windows driver reset-ownership: sends IOCTL-equivalent to
        device, closes TLS, REQ_SHUTDOWN, then deletes pairing.dat.
        No USB unpair command exists on this device - it's a
        software-only operation (registry cleanup on Windows).
        """
        print("\n--- Reset Ownership ---")
        if os.path.exists(PAIRING_FILE):
            print("  Deleting local PairingData...")
            os.unlink(PAIRING_FILE)
            print("  OK")
        else:
            print("  No local PairingData found")
        print("  Sending REQ_SHUTDOWN...")
        try:
            self.dev.ctrl_transfer(BM_OUT, REQ_SHUTDOWN, 0, 0, [],
                                   timeout=1000)
            self.dev.ctrl_transfer(BM_IN, REQ_SHUTDOWN_ACK, 0, 0, 2,
                                   timeout=1000)
        except Exception as exc:
            _log(f"  REQ_SHUTDOWN: {exc}")
        print("  Device unpaired")
        return True

    def _load_record_for_match(self, guid):
        """
        Load an enrolled record into the matching engine.
        Returns True on success.
        Sequence: 9f03 (FETCH_RECORD) → a003 (SELECT) → a103 (LOAD_TEMPLATE)
        """
        r = self.fetch_record(guid)
        if not r:
            return False
        entry = r.handle
        r = self.select_record(entry, label="SELECT_MATCH")
        if not r:
            return False
        return self.load_template(entry) is not None

    def _print_match(self, matched):
        """Fetch and print label/subfactor for a matched GUID."""
        print(f"  Match found! GUID: {matched.hex()}")
        rec  = self.fetch_record(matched)
        tmpl = self.load_template(rec.handle) if rec else None
        if tmpl:
            label_str = f"  label='{tmpl.label}'" if tmpl.label else ""
            print(f"  subfactor=0x{tmpl.subfactor:02x}{label_str}" if tmpl.subfactor is not None else f"  {label_str}")

    def match_result(self):
        """
        Send 9901 match result query.

        Response layout (66 bytes, from Ghidra/static analysis):
          [0x00:0x02]  status code (u16 LE): 0x0000=match, 0x0509=no-match
          [0x02:0x12]  GUID (16 bytes)
          [0x12:0x16]  qm_struct_size (u32 LE, expected 0x24=36)
          [0x16:0x1e]  extra sizes (2x u32)
          [0x1e:0x22]  matchScore     (i32 LE)  -- Match-on-Chip result
          [0x22:0x26]  matchIndex     (u32 LE)
          [0x26:0x2a]  matchStrength  (u32 LE)
          [0x2a:0x2e]  templateUpdate (u32 LE)  -- inferred; qm+12 not explicit in decompiled code
          [0x2e:0x42]  remaining qm fields (20 bytes)

        Returns MatchResult(status, guid, score, index, strength, template_update)
        or None on TLS error.
        """
        r = CMD_MATCH_RESULT.send(self)
        if not r or len(r) < 2:
            return None
        status = struct.unpack('<H', r[:2])[0]
        guid = r[0x02:0x12] if len(r) >= 18 else None

        score = index = strength = template_update = None
        if (len(r) >= 0x42
                and struct.unpack('<I', r[0x12:0x16])[0] == 0x24):
            score           = struct.unpack('<i', r[0x1e:0x22])[0]
            index           = struct.unpack('<I', r[0x22:0x26])[0]
            strength        = struct.unpack('<I', r[0x26:0x2a])[0]
            template_update = struct.unpack('<I', r[0x2a:0x2e])[0]

        return MatchResult(status, guid, score, index, strength, template_update)

    def identify_all(self):
        """
        Full identify-all sequence matching windows driver trace.
        Loads all enrolled records, captures a finger, matches
        against all loaded templates, and returns the matched
        16-byte GUID (or None if no match / error).
        """
        print("\n--- Identify All ---")

        # 1. Load all enrolled records into matching engine
        guids = self.get_storage_count()
        _log(f"Storage count: {len(guids)}")

        loaded = 0
        for guid in guids:
            if guid == NULL_GUID:
                continue
            print(f"  Loading {guid.hex()}...")
            if self._load_record_for_match(guid):
                loaded += 1
                print(f"    OK")
            else:
                print(f"    FAILED")
        if loaded == 0:
            print("  No records to match against")
            return None
        print(f"  Loaded {loaded} record(s)")

        # 3. List entries + SELECT per entry
        entries = self._list_entries()
        for ent in entries:
            self.select_entry(ent)

        # 4. Capture finger
        print("\n  Touch and hold the sensor...")
        cap = self.capture_data()
        if not cap.raw or cap.sensor_status != 1:
            print("  No finger detected")
            return None
        # 5. Interrupt 1 (capture armed)
        i1 = self.read_interrupt(timeout=60000)
        if i1 is None:
            print("  Finger removed")
            return None
        _log(f"  Interrupt 1: {i1.hex()}")
        self._print_sensor_status(cap.ctx, label="armed: ")

        # 6. Pre-capture queries
        self.query_status_ext(4)
        self.query_enrollment_needs()

        ext1 = self.query_status_ext(1)
        print(f"  Progress: {ext1.progress}")

        # UPDATE_CHECK with 8014 (identify variant)
        r = CMD_UPDATE_IDENT_CHECK.send(self, label="UPDATE_IDENTIFY_CHECK")
        if r is None:
            _log("  UPDATE_IDENTIFY_CHECK failed")

        # 7. Interrupt 2 (data captured)
        i2 = self.read_interrupt(timeout=60000)
        if i2 is None:
            print("  Finger removed before capture complete")
            return None
        _log(f"  Interrupt 2: {i2.hex()}")

        # 8. Post-capture queries
        self._print_sensor_status(label="captured: ")
        self.query_enrollment_simple()
        self.query_status_ext(4)
        self.update_enrollment_ack()

        # 9. Match result
        mr = self.match_result()
        if mr is None:
            print("  MATCH_RESULT failed (TLS error)")
            return None
        _log(f"  match: {mr}")
        if mr.status != 0:
            print(f"  No match (status=0x{mr.status:04x})")
            return None
        if mr.guid is None or mr.guid == NULL_GUID:
            print("  MATCH_RESULT returned zero GUID")
            return None
        self._print_match(mr.guid)
        return mr.guid

    def identify(self):
        """
        Single-shot identify.  Assumes the matching engine already has
        templates loaded (from a prior identify-all or verify call).
        Captures a finger, matches, returns the matched GUID or None.
        """
        print("\n--- Identify ---")
        print("\n  Touch and hold the sensor...")
        cap = self.capture_data()
        if not cap.raw or cap.sensor_status != 1:
            print("  No finger detected")
            return None
        self._print_sensor_status(cap.ctx, label="capture: ")

        i1 = self.read_interrupt(timeout=60000)
        if i1 is None:
            print("  Finger removed"); return None
        self._print_sensor_status(cap.ctx, label="armed:   ")

        self.query_status_ext(4)
        self.query_enrollment_needs()

        ext1 = self.query_status_ext(1)
        print(f"  Progress: {ext1.progress}")

        CMD_UPDATE_IDENT_CHECK.send(self, label="UPDATE_IDENTIFY_CHECK")

        i2 = self.read_interrupt(timeout=60000)
        if i2 is None:
            print("  Finger removed before capture complete")
            return None

        self._print_sensor_status(label="captured: ")
        self.query_enrollment_simple()
        self.query_status_ext(4)
        self.update_enrollment_ack()

        mr = self.match_result()
        if mr is None:
            print("  MATCH_RESULT failed (TLS error)")
            return None
        _log(f"  match: {mr}")
        if mr.status != 0:
            print(f"  No match (status=0x{mr.status:04x})")
            return None
        if mr.guid is None or mr.guid == NULL_GUID:
            print("  MATCH_RESULT returned zero GUID")
            return None
        self._print_match(mr.guid)
        return mr.guid

    def _list_entries(self):
        """Fetch all entry blobs via 9f01. Returns list of 16-byte handles.
        Must init storage before FETCH_FIRST (device rejects with TLS
        Alert 022f otherwise, corrupting the session)."""
        self.storage_query_init(1)
        self.storage_query_init(2)
        resp = CMD_FETCH_FIRST.send(self)
        if resp is None or len(resp) < 4:
            return []
        nentries = struct.unpack('<H', resp[2:4])[0]
        return [resp[4 + i*16 : 4 + (i+1)*16]
                for i in range(min(nentries, (len(resp)-4)//16))]

    def _delete_managers_at_indices(self, indices, managers):
        """Delete manager entries at the given positional indices.

        indices  -- list of int, positions within the managers list
        managers -- ordered list of 16-byte manager entry handles
                    (same order as GUIDs in 9f02 response)

        Returns True if all deletions returned 00000300; False otherwise.
        """
        ok = True
        for idx in indices:
            if idx >= len(managers):
                print(f"  ERROR: manager index {idx} out of range"
                      f" ({len(managers)} managers)")
                ok = False
                continue
            ent = managers[idx]
            dr = self.delete_entry(ent, label="DELETE_MANAGER")
            if dr is None or dr.status != DELETE_STATUS_OK:
                print(f"  WARNING: delete[{idx}] returned {dr}")
                ok = False
        return ok

    def erase_database(self):
        """
        Erase ALL records and entry handles from device storage.

        Deletes every entry handle returned by 9f01 (FETCH_FIRST) via
        a301 DELETE_ENTRY. This covers both manager entries (which hold
        GUID references) and accumulated ghost slot entries. After this,
        9f02 returns empty and 9f01 returns 0 (firmware re-creates one
        fresh session entry on the next TLS connect).

        No a401/a402/a403 finalise needed -- confirmed experimentally.
        """
        entries = self._list_entries()
        print(f"  {len(entries)} entries to delete")
        deleted = 0
        for e in entries:
            dr = self.delete_entry(e)
            if dr is not None:
                deleted += 1
        print(f"  {deleted} deleted")

        # Verify
        self.storage_query_init(1)
        self.storage_query_init(2)
        remaining = self.storage_query_all()
        if remaining:
            print(f"  WARNING: {len(remaining)} GUIDs still present")
        else:
            print("  OK -- no records remain")
        return not remaining

    def _finalise_storage(self):
        """Send a401/a402/a403 finalise sequence (windows driver clear-db compat).

        Returns True on success.
        """
        for cmd in (CMD_STORAGE_WIPE_1, CMD_STORAGE_WIPE_2, CMD_STORAGE_WIPE_3):
            r = cmd.send(self)
            if r is None:
                print(f"  {cmd.label} failed")
                return False
        return True

    def erase_database_compat(self):
        """
        Erase enrolled records using the windows driver clear-db sequence.

        Mirrors what the Windows driver does: loads all templates, then
        deletes only manager entries (a001=all-zeros) via a301, then
        finalises with a401/a402/a403. Ghost slot entries are NOT
        removed (they accumulate over time). Use erase_database() for
        a full wipe including ghost slots.
        """
        print("  Fetching records...")
        self.storage_query_init(1)
        self.storage_query_init(2)
        guids = self.storage_query_all()
        print(f"  {len(guids)} GUIDs in index")

        # Load all templates (host-side prep before delete, per windows driver)
        for guid in guids:
            rec = self.fetch_record(guid)
            if rec:
                self.select_record(rec.handle)
                self.load_template(rec.handle)

        # Delete only manager entries (a001 returns all zeros)
        entries = self._list_entries()
        print(f"  {len(entries)} entries found")
        managers = self._find_managers(entries)
        print(f"  {len(managers)} manager entries to delete")
        self._delete_managers_at_indices(range(len(managers)), managers)

        if not self._finalise_storage():
            return False

        # Verify
        self.storage_query_init(1)
        self.storage_query_init(2)
        remaining = self.storage_query_all()
        if remaining:
            print(f"  WARNING: {len(remaining)} GUIDs still present")
        else:
            print("  OK -- no records remain")
        return not remaining

    def clear_local_db(self):
        """
        Delete only GUIDs accessible in the current pairing namespace.

        Foreign-namespace GUIDs (enrolled under a different pairing
        session) are left untouched. Iterates manager entries one by
        one, checking 9f02 after each deletion to detect which GUID
        disappeared and whether it was ours.

        Use erase_database() to wipe everything unconditionally.
        """
        print("  Querying records...")
        self.storage_query_init(1)
        self.storage_query_init(2)
        all_guids = self.storage_query_all()

        accessible = set(
            g for g in all_guids if self._is_accessible_guid(g)
        )
        if not accessible:
            print("  No accessible GUIDs in current namespace")
            return True
        n_foreign = len(all_guids) - len(accessible)
        print(f"  {len(accessible)} accessible GUID(s) to delete"
              f" ({n_foreign} foreign, skipped)")

        remaining_accessible = set(accessible)
        all_guids_set = set(all_guids)
        deleted = 0

        while remaining_accessible:
            entries = self._list_entries()
            managers = self._find_managers(entries)
            _log(f"  {len(managers)} manager entries found")
            if not managers:
                print("  ERROR: no managers left but accessible GUIDs"
                      " still reported -- aborting")
                break

            progress = False
            for mgr in managers:
                dr = self.delete_entry(mgr, label="DELETE_MANAGER")
                if dr is None or dr.status != DELETE_STATUS_OK:
                    _log(f"  a301 returned {dr} -- skip")
                    continue
                # Check what disappeared from the full GUID set
                self.storage_query_init(1)
                self.storage_query_init(2)
                after = set(self.storage_query_all())
                all_gone = all_guids_set - after
                foreign_gone = all_gone - accessible
                if foreign_gone:
                    print(f"  ERROR: deleted a foreign GUID"
                          f" {next(iter(foreign_gone)).hex()} --"
                          f" aborting to avoid further damage")
                    return False
                our_gone = all_gone & accessible
                if our_gone:
                    for g in our_gone:
                        _log(f"  deleted GUID {g.hex()}")
                        deleted += 1
                    remaining_accessible -= our_gone
                    all_guids_set = after
                    progress = True
                    break  # restart manager scan (handles are stale)
                else:
                    _log(f"  manager {mgr.hex()[:16]} deleted but no"
                         f" GUID disappeared -- continuing")

            if not progress:
                print("  ERROR: no progress in manager sweep --"
                      " aborting to avoid infinite loop")
                break

        # Verify
        self.storage_query_init(1)
        self.storage_query_init(2)
        remaining = self.storage_query_all()
        still_accessible = [g for g in remaining
                            if self._is_accessible_guid(g)]
        if still_accessible:
            print(f"  WARNING: {len(still_accessible)} accessible"
                  f" GUID(s) still present")
            return False
        print(f"  OK -- deleted {deleted} GUID(s),"
              f" {len(remaining)} foreign GUID(s) remain")
        return True

    def _commit_enrollment(self, guid, finger=FpFinger.UNKNOWN, username=None):
        """
        Full commit finalization sequence (5 steps + close).
        Must be called after 5 successful enrollment samples.
        """
        print("\n--- Commit enrollment ---")
        print(f"  GUID: {guid.hex()}")

        # Step 2: Submit fixed template
        print("  Sending enrollment template...")
        resp = CMD_ENROLL_TEMPLATE.send(self)
        if resp is None:
            print("  ENROLL_TEMPLATE failed (TLS error)")
            return False
        ts = self._parse_template_status(resp)
        if ts.status != 0:
            print(f"  ENROLL_TEMPLATE rejected:"
                  f" TemplateStatus=0x{ts.status:08x}"
                  f" PercentComplete={ts.percent_complete} RejectDetail=0x{ts.reject_detail:x}")
            return False
        print(f"  Template response: {resp.hex()}")
        _log(f"  {ts}")

        # Step 3: Build + send commit payload
        payload = self._build_commit_payload(guid, finger, username)
        _hexdump(f"Commit plain ({len(payload)}B)", payload)
        print(f"  Sending commit ({len(payload)}B)...")
        resp = self.storage_commit(payload)
        if resp is None:
            print("  STORAGE_COMMIT failed (TLS Alert)")
            if self.tls:
                _log(f"  client_seq={self.tls.client_seq} server_seq={self.tls.server_seq}")
            return False
        print(f"  Commit response: {resp.hex()}")

        # Step 4: Storage query init
        print("  Storage query...")
        resp = CMD_STORAGE_QUERY_INIT.send(self, label="COMMIT_STORAGE_QUERY")
        if resp is None:
            print("  Storage query failed")
            return False
        print(f"  Storage query resp ({len(resp)}B): {resp[:16].hex()}...")

        # Step 5: Engine commit ack (release enrollment session)
        print("  Engine ack...")
        resp = self.engine_commit_ack()
        if resp is None:
            print("  ENGINE_COMMIT_ACK failed")
            return False
        print(f"  Ack response: {resp.hex()}")

        # Step 6: Close notify
        print("  Close notify...")
        resp = self.close_notify()
        print(f"  Close: {resp.hex() if resp else None}")

        print("  Commit done!")
        return True

    @staticmethod
    def _parse_template_status(resp):
        """
        Parse ENROLL_TEMPLATE (39f4) response.
        Returns (status, percent_complete, reject_detail).
        status == 0 means success.
        Response is either `0000` (2B success) or a 66-byte STATUS_EXT-
        like struct with details at offsets:
          [2:6]  - TemplateStatus (LE u32)
          [12:16] - PercentComplete (LE u32)
          [8:12]  - RejectDetail (LE u32)
        """
        if resp is None or len(resp) < 2:
            return TemplateStatus(-1, 0, 0)
        if resp == b'\x00\x00' or resp == b'\x00\x00\x00\x00':
            return TemplateStatus(0, 0, 0)
        if len(resp) < 16:
            return TemplateStatus(-1, 0, 0)
        ts_raw = struct.unpack('<I', resp[2:6])[0]
        ts = 0 if ts_raw in (0, 6) else ts_raw
        pc = struct.unpack('<I', resp[12:16])[0]
        rd = struct.unpack('<I', resp[8:12])[0]
        return TemplateStatus(ts, pc, rd)

    def _enroll_one_sample(self, sample_num, max_samples):
        """One enrollment sample, matching windows driver trace exactly.

        Always completes the full 11-command sequence, even on errors,
        to keep device protocol state consistent.  Returns:
          (True, guid)  -- enrollment complete, commit now
          (True, None)  -- good sample, keep going
          (False, None) -- error (no finger, bad scan, etc.), skip
        """
        print(f"\n--- Sample {sample_num}/{max_samples} ---")
        print("  Touch and hold the sensor...")
        _log(f"  _enroll_one_sample started")

        cap = self.capture_data()
        ok = cap.raw is not None and cap.sensor_status == 1
        if cap.raw is None:
            print("  CAPTURE_DATA failed")
        elif cap.sensor_status != 1:
            print("  No finger detected")
            return False, None

        self._print_sensor_status(cap.ctx, label="capture: ")

        # Interrupt 1: capture armed (01) -- immediate after CAPTURE
        i1 = self.read_interrupt(timeout=60000)
        if i1 is None:
            print("  Finger removed before capture complete")
            return False, None
        i1_type = i1[0] if len(i1) > 0 else 0
        _log(f"  Interrupt raw: {i1.hex()}")
        print(f"  Interrupt: type=0x{i1_type:02x}"
              f" ({'capture armed' if i1_type==1 else 'data captured' if i1_type==2 else 'unknown'})")
        self._print_sensor_status(cap.ctx, label="armed:   ")

        # Pre-capture queries (finger is being placed/held)
        self.query_status_ext(4)
        r = self.query_enrollment_needs()
        if r is None:
            print("  QUERY_ENROLL_NEEDS failed")

        ext1 = self.query_status_ext(1)
        print(f"  Progress: {ext1.progress}")

        self.update_enrollment_check()

        # Interrupt 2: finger data captured (02)
        i2 = self.read_interrupt(timeout=60000)
        if i2 is None:
            print("  Finger removed before capture complete")
            ok = False
        else:
            i2_type = i2[0] if len(i2) > 0 else 0
            _log(f"  Interrupt raw: {i2.hex()}")
            print(f"  Interrupt: type=0x{i2_type:02x}"
                  f" ({'capture armed' if i2_type==1 else 'data captured' if i2_type==2 else 'unknown'})")

        # Post-capture queries
        self._print_sensor_status(label="captured: ")
        self.query_enrollment_simple()
        ext4b = self.query_status_ext(4)
        _log(f"  Ext4 progress: {ext4b.progress}")
        self.update_enrollment_ack()

        enroll = self.get_enroll_status()
        if enroll is None:
            print("  ENROLL_STATUS failed")
            return False, None
        print(f"  ENROLL_STATUS: status=0x{enroll.status:04x}"
              f" guid={'yes' if enroll.guid else 'no'}"
              f" sample_cnt={enroll.sample_cnt}"
              + (f" progress_sum={enroll.progress_sum}"
                 f" samples_used={enroll.samples_used}"
                 f" size_flag={enroll.size_flag}"
                 if enroll.progress_sum is not None else ""))

        # GUID present → enrollment complete, ready to commit
        if enroll.guid:
            print(f"  GUID: {enroll.guid.hex()}")
            return True, enroll.guid

        # Track progress via the two counters that change only when
        # the device makes real progress: sample_cnt [22:24] and
        # progress_sum [24:26].  When both plateau, the device has
        # extracted enough data.
        prev = getattr(self, '_prev_enroll_progress', None)
        changed = False
        if enroll.progress_sum is not None:
            if prev is not None:
                changed = (
                    enroll.sample_cnt != prev[0]
                    or enroll.progress_sum != prev[1])
            else:
                changed = True
            self._prev_enroll_progress = (enroll.sample_cnt, enroll.progress_sum)
            if not changed:
                plateau = getattr(self, '_enroll_plateau', 0) + 1
                self._enroll_plateau = plateau
                _log(f"  ENROLL plateau count={plateau}")
            else:
                self._enroll_plateau = 0
        elif enroll.sample_cnt is not None:
            sc_prev = getattr(self, '_prev_enroll_cnt', None)
            self._prev_enroll_cnt = enroll.sample_cnt
            if sc_prev is not None:
                changed = enroll.sample_cnt > sc_prev
                if changed:
                    self._enroll_plateau = 0
                else:
                    plateau = getattr(self, '_enroll_plateau', 0) + 1
                    self._enroll_plateau = plateau
            else:
                changed = True

        # 0x0680 = WINBIO_E_DATABASE_FULL
        if enroll.status == 0x0680:
            print(f"  Database full (status=0x{enroll.status:04x})")
            return False, enroll.status

        # 3 consecutive no-change → enrollment complete
        if not changed and getattr(self, '_enroll_plateau', 0) >= 3:
            print(f"  Enrollment progress plateaued - device cannot extract"
                  f" more data.  Aborting.")
            return False, 0x0002

        if changed:
            self._enroll_errors = 0
            print(f"  Sample {sample_num} OK")
            return True, None
        else:
            errs = (getattr(self, '_enroll_errors', 0) + 1)
            self._enroll_errors = errs
            if enroll.status != 0:
                print(f"  Capture rejected (status=0x{enroll.status:04x})"
                      f" {errs}/3 - lift and retry")
            else:
                print(f"  Finger released too early {errs}/3")
            if errs >= 3:
                print(f"  3 consecutive unproductive captures - aborting")
                return False, 0x0001
            return False, None

    def enroll(self, finger=FpFinger.UNKNOWN, username=None):
        """
        Full enrollment flow (interactive).
        Checks DB capacity first, then completes each sample fully.
        Errors (no finger, bad scan) are skipped without counting.
        """
        print("\n--- Enrollment ---")

        if username is None:
            username = getpass.getuser()[:32]
        print(f"  Finger: {FpFinger(finger).name}  User: {username}")

        # Check DB capacity (max ~10 records from WINBIO_E_DATABASE_FULL)
        guids = self.get_storage_count()
        print(f"  DB records: {len(guids)}")
        if len(guids) >= 10:
            ans = input("  Database is full! Try anyway? [y/N] ").strip().lower()
            if ans != 'y':
                print("  Enrollment cancelled.")
                return False

        r = self.enroll_begin()
        if r is None:
            print("  ENROLL_BEGIN failed")
            return False
        print(f"  ENROLL_BEGIN: {r.hex()}")

        self._prev_enroll_cnt = None
        self._prev_enroll_progress = None
        self._enroll_plateau = 0
        self._enroll_errors = 0
        max_attempts = 50
        self._enroll_active = True

        for i in range(1, max_attempts + 1):
            ok, guid = self._enroll_one_sample(i, max_attempts)
            if not ok:
                if isinstance(guid, int):
                    # Terminal error (3 bad captures, DB full, etc.)
                    print(f"  Terminal error code=0x{guid:04x}")
                    cnt = len(self.get_storage_count())
                    if cnt >= 10:
                        print(f"  Database has {cnt} records "
                              "(likely full). Clear some and retry.")
                    print("  Discarding enrollment...")
                    self.discard_enrollment()
                    self.restart_session()
                    self._enroll_active = False
                    return False
                continue        # transient error -- wait for next touch
            if guid is not None:
                self._enroll_active = False
                ok2 = self._commit_enrollment(guid=guid, finger=finger,
                                              username=username)
                if not ok2:
                    cnt = len(self.get_storage_count())
                    print(f"  DB records after failed commit: {cnt}")
                return ok2

        print("  Enrollment aborted after 50 attempts -- discarding...")
        self.discard_enrollment()
        self.restart_session()
        self._enroll_active = False
        return False


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in (
            'list-db', 'list-db-all', 'enroll', 'clear-db',
            'clear-db-compat', 'clear-local-db', 'identify-all', 'identify',
            'reset-ownership', 'delete-record', 'probe-guid',
            'probe-managers'):
        print("Usage: sensor.py list-db|list-db-all|enroll|clear-db|"
              "clear-db-compat|clear-local-db|identify-all|identify|"
              "reset-ownership|delete-record [guid <hex32>]|"
              "probe-guid <hex32>")
        sys.exit(1)

    print("Connecting to sensor...")
    sensor = BiometricSensor()
    sensor.find_device()

    # reset-ownership is a special case: no init, no TLS needed
    if sys.argv[1] == 'reset-ownership':
        sensor.reset_ownership()
        sensor.close()
        print("Done.")
        return

    print("Running init phases...")
    sensor.init_device()

    print("REQ_READY...")
    ready = sensor.req_ready()
    _log(f"REQ_READY = {ready.hex()}")

    # ----- Challenge / PairingData -----
    print("Loading PairingData...")
    tlvs = load_pairing_data()
    pair = get_pairing_fields(tlvs) if tlvs else None

    if pair:
        host_pubkey, client_privkey_le, client_cert, dev_x_be, dev_y_be, client_pubkey_x_le = pair
        client_privkey_be = client_privkey_le[::-1]
        print(f"  host_pubkey: {host_pubkey[:8].hex()}...")
        _log(f"  client_privkey_le: {client_privkey_le[:8].hex()}...")
        _log(f"  dev_x_be: {dev_x_be[:8].hex()}...")
        device_cert_for_save = None
        # Even with PairingData, check if device wants a challenge
        if ready and int.from_bytes(ready, 'little') != 0:
            print("  Device requests challenge (REQ_READY non-zero)")
            print("  Sending pairing challenge...")
            challenge_cert, challenge_device_cert = sensor.send_challenge(
                host_pubkey, client_privkey_be)
            # Device certificate has fresh device key - override stored values
            dev_x_be, dev_y_be = dev_key_from_tag3(challenge_device_cert)
            client_cert = challenge_cert
            client_pubkey_x_le = (challenge_cert[144:176]
                                   if len(challenge_cert) >= 176 else b'\x00' * 32)
            device_cert_for_save = challenge_device_cert
            _log(f"  Updated dev key from challenge: {dev_x_be[:8].hex()}...")
    else:
        print("  No PairingData -- generating fresh host identity")
        # Generate random host ECDSA key pair (the client identity for TLS)
        _host_privkey_int = int.from_bytes(os.urandom(32), 'big')
        _host_privkey_mod = NIST256p.order - 1
        _host_privkey_int = (_host_privkey_int % _host_privkey_mod) + 1
        _host_privkey_be  = _host_privkey_int.to_bytes(32, 'big')
        # Compute host public key blob from host pubkey
        _host_pubkey_Q = NIST256p.generator * _host_privkey_int
        _host_pubkey_x_le = _host_pubkey_Q.x().to_bytes(32, 'big')[::-1]
        _host_pubkey_y_le = _host_pubkey_Q.y().to_bytes(32, 'big')[::-1]
        host_pubkey = (b'\x3f\x5f\x17\x00' + _host_pubkey_x_le
                    + b'\x00' * 36 + _host_pubkey_y_le + b'\x00' * 38)
        client_privkey_be = _host_privkey_be   # for TLS CertVerify
        client_pubkey_x_le = _host_pubkey_x_le  # pubkey X for cert body
        print("  Sending pairing challenge...")
        try:
            challenge_cert, challenge_device_cert = sensor.send_challenge(
                host_pubkey, IDENTITY_D_BE)
            client_cert = challenge_cert
            client_pubkey_x_le = (challenge_cert[144:176]
                                   if len(challenge_cert) >= 176 else b'\x00' * 32)
            dev_x_be, dev_y_be = dev_key_from_tag3(challenge_device_cert)
            device_cert_for_save = challenge_device_cert
            print("  Challenge accepted")
        except (RuntimeError, ValueError) as exc:
            print(f"  Challenge failed: {exc}")
            print("  Cannot proceed without device key -- stopping")
            sensor.close()
            sys.exit(1)

    if sensor.serial:
        fw = sensor.firmware_version
        fw_str = f"{fw[0]}.{fw[1]}" if fw else "?"
        print(f"  Serial: {sensor.serial}  Firmware: {fw_str}")

    # ----- TLS handshake -----
    print("TLS handshake...")
    try:
        sensor.connect(host_pubkey, client_privkey_be, client_pubkey_x_le,
                       client_cert, dev_x_be, dev_y_be)
    except TlsAlertError as exc:
        print(f"  TLS handshake failed: {exc}")
        sensor.close()
        sys.exit(1)
    print("  TLS OK")

    # ----- Save PairingData if we used fresh keys -----
    if device_cert_for_save is not None and not os.path.exists(PAIRING_FILE):
        _save_pairing_tlv({TLV_CLIENT_CERT:    client_cert,
                           TLV_CLIENT_PRIVKEY: bytes(reversed(client_privkey_be)),
                           TLV_DEVICE_CERT:    device_cert_for_save})

    # ----- Biometric commands -----
    try:
        if sys.argv[1] == 'list-db':
            print("list-db...")
            sensor.list_enrolled()
        elif sys.argv[1] == 'enroll':
            # Usage: enroll [--finger <name_or_int>]
            args   = sys.argv[2:]
            finger = FpFinger.UNKNOWN
            if '--finger' in args:
                idx = args.index('--finger')
                if idx + 1 < len(args):
                    farg = args[idx + 1]
                    try:
                        finger = FpFinger(int(farg))
                    except ValueError:
                        try:
                            finger = FpFinger[farg.upper()]
                        except KeyError:
                            print(f"Unknown finger: {farg!r}. "
                                  f"Valid: {[f.name for f in FpFinger]}")
                            sys.exit(1)
            sensor.enroll(finger=finger)
        elif sys.argv[1] == 'clear-db':
            print("clear-db...")
            sensor.erase_database()
        elif sys.argv[1] == 'clear-db-compat':
            print("clear-db-compat...")
            sensor.erase_database_compat()
        elif sys.argv[1] == 'clear-local-db':
            print("clear-local-db...")
            sensor.clear_local_db()
        elif sys.argv[1] == 'identify':
            print("identify...")
            guid = sensor.identify()
            if guid:
                print(f"Result: matched {guid.hex()}")
            else:
                print("Result: no match / error")
        elif sys.argv[1] == 'identify-all':
            print("identify-all...")
            guid = sensor.identify_all()
            if guid:
                print(f"Result: matched {guid.hex()}")
            else:
                print("Result: no match / error")
        elif sys.argv[1] == 'list-db-all':
            print("list-db-all...")
            sensor.list_all()
        elif sys.argv[1] == 'purge-entries':
            print("purge-entries...")
            sensor.purge_entries()
        elif sys.argv[1] == 'delete-record':
            # Usage: delete-record [--force] guid <hex32>
            args = sys.argv[2:]
            force = '--force' in args
            args = [a for a in args if a != '--force']
            if len(args) < 2 or args[0] != 'guid':
                print("Usage: sensor.py delete-record [--force] guid <hex32>")
                sys.exit(1)
            guid_hex = args[1]
            if len(guid_hex) != 32:
                print("GUID must be 32 hex characters")
                sys.exit(1)
            guid = bytes.fromhex(guid_hex)
            print(f"Deleting record {guid_hex}...")
            ok = sensor.delete_record_by_guid(guid, force=force)
            print(f"  {'OK' if ok else 'FAILED'}")
            if not ok:
                sys.exit(1)
        elif sys.argv[1] == 'probe-guid':
            if len(sys.argv) < 3 or len(sys.argv[2]) != 32:
                print("Usage: sensor.py probe-guid <hex32>")
                sys.exit(1)
            sensor.probe_guid(bytes.fromhex(sys.argv[2]))
        elif sys.argv[1] == 'probe-managers':
            print("probe-managers...")
            sensor.probe_managers()
    except TlsAlertError as exc:
        print(f"\nDevice sent fatal TLS alert: {exc}")
        sensor.close()
        sys.exit(1)
    except (KeyboardInterrupt, usb.core.USBError) as exc:
        print(f"\nInterrupted (USBError errno={getattr(exc, 'errno', None)})."
              if isinstance(exc, usb.core.USBError) else "\nInterrupted.")
        if getattr(sensor, '_enroll_active', False):
            print("  Discarding active enrollment...")
            sensor.discard_enrollment()
        else:
            sensor.cancel_session()

    # ----- Cleanup: close TLS session gracefully -----
    sensor.close()
    print("Done.")


if __name__ == '__main__':
    import signal
    def _sigint(sig, frame):
        raise KeyboardInterrupt
    # libusb may override Python's SIGINT handler; restore it explicitly
    # so Ctrl+C raises KeyboardInterrupt even while blocked in a C call.
    signal.signal(signal.SIGINT, _sigint)
    try:
        main()
    except Exception as exc:
        print(f"FATAL: {exc}")
        import traceback; traceback.print_exc()
        sys.exit(1)
