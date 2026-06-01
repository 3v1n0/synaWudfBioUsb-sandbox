#!/usr/bin/env python3
"""
Python USB driver for Synaptics/Kensington WBF biometric sensor (047d:00f2).

Protocol summary:
  Phase 1: 3x (REQ_START + init_cmds)
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
             [0:142]   HOST_142 (see below)
             [140:142] sep 00 02
             [142:144] u16le len 20 00 (= 32)
             [144:176] pub_key32 (32 bytes, from device pairing)
             [176:400] zero padding

HOST_142 (142 bytes):
  [0:4]    3f5f1700
  [4:36]   ECS2 public X (LE, 32 bytes)
  [36:72]  zero padding (36 bytes)
  [72:104] ECS2 public Y (LE, 32 bytes)
  [104:142] zero padding (38 bytes)

PairingData (local file or Wine registry):
  tag=1: 400-byte host cert body (HOST_142 + header + pub_key + zeros)
  tag=2: 32-byte ECS2 private key D (LE)
  tag=3: 400-byte device cert body (same structure as tag 1)
  tag=4: 420-byte unknown
  tag=0: 2-byte unknown

USB wValue map (confirmed from b.exe trace):
  Init cmds (plain):  OUT value=1 / IN value=0 (cert-section reads: IN value=0x8000)
  ClientHello:        OUT value=4 / IN value=0
  Bundle:             OUT value=0 / IN value=0
  GET_RECORD_COUNT:   OUT value=6 / IN value=0
  STORAGE_QUERY_INIT: OUT value=7 / IN value=0
  STORAGE_QUERY_ALL:  OUT value=2 / IN value=0
  FETCH_RECORD:       OUT value=2 / IN value=0

Class hierarchy:
  Sensor        -- USB transport layer (ctrl_out / ctrl_in)
  SensorTLS     -- extends Sensor; adds TLS 1.2 handshake
  BiometricSensor -- extends SensorTLS; adds fingerprint commands

Usage:
  lxc exec kensington-playground -- python3 /path/sensor.py list-db
  SENSOR_TRACE=1 ... python3 sensor.py list-db
"""

import os, sys, struct, hashlib, hmac as _hmac, re
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
    ALERTS = {
        0x2a: "bad_certificate",
        0x2e: "decode_error",
        0x28: "handshake_failure",
        0x2f: "decrypt_error",
        0x30: "protocol_version",
        0x15: "certificate_unknown",
    }

    def __init__(self, level, code, extra=""):
        name = self.ALERTS.get(code, f"unknown(0x{code:02x})")
        msg = f"TLS Alert: level={level:#04x} code={name}"
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

# Deterministic RNG for replay/comparison against b.exe trace
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

REQ_START    = 0x19   # OUT -- phase 1 init signal
REQ_ACK      = 0x1a   # IN  -- phase 1 ack
REQ_CMD      = 0x16   # OUT -- send command
REQ_RESP     = 0x17   # IN  -- read response
REQ_READY    = 0x14   # IN  -- ready check
REQ_SHUTDOWN = 0x1b   # OUT -- vendor reset/shutdown (seen from b.exe)
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
CIPHER_SUITE  = b'\xc0\x2e'

# ---------------------------------------------------------------------------
# Identity key (P_SHA256 D) — for challenge signature only
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
# during the challenge/pairing flow — never hardcoded.

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

    def ctrl_out(self, req, value=0, data=b'', label=""):
        _log(f">>> {label} {BM_OUT:02x}{req:02x}{value:04x} "
             f"data={data[:64].hex()}")
        try:
            self.dev.ctrl_transfer(BM_OUT, req, value, 0, data,
                                   timeout=USB_TIMEOUT)
        except Exception as exc:
            _log(f"  ERROR: {exc}")
            raise

    def ctrl_in(self, req, length, value=0, label=""):
        _log(f"<<< {label} {BM_IN:02x}{req:02x}{value:04x} len={length}")
        try:
            resp = bytes(self.dev.ctrl_transfer(BM_IN, req, value, 0,
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
        """Read from interrupt endpoint (blocking). Returns bytes or None."""
        try:
            resp = bytes(self.dev.read(self.INTERRUPT_EP, 64, timeout=timeout))
            _log(f"INTERRUPT ({len(resp)}B): {resp.hex()}")
            return resp
        except usb.core.USBError as exc:
            if exc.errno == 110:  # timeout
                _log("INTERRUPT timeout")
                return None
            raise

    # --- Init protocol ---

    def _cmd_device_info(self, n):
        """Send device info query (01...) -> 38B response."""
        self.ctrl_out(REQ_CMD, value=1,
                      data=bytes.fromhex('0100000000000000'),
                      label=f"DEV_INFO(r{n})")
        return self.ctrl_in(REQ_RESP, 0x26, label=f"DEV_INFO(r{n})")

    def _cmd_cert_section(self, n, section):
        """Read certificate section (8e <section> 00 02 ...)."""
        data = bytes([0x8e, section, 0, 2]) + b'\x00' * 20
        self.ctrl_out(REQ_CMD, value=1, data=data,
                      label=f"CERT_SECT_{section:02x}(r{n})")
        return self.ctrl_in(REQ_RESP, 4096, value=0x8000,
                            label=f"CERT_SECT_{section:02x}(r{n})")

    def _cmd_bootstrap_status(self, n):
        """Send bootstrap status query (19...) -> 68B response."""
        self.ctrl_out(REQ_CMD, value=1,
                      data=bytes.fromhex('1900000000000000'),
                      label=f"BOOT_STATUS(r{n})")
        return self.ctrl_in(REQ_RESP, 0x44, label=f"BOOT_STATUS(r{n})")

    def _init_round(self, n):
        """
        One init round: REQ_START + 4 plain commands.
        Returns the device-info response (for TLS-stale detection).
        Cert-section reads use wValue=0x8000 and request 4096 bytes
        (native format).
        """
        self.ctrl_out(REQ_START, value=1, label=f"REQ_START(r{n})")
        ack = self.ctrl_in(REQ_ACK, 1, label=f"REQ_ACK(r{n})")
        assert ack == b'\x01', f"ACK={ack.hex()}"

        info_resp = self._cmd_device_info(n)
        self._cmd_cert_section(n, 0x09)
        self._cmd_cert_section(n, 0x1a)
        self._cmd_bootstrap_status(n)
        return info_resp

    def init_device(self):
        """
        Run init rounds until the device responds with non-TLS data,
        indicating it has left TLS state from a previous session.
        """
        for i in range(9):
            info_resp = self._init_round(i)
            # If info_resp is not a TLS record, device is in plain mode
            if (i >= 2 and info_resp and len(info_resp) >= 1
                    and info_resp[0] not in (0x15, 0x16, 0x17)):
                break
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
        self.ctrl_out(REQ_CMD, value=1, data=challenge,
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
        self.tls = None

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
        # CH HS body = 71 bytes, total CH = 84 bytes (matched to b.exe trace).
        sess_id   = b'\x07' + b'\x00' * 7
        suites    = (b'\xc0\x05' + CIPHER_SUITE
                     + b'\x00\x3d\x00\x8d\x00\xa8\x00\xa9')
        # Extensions: ext_len=0x000a (10) is a device quirk -- it covers
        # supported_groups (6B) + ec_point_formats type+len (4B) only.
        # The ec_point_formats data (\x01\x00) sits outside ext_len field.
        # CH HS body = 71 bytes, total CH = 84 bytes (matched to b.exe trace).
        ext_inner = b'\x00\x04\x00\x02\x00\x17\x00\x0b\x00\x02'  # 10B
        ch_body = (TLS_VER + cli_rand + sess_id
                   + struct.pack('>H', len(suites)) + suites
                   + b'\x00'                          # compression: length=0
                   + struct.pack('>H', len(ext_inner)) + ext_inner
                   + b'\x01\x00')                     # ec_point_formats data
        ch_hs  = make_hs_message(0x01, ch_body)
        ch_rec = make_tls_record(TLS_HANDSHAKE, ch_hs)
        state.feed_hs(ch_hs)
        _hexdump("CH record", ch_rec)

        # Send CH: value=4 with 44000000 IOCTL header (confirmed b.exe trace)
        self.ctrl_out(REQ_CMD, value=4,
                      data=b'\x44\x00\x00\x00' + ch_rec,
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
                if ht == 0x02:    # ServerHello
                    srv_rand = hmsg[6:38]
                elif ht == 0x0d:  # CertificateRequest -- expected, no action
                    pass
                elif ht == 0x0e:  # ServerHelloDone
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

        cert_hs = make_hs_message(0x0b,
                      b'\x00\x01\x90' + b'\x00\x01\x90' + cert_body)
        state.feed_hs(cert_hs)
        _hexdump("Cert HS", cert_hs)

        # ----- ClientKeyExchange -----
        cke_hs = make_hs_message(0x10, b'\x04' + eph_x + eph_y)
        state.feed_hs(cke_hs)

        # ----- CertificateVerify -----
        hs_dig = state.hs_digest()
        _hexdump("HS hash for CertVerify", hs_dig)
        sig_der = sign_ecdsa_sha256(client_privkey_be, hs_dig)
        cv_hs   = make_hs_message(0x0f, sig_der)
        state.feed_hs(cv_hs)

        # ----- ChangeCipherSpec + Finished -----
        verify  = prf(master, 'client finished', state.hs_digest(), 12)
        fin_hs  = make_hs_message(0x14, verify)

        hs_rec  = make_tls_record(TLS_HANDSHAKE, cert_hs + cke_hs + cv_hs)
        ccs_rec = make_tls_record(TLS_CHANGE_CS, b'\x01')

        # Encrypted epoch begins at seq=0 after CCS
        state.client_seq = 0
        fin_cipher = state.encrypt(TLS_HANDSHAKE, fin_hs)
        state.client_seq = 1   # next encrypted record is seq=1
        fin_rec = make_tls_record(TLS_HANDSHAKE, fin_cipher)

        # Send bundle: value=0 per b.exe trace (wVal=0x0000 confirmed)
        burst = b'\x44\x00\x00\x00' + hs_rec + ccs_rec + fin_rec
        _hexdump("bundle", burst)
        self.ctrl_out(REQ_CMD, value=0, data=burst,
                      label="TLS_OUT(BUNDLE)")
        # Device should respond immediately (b.exe does no delay)
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
        _log("TLS handshake complete")

    def tls_send(self, plain, value, label="", ctype=TLS_APP_DATA):
        """Encrypt plain as TLS record (ctype), send, decrypt response."""
        assert self.tls is not None, "call connect() first"
        _log(f"  tx seq={self.tls.client_seq} plain_len={len(plain)}")
        body = self.tls.encrypt(ctype, plain)
        rec  = make_tls_record(ctype, body)
        # Pad to 8-byte alignment (native format)
        pad  = (-len(rec)) % 8
        self.ctrl_out(REQ_CMD, value=value,
                      data=rec + bytes(pad), label=f"TLS_OUT({label})")
        raw = self.ctrl_in(REQ_RESP, 256, label=f"TLS_IN({label})")
        if not raw:
            return None
        if len(raw) < 5:
            _log(f"  TLS({label}) short response ({len(raw)}B): {raw.hex()}")
            return None
        if raw[0] == TLS_ALERT:
            _log(f"  TLS ALERT: {raw.hex()}")
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
        """Send REQ_SHUTDOWN + TLS close_notify (matches b.exe)."""
        try:
            self.dev.ctrl_transfer(BM_OUT, REQ_SHUTDOWN, 0, 0, [],
                                   timeout=1000)
            self.dev.ctrl_transfer(BM_IN, REQ_ACK, 0, 0, 2,
                                   timeout=1000)
        except Exception:
            pass
        # TLS close_notify as Alert record (ctype=0x15)
        if self.tls is not None:
            try:
                self.tls_send(b'\x00\x01', value=7,
                              label="CLOSE_NOTIFY", ctype=TLS_ALERT)
            except Exception:
                pass
        self.tls = None


# ---------------------------------------------------------------------------
# BiometricSensor -- extends SensorTLS with fingerprint commands
# ---------------------------------------------------------------------------

class BiometricSensor(SensorTLS):
    """
    High-level fingerprint database commands over the encrypted TLS channel.

    Command value codes (from b.exe trace):
      GET_RECORD_COUNT  -> value=6
      STORAGE_QUERY_INIT -> value=7
      STORAGE_QUERY_ALL  -> value=2
      FETCH_RECORD       -> value=2
    """

    def get_record_count(self):
        """
        Send GET_RECORD_COUNT (8200...).
        Returns status from response[0:2] (0x0000 = OK), or -1 on error.
        The raw 34-byte response is a fixed status block,
        NOT the actual count.  Use get_storage_count() for
        the real number of records.
        """
        resp = self.tls_send(
            bytes.fromhex('820000000000000207'),
            value=6, label="GET_RECORD_COUNT")
        if resp is None or len(resp) < 2:
            return -1
        return struct.unpack('<H', resp[:2])[0]

    def get_storage_count(self):
        """
        Full storage query sequence to obtain the actual record count.
        Returns (status, count, guids) where count = len(guids).
        """
        status = self.get_record_count()
        if status != 0:
            return status, 0, []
        self.storage_query_init(1)
        self.storage_query_init(2)
        guids = self.storage_query_all()
        return 0, len(guids), guids

    def storage_query_init(self, n):
        """Send STORAGE_QUERY_INIT (call twice before QUERY_ALL)."""
        return self.tls_send(
            bytes.fromhex('9e01'),
            value=7, label=f"QUERY_INIT_{n}")

    def storage_query_all(self):
        """
        Send STORAGE_QUERY_ALL wildcard.
        Returns list of 16-byte GUIDs for all allocated storage slots.
        """
        resp = self.tls_send(
            bytes.fromhex('9f02' + '00' * 3 + 'ff' * 16),
            value=2, label="QUERY_ALL")
        if not resp or len(resp) < 4:
            return []
        slot_count = struct.unpack('<H', resp[2:4])[0]
        guids, off = [], 4
        while off + 16 <= len(resp):
            guids.append(resp[off: off + 16])
            off += 16
        _log(f"QUERY_ALL: {len(guids)} slots "
             f"(header claims {slot_count})")
        return guids

    def fetch_record(self, guid):
        """
        Fetch a single record by GUID.
        Returns raw response bytes, or None on error.
        An all-zero 4-byte response means the slot is empty.
        """
        return self.tls_send(
            bytes.fromhex('9f03' + '00' * 3) + guid,
            value=2, label=f"FETCH_{guid[:4].hex()}")

    def list_enrolled(self):
        """
        Full list-db sequence. Returns list of (guid, record_data) for
        all non-empty slots. Prints results to stdout.
        """
        status, count, guids = self.get_storage_count()
        print(f"Storage count: status=0x{status:04x} count={count}")
        if not guids:
            print("No storage slots found.")
            return []

        enrolled = []
        for guid in guids:
            rec = self.fetch_record(guid)
            if rec and rec != b'\x00\x00\x00\x00':
                enrolled.append((guid, rec))

        if not enrolled:
            print("No enrolled fingerprints found.")
        else:
            print(f"Enrolled fingerprints ({len(enrolled)}):")
            for guid, rec in enrolled:
                print(f"  {guid.hex()}  data={rec.hex()}")

        return enrolled


    # --- Enroll protocol ---

    def enroll_begin(self):
        """Begin enrollment (value=0x0002). Returns raw response."""
        return self.tls_send(
            bytes.fromhex('96010000000000000000000000'),
            value=2, label="ENROLL_BEGIN")

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

    @staticmethod
    def _parse_capture_response(resp):
        """
        Parse 66-byte CAPTURE_DATA device response.
        Returns (sensor_status, reject_detail).

        The marker at [18:22] (LE u32) tells if a finger was detected:
          6 = WINBIO_I_MORE_DATA = finger detected
          0 = no finger / hardware rejected
        """
        if resp is None or len(resp) < 22:
            return 3, 0
        marker = struct.unpack_from('<I', resp, 18)[0]
        if marker == 6:
            return 1, 0   # finger detected
        return 2, 7       # no finger

    def capture_data(self, subfactor=6):
        """
        Send CAPTURE_DATA (value=0x0002).
        Returns (resp, sensor_status, reject_detail).
        37-byte payload: 86 <subf> 00*15 <subf> 00*19
        """
        payload = (bytes([0x86, subfactor])
                   + b'\x00' * 15
                   + bytes([subfactor])
                   + b'\x00' * 19)
        assert len(payload) == 37
        resp = self.tls_send(payload, value=2, label="CAPTURE_DATA")
        ss, rd = self._parse_capture_response(resp)
        if resp is not None and len(resp) == 66:
            _log(f"  CAPTURE_DATA resp: {resp.hex()}")
        return resp, ss, rd

    @staticmethod
    def _parse_sensor_status(resp):
        """
        Parse 18-byte SENSOR_STATUS response from get_sensor_status().

        Structure (from trace analysis):
          [0:2]   LE16 = 0x0000
          [2:4]   LE16 = 0x0001 (response type?)
          [4:6]   LE16 = 0x0000
          [6:8]   LE16 = raw field A (varies per sensor state)
          [8:10]  LE16 = raw field B (cumulative sample counter)
          [10:14] LE32 = raw field C
          [14:18] padding

        These fields are NOT mapped to WINBIO_SENSOR_STATUS/REJECT_DETAIL
        at the USB level. Returns (raw_A, raw_B, raw_C).
        """
        if resp is None or len(resp) < 10:
            return 0, 0, 0
        a = struct.unpack_from('<H', resp, 6)[0]
        b = struct.unpack_from('<H', resp, 8)[0]
        c = struct.unpack_from('<I', resp, 12)[0] if len(resp) >= 16 else 0
        return a, b, c

    def get_sensor_status(self, ctx=0):
        """
        Query sensor status (value=0x0006, 9 bytes).
        ctx is the enrollment context byte extracted from CAPTURE_DATA
        response[-2:] (LE u16).  Returns 18-byte response.
        """
        payload = bytes([0x87, ctx]) + bytes.fromhex('00200001000000')
        return self.tls_send(payload, value=6,
                             label=f"SENSOR_STATUS(ctx={ctx})")

    def update_enrollment_check(self):
        """
        Send UPDATE_ENROLLMENT check (value=0x0006).
        17-byte payload: 800c + zeros + flags + subfactor.
        """
        payload = bytes.fromhex(
            '800c000000010000000100000801010100')
        return self.tls_send(payload, value=6, label="UPDATE_ENROLL_CHECK")

    def update_enrollment_ack(self):
        """Send ack byte (81) after enrollment update (value=0x0006)."""
        return self.tls_send(
            bytes.fromhex('81'),
            value=6, label="UPDATE_ENROLL_ACK")

    def query_enrollment_needs(self):
        """
        Query device's enrollment requirements (value=0x0002).
        125-byte payload: 39 00 71 02 ...
        """
        return self.tls_send(
            bytes.fromhex(
                '3900710200ffff0000057f0020000000'
                '007f7f000000000000ffff0000057f00'
                '20000000007f7f000000000000ffff00'
                '00057f0020000000007f7f0000000000'
                '00000000000000000000000000000000'
                '00000000000000000000000000000000'
                '00000000000000000000000000000000'
                '00000000000000000000000000'),
            value=2, label="QUERY_ENROLL_NEEDS")

    def query_status_ext(self, param=0):
        """
        Extended status query (value=0x0002, 37 bytes).
        86 00 <00*15> <param> <00*19>
        param=04 for initial capture, param=01 for quality check.
        """
        payload = (bytes([0x86, 0]) + b'\x00' * 15
                   + bytes([param]) + b'\x00' * 19)
        assert len(payload) == 37
        return self.tls_send(payload, value=2,
                             label=f"STATUS_EXT(param={param})")

    def query_enrollment_simple(self):
        """
        Simplified enrollment query (value=0x0002, 125 bytes).
        39 00 ... (zeros with periodic 0x20 pattern).
        """
        return self.tls_send(
            bytes.fromhex(
                '39000000000000000000000020000000'
                '00000000000000000000000000000000'
                '20000000000000000000000000000000'
                '00000000200000000000000000000000'
                '00000000000000002000000000000000'
                '00000000000000000000000020000000'
                '00000000000000000000000000000000'
                '20000000000000000000000000'),
            value=2, label="QUERY_ENROLL_SIMPLE")

    # -- Commit / finalization protocol ---

    ENROLL_TEMPLATE_FIXED = bytes.fromhex(
        '39f4010000f4010000077f0020000000'
        '007f7f00000000000000000000000000'
        '20000000000000000000000000f40100'
        '00007f00200000000000000000000000'
        '00000000000000002000000000000000'
        '00000000000000000000000000000000'
        '00000000000000000000000000000000'
        '00000000000000000000000000')

    COMMIT_HEADER = bytes.fromhex(
        '9603000000000000007d0000000000100000')

    COMMIT_IDENTITY_PREFIX = bytes.fromhex(
        '01004c00000002000000')

    COMMIT_PAD = bytes.fromhex(
        '0000000000000000')

    COMMIT_TLV1 = bytes.fromhex(
        '020001000000')

    def _enroll_label_bytes(self, label_str="FP1-00000000-0-00000000-none"):
        """Build label TLV: tag 0x0302 + LE length + null-terminated utf-8."""
        raw = label_str.encode("utf-8", errors="replace") + b"\x00"
        return bytes.fromhex('020300') + struct.pack('<I', len(raw)) + raw

    def _build_commit_payload(self, guid, sid, label):
        """
        Build 138-byte commit payload (padded to match device expectations).
        guid  -- 16 bytes from 9602 response
        sid   -- 16 bytes (generated)
        label -- string for identity label
        """
        payload = (self.COMMIT_HEADER
                   + b'\x00' + guid
                   + self.COMMIT_IDENTITY_PREFIX
                   + sid
                   + b'\x00' * 48
                   + self.COMMIT_PAD
                   + self.COMMIT_TLV1
                   + self._enroll_label_bytes(label))
        # Pad to 138 bytes (trace commit size). Excess zeros are safe
        # because TLV is self-delimiting.
        assert len(payload) <= 138, f"commit payload too large: {len(payload)}"
        return payload + b'\x00' * (138 - len(payload))

    def enroll_get_guid(self):
        """
        Send 9602 to get GUID after all samples captured.
        Returns 16-byte GUID or None.
        """
        resp = self.tls_send(
            bytes.fromhex('9602000000'),
            value=2, label="ENROLL_GET_GUID")
        if resp is None or len(resp) < 18:
            return None
        # GUID at [2:18] in 82-byte response
        return resp[2:18]

    def enroll_commit(self, payload):
        """
        Send 9603 commit payload (138 bytes, value=7).
        Returns response bytes or None.
        """
        return self.tls_send(payload, value=7, label="ENROLL_COMMIT")

    def enroll_commit_ack(self):
        """
        Send 9604 commit ack (5 bytes, value=2).
        Returns response bytes or None.
        """
        return self.tls_send(
            bytes.fromhex('9604000000'),
            value=2, label="ENROLL_COMMIT_ACK")

    def delete_record(self, entry):
        """
        Select + delete a single record by its 16-byte entry data.

        The entry can be obtained from _list_entries() (9f01) or
        from get_storage_count() GUIDs.
        Returns True on success.
        """
        r = self.tls_send(
            bytes.fromhex('a001000000') + entry,
            value=2, label="SELECT_ENTRY")
        if r is None:
            return False
        r = self.tls_send(
            bytes.fromhex('a301000000') + entry,
            value=2, label="DELETE_ENTRY")
        return r == b'\x00\x00\x03\x00'

    def delete_record_by_guid(self, guid):
        """
        Delete a single record by its 16-byte GUID.

        Uses FETCH_RECORD (9f03) to get the record entry handle,
        SELECT_RECORD (a003) to select it, and tries DELETE_RECORD
        (a302) to remove it as the a30x analogue of a003.
        If a302 doesn't exist, falls back to enumerating entries
        via A002 identity matching.
        """
        rec = self.fetch_record(guid)
        if rec and len(rec) >= 20:
            entry = rec[4:20]
            r = self.tls_send(
                bytes.fromhex('a003000000') + entry,
                value=2, label="SELECT_RECORD")
            if r is not None:
                r = self.tls_send(
                    bytes.fromhex('a302000000') + entry,
                    value=2, label="DELETE_RECORD")
                if r == b'\x00\x00\x03\x00':
                    return True

        entries = self._list_entries()
        for ent in entries:
            r = self.tls_send(
                bytes.fromhex('a001000000') + ent,
                value=2, label="SELECT_ENTRY")
            if r is None or len(r) < 12:
                continue
            if r[8:12] != b'\x01\x00\x00\x00':
                continue
            r2 = self.tls_send(
                bytes.fromhex('a002000000') + ent,
                value=2, label="GET_ENTRY_INFO")
            if r2 is None:
                continue
            _log(f"A002 response ({len(r2)}B): {r2.hex()}")
            for off in (0, 2, 4, 6, 8):
                if len(r2) >= off + 16 and r2[off:off+16] == guid:
                    return self.delete_record(ent)

        print(f"  GUID {guid.hex()} not found")
        return False

    def close_notify(self):
        """Send TLS close_notify (value=7). Returns response."""
        return self.tls_send(
            bytes.fromhex('0001'),
            value=7, label="CLOSE_NOTIFY")

    def reset_ownership(self):
        """
        Unpair device: clear local PairingData and reset device state.

        Replicates b.exe reset-ownership: sends IOCTL-equivalent to
        device, closes TLS, REQ_SHUTDOWN, then deletes pairing.dat.
        No USB unpair command exists on this device — it's a
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
            self.dev.ctrl_transfer(BM_IN, REQ_ACK, 0, 0, 2,
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
        r = self.tls_send(
            bytes.fromhex('9f03' + '00' * 3) + guid,
            value=2, label=f"FETCH_MATCH({guid[:4].hex()})")
        if not r or len(r) < 20:
            return False
        entry = r[4:20]
        if entry == b'\x00' * 16:
            return False
        r = self.tls_send(
            bytes.fromhex('a003000000') + entry,
            value=2, label="SELECT_MATCH")
        if not r:
            return False
        r = self.tls_send(
            bytes.fromhex('a103000000') + entry,
            value=2, label="LOAD_TEMPLATE")
        return r is not None

    def match_result(self):
        """
        Send 9901 match result query.

        Returns (status_code, guid_or_None):
          status_code = 0x0000 on success/match, 0x0509 for no-match,
                        or other device error codes.
          guid_or_None = 16-byte matched GUID or None.
        """
        r = self.tls_send(
            bytes.fromhex('99010000000000000000000000'),
            value=2, label="MATCH_RESULT")
        if not r or len(r) < 2:
            return None
        status = struct.unpack('<H', r[:2])[0]
        if len(r) >= 18:
            return status, r[2:18]
        return status, None

    def identify_all(self):
        """
        Full identify-all sequence matching b.exe trace.
        Loads all enrolled records, captures a finger, matches
        against all loaded templates, and returns the matched
        16-byte GUID (or None if no match / error).
        """
        print("\n--- Identify All ---")

        # 1. Load all enrolled records into matching engine
        status, count, guids = self.get_storage_count()
        _log(f"Storage count: status=0x{status:04x} count={count}")
        if status != 0:
            print(f"  Storage query failed: 0x{status:04x}")
            return None

        loaded = 0
        for guid in guids:
            if guid == b'\x00' * 16:
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
            self.tls_send(
                bytes.fromhex('a001000000') + ent,
                value=2, label="SELECT_ENTRY")

        # 4. Capture finger
        print("\n  Touch and hold the sensor...")
        cap, sensor_status, _ = self.capture_data()
        if not cap or sensor_status != 1:
            print("  No finger detected")
            return None
        ctx = self._extract_ctx(cap)
        _log(f"  ctx={ctx}")
        print("  Finger ON")

        # 5. Interrupt 1 (capture armed)
        i1 = self.read_interrupt(timeout=60000)
        if i1 is None:
            print("  Finger removed")
            return None
        _log(f"  Interrupt 1: {i1.hex()}")

        # 6. Pre-capture queries
        ss = self.get_sensor_status(0)
        _log(f"  SENSOR_STATUS: {ss.hex() if ss else 'None'}")
        self.query_status_ext(4)
        self.query_enrollment_needs()

        ext1 = self.query_status_ext(1)
        if ext1 and len(ext1) >= 2:
            qual = struct.unpack('<H', ext1[-2:])[0]
            print(f"  Progress: {qual}")

        # UPDATE_CHECK with 8014 (identify variant)
        r = self.tls_send(
            bytes.fromhex('8014000000010000000100000801010100'),
            value=6, label="UPDATE_IDENTIFY_CHECK")
        if r is None:
            _log("  UPDATE_IDENTIFY_CHECK failed")

        # 7. Interrupt 2 (data captured)
        i2 = self.read_interrupt(timeout=60000)
        if i2 is None:
            print("  Finger removed before capture complete")
            return None
        _log(f"  Interrupt 2: {i2.hex()}")

        # 8. Post-capture queries
        self.get_sensor_status(0)
        self.query_enrollment_simple()
        self.query_status_ext(4)
        self.update_enrollment_ack()

        # 9. Match result
        mr = self.match_result()
        if mr is None:
            print("  MATCH_RESULT failed (TLS error)")
            return None
        status, matched = mr
        if status != 0:
            print(f"  No match (status=0x{status:04x})")
            return None
        if matched is None or matched == b'\x00' * 16:
            print("  MATCH_RESULT returned zero GUID")
            return None
        print(f"  Match found! GUID: {matched.hex()}")
        return matched

    def identify(self):
        """
        Single-shot identify.  Assumes the matching engine already has
        templates loaded (from a prior identify-all or verify call).
        Captures a finger, matches, returns the matched GUID or None.
        """
        print("\n--- Identify ---")
        print("\n  Touch and hold the sensor...")
        cap, sensor_status, _ = self.capture_data()
        if not cap or sensor_status != 1:
            print("  No finger detected")
            return None
        ctx = self._extract_ctx(cap)
        print("  Finger ON")

        i1 = self.read_interrupt(timeout=60000)
        if i1 is None:
            print("  Finger removed"); return None

        self.get_sensor_status(0)
        self.query_status_ext(4)
        self.query_enrollment_needs()

        ext1 = self.query_status_ext(1)
        if ext1 and len(ext1) >= 2:
            qual = struct.unpack('<H', ext1[-2:])[0]
            print(f"  Progress: {qual}")

        self.tls_send(
            bytes.fromhex('8014000000010000000100000801010100'),
            value=6, label="UPDATE_IDENTIFY_CHECK")

        i2 = self.read_interrupt(timeout=60000)
        if i2 is None:
            print("  Finger removed before capture complete")
            return None

        self.get_sensor_status(0)
        self.query_enrollment_simple()
        self.query_status_ext(4)
        self.update_enrollment_ack()

        mr = self.match_result()
        if mr is None:
            print("  MATCH_RESULT failed (TLS error)")
            return None
        status, matched = mr
        if status != 0:
            print(f"  No match (status=0x{status:04x})")
            return None
        if matched is None or matched == b'\x00' * 16:
            print("  MATCH_RESULT returned zero GUID")
            return None
        print(f"  Match found! GUID: {matched.hex()}")
        return matched

    def _list_entries(self):
        """Fetch all entry blobs via 9f01. Returns list of 16-byte entries."""
        resp = self.tls_send(
            bytes.fromhex('9f01' + '00' * 19),
            value=2, label="FETCH_FIRST")
        if resp is None or len(resp) < 4:
            return []
        nentries = struct.unpack('<H', resp[2:4])[0]
        return [resp[4 + i*16 : 4 + (i+1)*16]
                for i in range(min(nentries, (len(resp)-4)//16))]

    def _finalise_erase(self):
        """a401/a402/a403 + verify empty. Returns True if empty."""
        for cmd, label in [('a401', 'FINALISE_1'),
                           ('a402', 'FINALISE_2'),
                           ('a403', 'FINALISE_3')]:
            r = self.tls_send(bytes.fromhex(cmd),
                              value=7, label=label)
            if r is None:
                print(f"  {label} failed"); return False
        self.storage_query_init(1)
        self.storage_query_init(2)
        remaining = self.storage_query_all()
        if remaining:
            print(f"  WARNING: {len(remaining)} records still present")
        else:
            print("  OK -- database empty")
        return not remaining

    def erase_database(self):
        """
        Delete all enrolled records matching b.exe's exact
        IOCTL_BIOMETRIC_ENGINE_ERASE_DATABASE sequence
        (traced with PROTO_TRACE=1 on 2026-05-31):
          1. FETCH_FIRST (9f01) → list entries
          2. For each entry: a001 (SELECT) + a301 (DELETE)
          3. a401 / a402 / a403 (finalise)
          4. STORAGE_QUERY_INIT ×2 + STORAGE_QUERY_ALL (verify)
        """
        entries = self._list_entries()
        if not entries:
            print("  No entries (database may be empty)")
            return True
        print(f"  Entries: {len(entries)}")

        for ent in entries:
            if not self.delete_record(ent):
                print(f"  delete failed for {ent[:8].hex()}")
                return False

        return self._finalise_erase()

    def _commit_enrollment(self, guid, label="FP1"):
        """
        Full commit finalization sequence (5 steps + close).
        Must be called after 5 successful enrollment samples.
        """
        print("\n--- Commit enrollment ---")
        print(f"  GUID: {guid.hex()}")

        # Step 2: Submit fixed template
        print("  Sending enrollment template...")
        resp = self.tls_send(self.ENROLL_TEMPLATE_FIXED,
                             value=2, label="ENROLL_TEMPLATE")
        if resp is None:
            print("  ENROLL_TEMPLATE failed (TLS error)")
            return False
        ts, pc, rd = self._parse_template_status(resp)
        if ts != 0:
            print(f"  ENROLL_TEMPLATE rejected:"
                  f" TemplateStatus=0x{ts:08x}"
                  f" PercentComplete={pc} RejectDetail=0x{rd:x}")
            return False
        print(f"  Template response: {resp.hex()}")
        _log(f"  TemplateStatus={ts:#x} PC={pc} RD=0x{rd:x}")

        # Step 3: Build + send commit payload
        sid = _rand(16)
        payload = self._build_commit_payload(guid, sid, label)
        _hexdump(f"Commit plain ({len(payload)}B)", payload)
        print(f"  Sending commit ({len(payload)}B) as label '{label}'...")
        resp = self.enroll_commit(payload)
        if resp is None:
            print("  ENROLL_COMMIT failed (TLS Alert)")
            # Try to log TLS state for debugging
            if self.tls:
                _log(f"  client_seq={self.tls.client_seq} server_seq={self.tls.server_seq}")
            return False
        print(f"  Commit response: {resp.hex()}")

        # Step 4: Storage query init
        print("  Storage query...")
        resp = self.tls_send(
            bytes.fromhex('9e01'),
            value=7, label="COMMIT_STORAGE_QUERY")
        if resp is None:
            print("  Storage query failed")
            return False
        print(f"  Storage query resp ({len(resp)}B): {resp[:16].hex()}...")

        # Step 5: Commit ack
        print("  Commit ack...")
        resp = self.enroll_commit_ack()
        if resp is None:
            print("  ENROLL_COMMIT_ACK failed")
            return False
        print(f"  Ack response: {resp.hex()}")

        # Step 6: Close notify
        print("  Close notify...")
        resp = self.close_notify()
        print(f"  Close: {resp.hex() if resp else None}")

        print("  Commit done!")
        return True

    @staticmethod
    def _extract_ctx(cap_resp):
        """Extract enrollment context from CAPTURE_DATA response[-2:] as LE u16."""
        if cap_resp is None or len(cap_resp) < 2:
            return 0
        return struct.unpack('<H', cap_resp[-2:])[0]

    @staticmethod
    def _has_guid(resp):
        """True if a 9602 response contains a valid GUID at [2:18]."""
        return resp is not None and len(resp) >= 18 and resp[2:18] != b'\x00' * 16

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
            return -1, 0, 0
        if resp == b'\x00\x00' or resp == b'\x00\x00\x00\x00':
            return 0, 0, 0
        if len(resp) < 16:
            return -1, 0, 0
        ts_raw = struct.unpack('<I', resp[2:6])[0]
        if ts_raw == 0 or ts_raw == 6:
            ts = 0
        else:
            ts = ts_raw
        pc = struct.unpack('<I', resp[12:16])[0]
        rd = struct.unpack('<I', resp[8:12])[0]
        return ts, pc, rd

    def _enroll_one_sample(self, sample_num, max_samples):
        """One enrollment sample, matching b.exe trace exactly.

        Always completes the full 11-command sequence, even on errors,
        to keep device protocol state consistent.  Returns:
          (True, guid)  -- enrollment complete, commit now
          (True, None)  -- good sample, keep going
          (False, None) -- error (no finger, bad scan, etc.), skip
        """
        print(f"\n--- Sample {sample_num}/{max_samples} ---")
        print("  Touch and hold the sensor...")
        _log(f"  _enroll_one_sample started")

        cap, sensor_status, reject_detail = self.capture_data()
        ok = cap is not None and sensor_status == 1
        if cap is None:
            print("  CAPTURE_DATA failed")
            cap = b''
        elif sensor_status != 1:
            print("  No finger detected")
            return False, None
        ctx = self._extract_ctx(cap)
        _log(f"  ctx={ctx}")
        print("  Finger ON")

        # Interrupt 1: capture armed (01) -- immediate after CAPTURE
        i1 = self.read_interrupt(timeout=60000)
        if i1 is None:
            print("  Finger removed before capture complete")
            return False, None
        i1_type = i1[0] if len(i1) > 0 else 0
        _log(f"  Interrupt raw: {i1.hex()}")
        print(f"  Interrupt: type=0x{i1_type:02x}"
              f" ({'capture armed' if i1_type==1 else 'data captured' if i1_type==2 else 'unknown'})")

        # Pre-capture queries (finger is being placed/held)
        ss_resp = self.get_sensor_status(ctx)
        ss_q, ql_q, rd_q = self._parse_sensor_status(ss_resp)
        _log(f"  SENSOR_STATUS: raw_fields=({ss_q},{ql_q},{rd_q})")
        self.query_status_ext(4)
        r = self.query_enrollment_needs()
        if r is None:
            print("  QUERY_ENROLL_NEEDS failed")

        ext1 = self.query_status_ext(1)
        if ext1 is not None:
            qual = ext1[-2:]
            print(f"  Progress: {struct.unpack('<H', qual)[0]}")
        else:
            print("  STATUS_EXT(1) failed (finger read error)")
            ok = False

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
        self.get_sensor_status(0)
        self.query_enrollment_simple()
        ext4b = self.query_status_ext(4)
        if ext4b is not None:
            qual2 = ext4b[-2:]
            _log(f"  Ext4 progress: {struct.unpack('<H', qual2)[0]}")
        self.update_enrollment_ack()

        # 9602 enrollment status
        r9602 = self.tls_send(bytes.fromhex('9602000000'),
                               value=2, label="ENROLL_STATUS")
        if self._has_guid(r9602):
            guid = r9602[2:18]
            print(f"  GUID: {guid.hex()}")
            return True, guid

        # 2-byte 9602 response = status code (not GUID)
        if r9602 is not None and len(r9602) == 2:
            status_le = struct.unpack('<H', r9602)[0]
            if r9602 != b'\x00\x00':
                print(f"  9602 error: status=0x{status_le:04x}")
                return False, status_le  # terminal; caller aborts
            # 0x0000 = "not done yet, keep going" (normal)

        # Longer response carries sample count at [22:24] LE16.
        # If it incremented vs previous sample, the capture was accepted.
        if r9602 is not None and len(r9602) >= 24:
            new_cnt = struct.unpack_from('<H', r9602, 22)[0]
            prev = getattr(self, '_prev_enroll_cnt', None)
            self._prev_enroll_cnt = new_cnt
            if prev is not None:
                if new_cnt > prev:
                    ok = True
                    _log(f"  ENROLL count {prev}→{new_cnt}")
                else:
                    ok = False
                    _log(f"  ENROLL count stuck at {new_cnt}")
            else:
                _log(f"  ENROLL initial count={new_cnt}")

        if ok:
            print(f"  Sample {sample_num} OK")
        else:
            print(f"  Sample {sample_num} had errors -- not counted")
        return ok, None

    def enroll(self):
        """
        Full enrollment flow (interactive).
        Checks DB capacity first, then completes each sample fully.
        Errors (no finger, bad scan) are skipped without counting.
        """
        print("\n--- Enrollment ---")

        # Check DB capacity (max ~10 records from WINBIO_E_DATABASE_FULL)
        status, count, _ = self.get_storage_count()
        print(f"  DB records: {count}")
        if status != 0:
            print(f"  Storage query status=0x{status:04x}")
        if count >= 10:
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
        max_attempts = 50
        for i in range(1, max_attempts + 1):
            ok, guid = self._enroll_one_sample(i, max_attempts)
            if not ok:
                if isinstance(guid, int):
                    # Terminal error (e.g. 9602 returned error code)
                    print(f"  9602 returned error code=0x{guid:04x}")
                    _, cnt, _ = self.get_storage_count()
                    if cnt >= 10:
                        print(f"  Database has {cnt} records "
                              "(likely full). Clear some and retry.")
                    return False
                continue            # transient error -- wait for next touch
            if guid is not None:
                ok2 = self._commit_enrollment(guid=guid, label="FP1")
                if not ok2:
                    _, cnt, _ = self.get_storage_count()
                    print(f"  DB records after failed commit: {cnt}")
                return ok2

        print("  Enrollment aborted after 50 attempts")
        return False


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in (
            'list-db', 'enroll', 'clear-db', 'identify-all', 'identify',
            'reset-ownership', 'delete-record'):
        print("Usage: sensor.py list-db|enroll|clear-db|identify-all|identify"
              "|reset-ownership|delete-record [guid <hex32>]")
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
            # Device certificate has fresh device key — override stored values
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
        # Compute HOST_142 from host pubkey
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
    if sys.argv[1] == 'list-db':
        print("list-db...")
        sensor.list_enrolled()
    elif sys.argv[1] == 'enroll':
        sensor.enroll()
    elif sys.argv[1] == 'clear-db':
        print("clear-db...")
        sensor.erase_database()
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
    elif sys.argv[1] == 'delete-record':
        if len(sys.argv) < 4 or sys.argv[2] != 'guid':
            print("Usage: sensor.py delete-record guid <hex32>")
            sys.exit(1)
        guid_hex = sys.argv[3]
        if len(guid_hex) != 32:
            print("GUID must be 32 hex characters")
            sys.exit(1)
        guid = bytes.fromhex(guid_hex)
        print(f"Deleting record {guid_hex}...")
        ok = sensor.delete_record_by_guid(guid)
        print(f"  {'OK' if ok else 'FAILED'}")
        if not ok:
            sys.exit(1)
    # ----- Cleanup: close TLS session gracefully -----
    sensor.close()
    print("Done.")


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f"FATAL: {exc}")
        import traceback; traceback.print_exc()
        sys.exit(1)
