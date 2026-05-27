#!/usr/bin/env python3
"""
Python USB driver for Synaptics/Kensington WBF biometric sensor (047d:00f2).

Protocol summary:
  Phase 1: 3x (REQ_START + init_cmds)
  Phase 2: REQ_READY -- returns 0000 (challenge is optional)
  Phase 3: TLS 1.2 handshake over custom USB framing
  Phase 4: Encrypted IOCTL app commands (AES-256-GCM)

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

Certificate body (400 bytes total):
  [0:2]    run_marker = cli_rand[4:6]
  [2:144]  HOST_142 from PairingData tag=1 blob[0:142]
  [144:148] header bytes: 00 02 20 00
  [148:180] pub_key32 (ECS2 public key X, LE) from PairingData tag=1
  [180:400] zero padding

PairingData (local file or Wine registry):
  tag=1: 398-byte host cert body (HOST_142 + header + pub_key + zeros)
  tag=2: 32-byte ECS2 private key D (LE)
  tag=3: 142-byte device cert body (DEV_142)

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
# Configuration
# ---------------------------------------------------------------------------

USB_ID       = os.environ.get("USB_ID", "047d:00f2")
USB_TIMEOUT  = 10000   # ms
SENSOR_TRACE = os.environ.get("SENSOR_TRACE", "0") == "1"

# Deterministic RNG for replay/comparison against b.exe trace
_DET_RNG   = os.environ.get("PROTO_DETERMINISTIC_RNG", "0") == "1"
_det_ctr   = 0

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

REQ_START = 0x19   # OUT -- phase 1 init signal
REQ_ACK   = 0x1a   # IN  -- phase 1 ack
REQ_CMD   = 0x16   # OUT -- send command
REQ_RESP  = 0x17   # IN  -- read response
REQ_READY = 0x14   # IN  -- ready check
BM_OUT, BM_IN = 0x40, 0xc0

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
# Fallback device ECDH static key (from ECK1 export in Wine trace)
# ---------------------------------------------------------------------------

DEV_X_BE = bytes.fromhex(
    '63df20dd820af4274c9e9a1854f02102'
    'bc0e1b76b8746817b68c440122df20bf')
DEV_Y_BE = bytes.fromhex(
    '4ef37a81815ead6a51b145aadbb3073f'
    '60bedb82ea38c34324983109df6fc0f3')

# HOST_142 fallback built from device key (used when no PairingData)
_DEV_X_LE = bytes(reversed(DEV_X_BE))
_DEV_Y_LE = bytes(reversed(DEV_Y_BE))
HOST_142_FALLBACK = (b'\x3f\x5f\x17\x00'
                     + _DEV_X_LE + b'\x00' * 20
                     + _DEV_Y_LE + b'\x00' * 54)
assert len(HOST_142_FALLBACK) == 142

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
    path = (reg_path
            or os.environ.get("PAIRING_REG")
            or os.path.expanduser("~/winelatestprefix/user.reg"))
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
    tlvs = _load_pairing_from_file()
    if tlvs is not None:
        return tlvs
    blob = _load_pairing_blob_from_registry()
    if blob:
        plain = _decrypt_pairing_data(blob)
        if plain:
            tlvs = _parse_pairing_tlv(plain)
            if tlvs:
                _save_pairing_tlv(tlvs)
                return tlvs
    return None


def get_pairing_fields(tlvs):
    """
    Extract (host_142, eck2_le, cert_data, dev_x_be, dev_y_be, eck2_pub_le)
    from TLV dict.
    """
    cert_data = tlvs.get(1)
    if not cert_data or len(cert_data) < 142:
        return None
    if cert_data[:4] != b'\x3f\x5f\x17\x00':
        return None
    host_142    = cert_data[:142]
    eck2_le     = tlvs.get(2, b'\x00' * 32)
    # Public key X coord (LE) stored at cert_data[146:178]
    # (after HOST_142[0:142] + header[142:146])
    eck2_pub_le = (cert_data[146:178]
                   if len(cert_data) >= 178 else b'\x00' * 32)
    # Device ECDH static key from Tag 3 (host cert), fallback to constants
    dev_x_be, dev_y_be = DEV_X_BE, DEV_Y_BE
    host_cert = tlvs.get(3)
    if (host_cert and len(host_cert) >= 142
            and host_cert[:4] == b'\x3f\x5f\x17\x00'):
        x_le = host_cert[4:36]
        off  = 36
        while off < 142 and host_cert[off] == 0:
            off += 1
        if off < 142:
            y_le   = host_cert[off:off + 32]
            dev_x_be = x_le[::-1]
            dev_y_be = y_le[::-1]
    return host_142, eck2_le, cert_data, dev_x_be, dev_y_be, eck2_pub_le


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
    """Sign digest32 with P-256 private key. Returns DER signature."""
    priv = ec.derive_private_key(int.from_bytes(priv_d_be, 'big'),
                                 ec.SECP256R1(), default_backend())
    return priv.sign(digest32, ec.ECDSA(ec_utils.Prehashed(hashes.SHA256())))


# ---------------------------------------------------------------------------
# TLS state (keys + sequence numbers)
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
# USB Sensor
# ---------------------------------------------------------------------------

class Sensor:
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

    # --- Init phase ---

    def init_phase(self, n):
        """One init round: REQ_START + 4 commands."""
        self.ctrl_out(REQ_START, value=1, label=f"REQ_START(r{n})")
        ack = self.ctrl_in(REQ_ACK, 1, label=f"REQ_ACK(r{n})")
        assert ack == b'\x01', f"ACK={ack.hex()}"

        def cmd(data, resp_len, lbl):
            self.ctrl_out(REQ_CMD, value=1, data=data, label=lbl)
            return self.ctrl_in(REQ_RESP, resp_len, label=lbl)

        cmd(bytes.fromhex('0100000000000000'), 0x26, f"init1(r{n})")
        cmd(bytes.fromhex(
            '8e0900020000000000000000000000000000000000000000'),
            0x1a, f"init2(r{n})")
        cmd(bytes.fromhex(
            '8e1a00020000000000000000000000000000000000000000'),
            0x4e, f"init3(r{n})")
        cmd(bytes.fromhex('1900000000000000'), 0x44, f"init4(r{n})")

    def init_phases(self):
        """Run 3 init rounds as native b.exe does."""
        for i in range(3):
            self.init_phase(i)
        _log("Init phases done")

    def req_ready(self):
        return self.ctrl_in(REQ_READY, 2, label="REQ_READY")


# ---------------------------------------------------------------------------
# TLS handshake
# ---------------------------------------------------------------------------

def do_tls_handshake(sensor, host_142, eck2_be, eck2_pub_le,
                     cert_data_398, dev_x_be, dev_y_be):
    """
    Full TLS 1.2 handshake with the device. Returns TLSState.

    Parameters:
      sensor        -- connected Sensor
      host_142      -- 142-byte host EC key blob (from PairingData tag=1)
      eck2_be       -- 32-byte ECS2 private key D (BE) for CertVerify signing
      eck2_pub_le   -- 32-byte ECS2 public key X coord (LE) for cert embedding
      cert_data_398 -- 398-byte cert body (PairingData tag=1); None = fresh
      dev_x_be      -- 32-byte device ECDH static pub X (BE)
      dev_y_be      -- 32-byte device ECDH static pub Y (BE)
    """
    state    = TLSState()
    cli_rand = _rand(32)
    _log(f"cli_rand={cli_rand.hex()}")

    # ----- Ephemeral ECDH key pair -----
    eck2_d  = _rand(32)
    pub     = ecdh_pubkey(eck2_d)
    eph_x   = pub[:32]
    eph_y   = pub[32:]
    _log(f"eph_x={eph_x.hex()}")

    # ----- ClientHello -----
    sess_id  = b'\x07' + b'\x00' * 7
    suites   = b'\xc0\x05' + CIPHER_SUITE + b'\x00\x3d\x00\x8d\x00\xa8\x00\xa9'
    ext_data = (b'\x00\x04\x00\x02\x00\x17'
                b'\x00\x0b\x00\x02\x01\x00'
                b'\x00\x00\x00\x00')
    ch_body = (TLS_VER + cli_rand + sess_id
               + struct.pack('>H', len(suites)) + suites
               + b'\x00' + struct.pack('>H', len(ext_data)) + ext_data)
    ch_hs  = make_hs_message(0x01, ch_body)
    ch_rec = make_tls_record(TLS_HANDSHAKE, ch_hs)
    state.feed_hs(ch_hs)
    _hexdump("CH record", ch_rec)

    # Send CH (value=4, with 44000000 IOCTL header)
    sensor.ctrl_out(REQ_CMD, value=4,
                    data=b'\x44\x00\x00\x00' + ch_rec, label="TLS_OUT(CH)")
    raw_sh = sensor.ctrl_in(REQ_RESP, 0x400, label="TLS_IN(CH)")
    if raw_sh and raw_sh[0] == TLS_ALERT:
        raise RuntimeError(f"TLS Alert on CH: {raw_sh.hex()}")

    # ----- Parse ServerHello + CertReq + SHellDone -----
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
            hl   = struct.unpack_from('>I', b'\x00' + rbody[hoff+1:hoff+4])[0]
            hmsg = rbody[hoff: hoff + 4 + hl]
            state.feed_hs(hmsg)
            if ht == 0x02:       # ServerHello
                srv_rand = hmsg[6:38]
                _log(f"SH: cipher={hmsg[38+rbody[hoff+38]:].hex()[:4]}")
            elif ht == 0x0d:     # CertificateRequest -- expected
                pass
            elif ht == 0x0e:     # ServerHelloDone
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
    run_marker = cli_rand[4:6]
    if cert_data_398 is not None:
        cert_body = run_marker + cert_data_398[:398]
    else:
        pub_key = eck2_pub_le or b'\x00' * 32
        cert_body = (run_marker + host_142
                     + struct.pack('>HB', 2, 32) + b'\x00'
                     + pub_key + b'\x00' * 220)
    assert len(cert_body) == 400, f"cert_body={len(cert_body)}"

    body     = b'\x00\x01\x90' + b'\x00\x01\x90' + cert_body
    cert_hs  = make_hs_message(0x0b, body)   # Certificate
    state.feed_hs(cert_hs)
    _hexdump("Cert HS", cert_hs)

    # ----- ClientKeyExchange -----
    cke_hs = make_hs_message(0x10, b'\x04' + eph_x + eph_y)
    state.feed_hs(cke_hs)

    # ----- CertificateVerify -----
    hs_dig = state.hs_digest()
    _hexdump("HS hash for CertVerify", hs_dig)
    sig_der = sign_ecdsa_sha256(eck2_be, hs_dig)
    cv_hs   = make_hs_message(0x0f, sig_der)
    state.feed_hs(cv_hs)

    # ----- ChangeCipherSpec + Finished -----
    hs_hash_fin = state.hs_digest()
    verify      = prf(master, 'client finished', hs_hash_fin, 12)
    fin_hs      = make_hs_message(0x14, verify)

    hs_plain = cert_hs + cke_hs + cv_hs
    hs_rec   = make_tls_record(TLS_HANDSHAKE, hs_plain)
    ccs_rec  = make_tls_record(TLS_CHANGE_CS, b'\x01')

    # Reset client seq after CCS
    state.client_seq = 0
    fin_cipher = state.encrypt(TLS_HANDSHAKE, fin_hs)
    state.client_seq = 1   # next encrypted record starts at 1
    fin_rec = make_tls_record(TLS_HANDSHAKE, fin_cipher)

    burst = b'\x44\x00\x00\x00' + hs_rec + ccs_rec + fin_rec
    _hexdump("bundle total", burst)
    sensor.ctrl_out(REQ_CMD, value=0, data=burst, label="TLS_OUT(BUNDLE)")
    raw_sfin = sensor.ctrl_in(REQ_RESP, 0x200, label="TLS_IN(BUNDLE)")

    # ----- Server CCS + Finished -----
    state.server_seq = 0
    off = 0
    while off + 5 <= len(raw_sfin):
        stype = raw_sfin[off]
        slen  = struct.unpack_from('>H', raw_sfin, off + 3)[0]
        sbody = raw_sfin[off + 5: off + 5 + slen]
        off  += 5 + slen
        if stype == TLS_ALERT:
            raise RuntimeError(f"TLS Alert from server: {sbody.hex()}")
        if stype == TLS_HANDSHAKE:
            try:
                srv_fin = state.decrypt(TLS_HANDSHAKE, sbody)
                _hexdump("Server Finished", srv_fin)
            except Exception as exc:
                _log(f"  Server Finished decrypt failed: {exc}")
    return state


# ---------------------------------------------------------------------------
# App commands (encrypted IOCTL layer)
# ---------------------------------------------------------------------------

def _app_encrypt(state, content_type, plain):
    body = state.encrypt(content_type, plain)
    rec  = make_tls_record(content_type, body)
    # Pad to 8-byte alignment (native format)
    pad  = (-len(rec)) % 8
    return rec + bytes(pad)


def _app_decrypt(state, data):
    if len(data) < 5:
        return None
    rtype  = data[0]
    rlen   = struct.unpack('>H', data[3:5])[0]
    rbody  = data[5: 5 + rlen]
    return state.decrypt(rtype, rbody)


def app_cmd(sensor, state, plain, value=7, label=""):
    """Send one encrypted app command, return decrypted response."""
    _log(f"  APP({label}) plain: {plain.hex()}")
    out = _app_encrypt(state, TLS_APP_DATA, plain)
    sensor.ctrl_out(REQ_CMD, value=value, data=out, label=f"APP_OUT({label})")
    raw = sensor.ctrl_in(REQ_RESP, 256, label=f"APP_IN({label})")
    if not raw:
        _log("  No response")
        return None
    if raw[0] == TLS_ALERT:
        _log(f"  TLS ALERT: {raw.hex()}")
        return None
    try:
        pt = _app_decrypt(state, raw)
        _log(f"  APP({label}) resp: {pt.hex() if pt else 'None'}")
        return pt
    except Exception as exc:
        _log(f"  App decrypt failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# list-db command sequence
# ---------------------------------------------------------------------------

def do_list_db(sensor, state):
    """
    Enumerate fingerprint database.
    Prints enrolled records to stdout regardless of SENSOR_TRACE.

    Sequence:
      GET_RECORD_COUNT  (value=6)
      STORAGE_QUERY_INIT x2 (value=7)
      STORAGE_QUERY_ALL wildcard (value=2)
      FETCH_RECORD for each GUID (value=2)
    """
    # GET_RECORD_COUNT
    app_cmd(sensor, state, bytes.fromhex('820000000000000207'),
            value=6, label="GET_RECORD_COUNT")

    # STORAGE_QUERY_INIT x2
    for n in (1, 2):
        app_cmd(sensor, state, bytes.fromhex('9e01'),
                value=7, label=f"QUERY_INIT_{n}")

    # STORAGE_QUERY_ALL wildcard
    query_resp = app_cmd(sensor, state,
                         bytes.fromhex('9f02' + '00' * 3 + 'ff' * 16),
                         value=2, label="QUERY_ALL")
    if not query_resp or len(query_resp) < 4:
        print("No records (empty QUERY_ALL response)")
        return

    slot_count = struct.unpack('<H', query_resp[2:4])[0]
    guids = []
    off = 4
    while off + 16 <= len(query_resp):
        guids.append(query_resp[off: off + 16])
        off += 16
    _log(f"STORAGE_QUERY_ALL: {len(guids)} slots (header claims {slot_count})")

    enrolled = []
    for guid in guids:
        rec = app_cmd(sensor, state,
                      bytes.fromhex('9f03' + '00' * 3) + guid,
                      value=2, label=f"FETCH_{guid[:4].hex()}")
        if rec and rec != b'\x00\x00\x00\x00':
            enrolled.append((guid, rec))

    if not enrolled:
        print("No enrolled fingerprints found.")
    else:
        print(f"Enrolled fingerprints ({len(enrolled)}):")
        for guid, rec in enrolled:
            print(f"  {guid.hex()}  data={rec.hex()}")


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ('list-db',):
        print("Usage: sensor.py list-db")
        sys.exit(1)

    print("Connecting to sensor...")
    sensor = Sensor()
    sensor.find_device()

    print("Running init phases...")
    sensor.init_phases()

    print("REQ_READY...")
    ready = sensor.req_ready()
    _log(f"REQ_READY = {ready.hex()}")

    # ----- PairingData -----
    print("Loading PairingData...")
    tlvs    = load_pairing_data()
    pair    = get_pairing_fields(tlvs) if tlvs else None

    if pair:
        host_142, eck2_le, cert_data, dev_x_be, dev_y_be, eck2_pub_le = pair
        eck2_be      = eck2_le[::-1]
        cert_data_398 = cert_data
        print(f"  host_142: {host_142[:8].hex()}...")
        _log(f"  eck2_le:  {eck2_le[:8].hex()}...")
        _log(f"  dev_x_be: {dev_x_be[:8].hex()}...")
    else:
        print("  No PairingData -- generating fresh ECS2 key pair")
        eck2_be_raw  = _rand(32)
        eck2_be      = eck2_be_raw
        eck2_pub     = ecdh_pubkey(eck2_be)
        eck2_pub_le  = eck2_pub[:32][::-1]
        host_142     = HOST_142_FALLBACK
        cert_data_398 = None
        dev_x_be, dev_y_be = DEV_X_BE, DEV_Y_BE

    # ----- TLS handshake -----
    print("TLS handshake...")
    state = do_tls_handshake(sensor, host_142, eck2_be, eck2_pub_le,
                             cert_data_398, dev_x_be, dev_y_be)
    print("  TLS OK")

    # ----- Save PairingData if fresh keys -----
    if pair is None and not os.path.exists(PAIRING_FILE):
        host_x_le = bytes(reversed(dev_x_be))
        host_y_le = bytes(reversed(dev_y_be))
        host_cert = (b'\x3f\x5f\x17\x00' + host_x_le + b'\x00' * 20
                     + host_y_le + b'\x00' * 54)
        pub_key = eck2_pub_le or b'\x00' * 32
        cb = (host_142 + struct.pack('>HB', 2, 32) + b'\x00'
              + pub_key + b'\x00' * 220)
        _save_pairing_tlv({1: cb, 2: bytes(reversed(eck2_be)), 3: host_cert})

    # ----- App commands -----
    if sys.argv[1] == 'list-db':
        print("list-db...")
        do_list_db(sensor, state)

    print("Done.")


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f"FATAL: {exc}")
        import traceback; traceback.print_exc()
        sys.exit(1)
