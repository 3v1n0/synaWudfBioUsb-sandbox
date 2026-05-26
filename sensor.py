#!/usr/bin/env python3
"""
Python USB driver for Synaptics/Kensington WBF biometric sensor (047d:00f2).

Protocol summary:
  Phase 1: 3 x (REQ_START + init_cmds + REQ_ACK)
  Phase 2: REQ_READY -- returns 0000 (challenge is built but optional)
  Phase 3: TLS 1.2 handshake over custom USB framing
  Phase 4: Encrypted IOCTL app commands (AES-256-GCM)

Key derivation (confirmed from native trace with Wine sym-key tracing):
  Cipher suite: 0xc02e (driver uses AES-256-GCM internally despite name)
  ECDH(client_ephemeral, device_pub_ECK1) -> ecdh_x (32 bytes)
  master = PRF_SHA384(ecdh_x, "master secret", cli_rand + srv_rand, 48)
    Note: cli first (standard TLS order)
  key_mat = PRF_SHA384(master, "key expansion", cli_rand + srv_rand, 72)
    client_enc = km[0:32]   (AES-256 key)
    server_enc = km[32:64]  (AES-256 key)
    client_iv4 = km[64:68]  (4-byte implicit IV prefix)
    server_iv4 = km[68:72]  (4-byte implicit IV prefix)
    No MAC keys (GCM provides authentication)
  GCM nonce (12 bytes) = implicit_iv4(4) + explicit_random(8)
  TLS record body = explicit_random(8) + ciphertext + tag(16)
  AAD = seq_num(8) + content_type(1) + TLS_VER(2) + plain_len(2)
  verify_data = PRF_SHA384(master, "client finished", hs_hash_sha256, 12)

Certificate body (400 bytes):
  [0:2]   run_marker = server_random[4:6]
  [2:144] HOST_142 from PairingData tag=1 blob[0:142]
  [144:146] LE u16 = 32 (pub_key length)
  [146:178] pub_key from PairingData tag=1 blob[144:176]
  [178:400] 222 zeros

Usage:
  python3 sensor.py list-db
  PROTO_TRACE=1 python3 sensor.py list-db
"""

import struct, sys, os, hashlib, hmac as _hmac, re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

try:
    import usb.core, usb.util
except ImportError:
    print("Install pyusb: pip install pyusb")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SENSOR_VID, SENSOR_PID = 0x047d, 0x00f2
USB_TIMEOUT = 5000
PROTO_TRACE = os.environ.get("PROTO_TRACE")

# USB control request codes
REQ_START = 0x19   # OUT, phase 1 init signal
REQ_ACK   = 0x1a   # IN,  phase 1 ack read
REQ_CMD   = 0x16   # OUT, send command data
REQ_RESP  = 0x17   # IN,  read response data
REQ_READY = 0x14   # IN,  ready check
REQ_END   = 0x1b   # OUT, end session signal
BM_OUT, BM_IN = 0x40, 0xc0

# TLS constants
TLS_VER       = b'\x03\x03'
TLS_HANDSHAKE = 0x16
TLS_CHANGE_CS = 0x14
TLS_APP_DATA  = 0x17
TLS_ALERT     = 0x15
# Cipher suite 0xc02e -- driver internally uses AES-256-GCM
CIPHER_SUITE  = b'\xc0\x2e'

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def proto_log(direction, layer, data):
    if PROTO_TRACE:
        print(f"[proto] {direction} dev {layer} len={len(data)} {data.hex()}")


# ---------------------------------------------------------------------------
# PRF (TLS 1.2, SHA-384) -- all derivations use this
# ---------------------------------------------------------------------------
def _p_hash(secret, seed, length):
    """P_SHA384(secret, seed) for TLS 1.2 PRF."""
    result = b''
    A = _hmac.new(secret, seed, hashlib.sha384).digest()
    while len(result) < length:
        result += _hmac.new(secret, A + seed, hashlib.sha384).digest()
        A = _hmac.new(secret, A, hashlib.sha384).digest()
    return result[:length]

def prf(secret, label, seed, length):
    """TLS 1.2 PRF with SHA-384."""
    return _p_hash(secret, label.encode() + seed, length)


# ---------------------------------------------------------------------------
# AES-256-GCM encrypt/decrypt (TLS 1.2 GCM record format)
#
# Record body layout:
#   explicit_nonce(8) + ciphertext(plain_len) + tag(16)
# Full GCM nonce = implicit_iv4(4) + explicit_nonce(8)
# AAD = seq_num(8) + content_type(1) + TLS_VER(2) + plain_len(2)
# ---------------------------------------------------------------------------
def tls_encrypt(key, implicit_iv4, seq_num, content_type, plaintext):
    """Encrypt plaintext using AES-256-GCM. Returns record body bytes."""
    explicit = os.urandom(8)
    nonce = implicit_iv4 + explicit
    aad = (struct.pack('>Q', seq_num)
           + bytes([content_type]) + TLS_VER
           + struct.pack('>H', len(plaintext)))
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce),
                 backend=default_backend()).encryptor()
    enc.authenticate_additional_data(aad)
    ct = enc.update(plaintext) + enc.finalize()
    tag = enc.tag  # 16 bytes
    return explicit + ct + tag

def tls_decrypt(key, implicit_iv4, seq_num, content_type, body):
    """Decrypt TLS record body using AES-256-GCM. Returns plaintext."""
    explicit = body[:8]
    ct       = body[8:-16]
    tag      = body[-16:]
    nonce = implicit_iv4 + explicit
    plain_len = len(ct)
    aad = (struct.pack('>Q', seq_num)
           + bytes([content_type]) + TLS_VER
           + struct.pack('>H', plain_len))
    dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag, min_tag_length=16),
                 backend=default_backend()).decryptor()
    dec.authenticate_additional_data(aad)
    return dec.update(ct) + dec.finalize_with_tag(tag)


# ---------------------------------------------------------------------------
# TLS record framing
# ---------------------------------------------------------------------------
def make_tls_record(content_type, data):
    return bytes([content_type]) + TLS_VER + struct.pack('>H', len(data)) + data

def make_hs_message(msg_type, body):
    return bytes([msg_type]) + struct.pack('>I', len(body))[1:] + body


# ---------------------------------------------------------------------------
# PairingData parsing
# ---------------------------------------------------------------------------
def load_pairing_data(reg_path=None):
    """
    Read PairingData from Wine registry. Returns raw hex blob bytes.
    """
    if reg_path is None:
        reg_path = os.path.expanduser('~/winelatestprefix/user.reg')
    text = open(reg_path, encoding='utf-16-le', errors='replace').read()
    # Find Software\\Synaptics\\PairingData section
    m = re.search(
        r'\[Software\\\\Synaptics\\\\PairingData\].*?(?=\[|\Z)',
        text, re.DOTALL)
    if not m:
        raise RuntimeError("PairingData key not found in registry")
    section = m.group(0)
    # Extract hex value (multi-line hex: entry like "name"=hex:XX,XX,...)
    hm = re.search(r'"[^"]+"\s*=\s*hex:([\s\S]+?)(?=\n"|\n\[|\Z)', section)
    if not hm:
        raise RuntimeError("PairingData hex value not found")
    hex_str = re.sub(r'[\s\\,]', '', hm.group(1))
    return bytes.fromhex(hex_str)


def _unprotect_dpapi_wine(blob):
    """
    Unwrap a Wine DPAPI blob using the Wine-compatible 3DES-CBC scheme.
    Returns decrypted bytes.
    """
    # Wine CryptUnprotectData uses 3DES-CBC with a key derived from:
    #   HMAC-SHA1(PBKDF2(username, salt, 1, 20, SHA1), optional_entropy)
    # and the salt is embedded in the blob header.
    #
    # Full parse: rely on sensor.py from the known-working implementation.
    # For now, use the subprocess approach to call the existing parse function.
    raise NotImplementedError(
        "DPAPI unwrap: use load_pairing_material() instead")


def load_pairing_material():
    """
    Load HOST_142, pub_key32 from PairingData registry blob.
    The blob has already been DPAPI-decrypted by b.exe and stored
    in a Wine registry path. We read it via the parse functions in the
    existing code (imported as module).
    Returns: (host_142, pub_key32) where both are bytes.
    """
    # Import from the utility module that already handles DPAPI unwrapping
    import importlib.util, pathlib
    # Try to import existing pairing functions
    spec = importlib.util.spec_from_file_location(
        "_old_sensor",
        str(pathlib.Path(__file__).parent / "_pairing_helper.py"))
    if spec is not None:
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.load_pairing_material()
    raise NotImplementedError("Need _pairing_helper.py")


def parse_pairing_tlv(blob):
    """
    Parse the 5-field TLV blob (after DPAPI decryption):
      tag=2: 32-byte device ID / session key
      tag=1: 400-byte HOST region:
               [0:142]   HOST_142
               [142:144] LE u16 = 32 (pub_key length)
               [144:176] pub_key (32 bytes)
               [176:400] zeros
      tag=4: 420-byte EC curve params
      tag=3: 400-byte DEV region:
               [0:142]   DEV_142
               [142:144] LE u16 = sig_len
               [144:...]  DER signature
      tag=0: end marker
    """
    fields = {}
    off = 0
    while off + 6 <= len(blob):
        tag = struct.unpack_from('<H', blob, off)[0]
        length = struct.unpack_from('<I', blob, off + 2)[0]
        data = blob[off + 6: off + 6 + length]
        fields[tag] = data
        off += 6 + length
        if tag == 0:
            break
    return fields


def load_pairing_from_blob(blob):
    """
    Given the raw DPAPI-decrypted PairingData blob, extract:
      host_142    (142 bytes)
      pub_key32   (32 bytes) -- client EC pub key stored after host_142
      dev_142     (142 bytes)
      dev_sig_der (DER ECDSA signature bytes, verifies dev_142)
    """
    f = parse_pairing_tlv(blob)
    host_region = f[1]   # 400 bytes
    dev_region  = f[3]   # 400 bytes
    host_142 = host_region[:142]
    pub_len  = struct.unpack_from('<H', host_region, 142)[0]
    pub_key  = host_region[144: 144 + pub_len]
    dev_142  = dev_region[:142]
    sig_len  = struct.unpack_from('<H', dev_region, 142)[0]
    dev_sig  = dev_region[144: 144 + sig_len]
    return host_142, pub_key, dev_142, dev_sig


def extract_ecs2_private_d(blob):
    """
    Extract the ECS2 private key D from the DPAPI-decrypted PairingData blob.
    The signing private key D is at blob[6:38] (LE bytes).
    Reversed to BE for use with ec.derive_private_key().
    """
    # tag=2 data (32 bytes) at offset 6 is the device-session key,
    # not the signing D. The signing D comes from Wine's ECS2 keypair
    # which is the runtime key derived from PairingData.
    # For challenge construction, we need to call BCryptSignHash which
    # uses the runtime key. Without Wine, we can use the pre-captured
    # sign-key from trace (session-specific).
    raise NotImplementedError(
        "Signing key D must be obtained from Wine runtime trace "
        "or by DPAPI-decrypting the PairingData blob offline.")


# ---------------------------------------------------------------------------
# ECDSA signing (for CertVerify)
# ---------------------------------------------------------------------------
def sign_ecdsa_sha256(priv_d_be, digest32):
    """
    Sign digest32 with EC P-256 private key priv_d_be (32 bytes, big-endian).
    Returns DER-encoded signature.
    """
    d_int = int.from_bytes(priv_d_be, 'big')
    priv = ec.derive_private_key(d_int, ec.SECP256R1(), default_backend())
    return priv.sign(digest32, ec.ECDSA(ec_utils.Prehashed()))


def sign_ecdsa_raw(priv_d_be, digest32):
    """
    Sign digest32 and return raw r||s (64 bytes).
    """
    der = sign_ecdsa_sha256(priv_d_be, digest32)
    r, s = ec_utils.decode_dss_signature(der)
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


# ---------------------------------------------------------------------------
# Sensor USB interface
# ---------------------------------------------------------------------------
class Sensor:
    def __init__(self):
        self.dev = None
        self.find_device()

    def find_device(self):
        dev = usb.core.find(idVendor=SENSOR_VID, idProduct=SENSOR_PID)
        if dev is None:
            raise RuntimeError(
                f"Sensor {SENSOR_VID:#06x}:{SENSOR_PID:#06x} not found")
        dev.set_configuration()
        self.dev = dev

    # --- Low-level USB helpers ---

    def ctrl_out(self, request, value=0, index=0, data=b''):
        proto_log('>>>', 'ctrl_setup',
                  struct.pack('<BBHHH', BM_OUT, request, value, index, len(data)))
        if data:
            proto_log('>>>', 'enc', bytes(data))
        self.dev.ctrl_transfer(BM_OUT, request, value, index, data,
                               timeout=USB_TIMEOUT)

    def ctrl_in(self, request, length, value=0, index=0):
        proto_log('>>>', 'ctrl_setup',
                  struct.pack('<BBHHH', BM_IN, request, value, index, length))
        resp = self.dev.ctrl_transfer(BM_IN, request, value, index, length,
                                      timeout=USB_TIMEOUT)
        resp = bytes(resp)
        proto_log('<<<', 'enc', resp)
        return resp

    # --- Init protocol helpers ---

    def send_cmd(self, data, value=1):
        """Send a command via REQ_CMD (0x16) OUT then REQ_RESP (0x17) IN."""
        self.ctrl_out(REQ_CMD, value=value, data=data)

    def recv_resp(self, length, value=0):
        return self.ctrl_in(REQ_RESP, length, value=value | 0x8000)

    def send_cmd_recv(self, data, out_len, value=1):
        self.send_cmd(data, value=value)
        resp = self.recv_resp(out_len)
        proto_log('<<<', 'plain', resp)
        return resp

    def do_plain_exchange(self, cmd_data, resp_len):
        """
        Plain (unencrypted) command exchange.
        OUT: REQ_CMD value=1; IN: REQ_RESP.
        """
        proto_log('>>>', 'plain', cmd_data)
        self.ctrl_out(REQ_CMD, value=1, data=cmd_data)
        resp = self.ctrl_in(REQ_RESP, resp_len)
        proto_log('<<<', 'plain', resp)
        return resp

    # --- Init phases (3 iterations) ---

    def init_phase(self):
        """
        One round of init:
          REQ_START (OUT, no data)
          REQ_ACK   (IN,  1 byte = 0x01)
          cmd 0x01... (read device_info, 8B -> 38B)
          cmd 0x8e09 (read device_info_ext, 24B -> 26B)
          cmd 0x8e1a (read cert, 24B -> 78B)
          cmd 0x19   (phase marker, 8B -> 68B)
        """
        # Signal start
        self.ctrl_out(REQ_START)
        ack = self.ctrl_in(REQ_ACK, 1)
        assert ack == b'\x01', f"REQ_ACK = {ack.hex()}, expected 01"

        # Read device info (8B -> 38B)
        cmd_device_info = bytes.fromhex('0100000000000000')
        self.send_cmd_recv(cmd_device_info, 0x26)

        # Read device info ext (24B -> 26B)
        cmd_info_ext = bytes.fromhex(
            '8e0900020000000000000000000000000000000000000000')
        self.send_cmd_recv(cmd_info_ext, 0x1a)

        # Read cert (24B -> 78B)
        cmd_cert = bytes.fromhex(
            '8e1a00020000000000000000000000000000000000000000')
        self.send_cmd_recv(cmd_cert, 0x4e)

        # Phase marker (8B -> 68B)
        cmd_phase = bytes.fromhex('1900000000000000')
        self.send_cmd_recv(cmd_phase, 0x44)

    def init_phases(self):
        """Run 3 init phases (as native b.exe does)."""
        for i in range(3):
            self.init_phase()

    # --- REQ_READY ---

    def req_ready(self):
        """
        Send REQ_READY (0x14 IN, 2 bytes). Returns status bytes.
        Native returns 0000 (even without challenge).
        """
        resp = self.ctrl_in(REQ_READY, 2)
        proto_log('<<<', 'plain', resp)
        return resp

    # --- TLS framing ---

    def tls_send(self, tls_records, value=7):
        """
        Send TLS records with 44000000 prefix via REQ_CMD.
        """
        payload = b'\x44\x00\x00\x00' + tls_records
        proto_log('>>>', 'enc', payload)
        self.ctrl_out(REQ_CMD, value=value, data=payload)

    def tls_recv(self, max_len=0x200):
        """
        Read TLS response via REQ_RESP.
        Returns raw bytes including 44000000 prefix (drop it).
        """
        resp = self.ctrl_in(REQ_RESP, max_len)
        return resp

    # --- Encrypted app command ---

    def send_encrypted(self, tls_state, plaintext, resp_len, value=2):
        """
        Encrypt plaintext as TLS ApplicationData, send via REQ_CMD value=2,
        read response via REQ_RESP, decrypt and return plaintext.
        """
        ct = tls_state.encrypt(TLS_APP_DATA, plaintext)
        rec = make_tls_record(TLS_APP_DATA, ct)
        payload = rec
        proto_log('>>>', 'enc', payload)
        self.ctrl_out(REQ_CMD, value=value, data=payload)
        raw_resp = self.ctrl_in(REQ_RESP, resp_len)
        # Parse TLS record
        rec_type = raw_resp[0]
        rec_len  = struct.unpack_from('>H', raw_resp, 3)[0]
        rec_data = raw_resp[5: 5 + rec_len]
        plain = tls_state.decrypt(rec_type, rec_data)
        proto_log('<<<', 'plain', plain)
        return plain


# ---------------------------------------------------------------------------
# TLS state machine
# ---------------------------------------------------------------------------
class TLSState:
    def __init__(self):
        self.client_seq = 0
        self.server_seq = 0
        self.client_enc_key = None
        self.server_enc_key = None
        self.client_iv4 = None
        self.server_iv4 = None
        self.hs_hash = hashlib.sha256()  # running handshake hash

    def feed_hs(self, data):
        """Feed handshake message data (without TLS record header) to HS hash."""
        self.hs_hash.update(data)

    def get_hs_hash(self):
        return self.hs_hash.copy().digest()

    def setup_keys(self, master, cli_rand, srv_rand):
        """Derive key material from master secret (cli_rand + srv_rand order)."""
        # AES-256-GCM: no MAC keys, enc=32B each, implicit_iv=4B each = 72B total
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
# TLS handshake
# ---------------------------------------------------------------------------
def do_tls_handshake(sensor, host_142, pub_key32, sign_d_be=None):
    """
    Perform the full TLS 1.2 handshake with the device.

    Parameters:
      sensor     -- Sensor instance (USB connected)
      host_142   -- 142-byte host EC key blob from PairingData tag=1[0:142]
      pub_key32  -- 32-byte host pub key from PairingData tag=1[144:176]
      sign_d_be  -- 32-byte private signing key (big-endian) for CertVerify.
                    If None, CertVerify will be skipped (may cause server alert).

    Returns TLSState with keys set up.
    """
    state = TLSState()

    # -----------------------------------------------------------------------
    # Generate ephemeral ECDH key pair
    # -----------------------------------------------------------------------
    ephemeral_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    eph_pub = ephemeral_key.public_key().public_numbers()
    eph_x_be = eph_pub.x.to_bytes(32, 'big')
    eph_y_be = eph_pub.y.to_bytes(32, 'big')
    eph_d_be = ephemeral_key.private_numbers().private_value.to_bytes(32, 'big')

    # -----------------------------------------------------------------------
    # Build ClientHello
    # -----------------------------------------------------------------------
    # Client random: 4-byte timestamp + 28 random bytes (use zeros for now,
    # native trace uses zeros for gmt_unix_time field)
    import time, os
    cli_rand = struct.pack('>I', int(time.time()) & 0xffffffff) + os.urandom(28)

    ch_body = (
        TLS_VER                    # client_version
        + cli_rand                 # random (32 bytes)
        + b'\x07' + bytes(7)       # session_id length=7 + 7 zero bytes
        # cipher suites (12 bytes = 6 suites, no null terminator)
        + b'\x00\x0c'
        + b'\xc0\x05'             # TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
        + CIPHER_SUITE            # 0xc02e
        + b'\x00\x3d'
        + b'\x00\x8d'
        + b'\x00\xa8'
        + b'\x00\xa9'
        + b'\x00'                  # compression: no methods (length=0)
        # extensions (10 bytes)
        + b'\x00\x0a'
        + b'\x00\x0a'             # ext: supported_groups
        + b'\x00\x04'
        + b'\x00\x02'
        + b'\x00\x17'             # secp256r1
        + b'\x00\x0b'             # ext: ec_point_formats
        + b'\x00\x02'
        + b'\x01\x00'             # uncompressed
        + b'\x00\x00\x00\x00'    # 4 trailing zeros (native format)
    )
    ch_hs = make_hs_message(0x01, ch_body)   # ClientHello
    ch_rec = make_tls_record(TLS_HANDSHAKE, ch_hs)
    state.feed_hs(ch_hs)

    proto_log('>>>', 'plain', ch_hs)

    # Send via value=4 (matches native trace: 4016040000...)
    sensor.ctrl_out(REQ_CMD, value=4, data=b'\x44\x00\x00\x00' + ch_rec)
    raw_sh = sensor.ctrl_in(REQ_RESP, 1)  # returns full ServerHello bytes

    # -----------------------------------------------------------------------
    # Parse ServerHello response
    # -----------------------------------------------------------------------
    # Strip leading byte if needed
    data = raw_sh
    # Parse multiple TLS records
    srv_rand = None
    records = []
    off = 0
    while off < len(data):
        if off + 5 > len(data):
            break
        rec_type = data[off]
        rec_len  = struct.unpack_from('>H', data, off + 3)[0]
        rec_body = data[off + 5: off + 5 + rec_len]
        records.append((rec_type, rec_body))
        off += 5 + rec_len

    # Process handshake record(s)
    for rec_type, rec_body in records:
        if rec_type != TLS_HANDSHAKE:
            continue
        # Parse handshake messages within the record
        hoff = 0
        while hoff < len(rec_body):
            ht = rec_body[hoff]
            hl = int.from_bytes(rec_body[hoff+1:hoff+4], 'big')
            hbody = rec_body[hoff+4: hoff+4+hl]
            hs_msg = rec_body[hoff:hoff+4+hl]
            state.feed_hs(hs_msg)
            if ht == 0x02:  # ServerHello
                # version(2) + random(32) + session_id_len(1) + ... + cipher(2) + comp(1)
                srv_rand = hbody[2:34]
            elif ht == 0x0b:  # Certificate
                # cert_list_len(3) + cert_len(3) + cert_body(cert_len)
                cert_list_len = int.from_bytes(hbody[0:3], 'big')
                cert_len      = int.from_bytes(hbody[3:6], 'big')
                dev_cert_body = hbody[6: 6 + cert_len]
                # Extract device ECDH public key from cert body (DEV_142)
                # cert body structure: run_marker(2) + DEV_142(142) + ...
                dev_142 = dev_cert_body[2:144]
            elif ht == 0x0e:  # ServerHelloDone
                pass
            hoff += 4 + hl

    if srv_rand is None:
        raise RuntimeError("ServerHello not received or parsed")

    # run_marker for our Certificate = srv_rand[4:6]
    run_marker = srv_rand[4:6]

    # -----------------------------------------------------------------------
    # Extract device ECDH static public key from DEV_142
    # DEV_142: 3f5f1700 + X_le(32) + 36*00 + Y_le(32) + 38*00
    # -----------------------------------------------------------------------
    dev_x_le = dev_142[4:36]
    dev_y_le = dev_142[72:104]
    dev_x_int = int.from_bytes(dev_x_le[::-1], 'big')
    dev_y_int = int.from_bytes(dev_y_le[::-1], 'big')
    device_pub = ec.EllipticCurvePublicNumbers(
        dev_x_int, dev_y_int, ec.SECP256R1()
    ).public_key(default_backend())

    # -----------------------------------------------------------------------
    # ECDH key exchange -> pre-master (= master) secret
    # -----------------------------------------------------------------------
    ecdh_x = ephemeral_key.exchange(ec.ECDH(), device_pub)  # 32 bytes
    master = prf(ecdh_x, 'master secret', cli_rand + srv_rand, 48)
    state.setup_keys(master, cli_rand, srv_rand)

    # -----------------------------------------------------------------------
    # Build client Certificate (from PairingData)
    # -----------------------------------------------------------------------
    # cert_body (400 bytes): run_marker(2) + host_142(142) + u16le(32) + pub_key32(32) + 222*0
    cert_body = (run_marker + host_142
                 + struct.pack('<H', 32) + pub_key32
                 + bytes(222))
    assert len(cert_body) == 400, f"cert_body len={len(cert_body)}"

    cert_hs_body = (
        b'\x00\x01\x90'       # cert_list_len = 400
        + b'\x00\x01\x90'     # cert_len = 400
        + cert_body
    )
    cert_hs = make_hs_message(0x0b, cert_hs_body)  # Certificate

    # -----------------------------------------------------------------------
    # Build ClientKeyExchange: uncompressed ephemeral ECDH pub point
    # -----------------------------------------------------------------------
    eph_pub_uncompressed = b'\x04' + eph_x_be + eph_y_be
    cke_body = (
        struct.pack('>H', 1 + 64)   # length of point data
        + eph_pub_uncompressed
    )
    cke_hs = make_hs_message(0x10, cke_body)  # ClientKeyExchange

    # Feed to HS hash before CertVerify
    state.feed_hs(cert_hs)
    state.feed_hs(cke_hs)

    # -----------------------------------------------------------------------
    # CertVerify: ECDSA sign handshake hash
    # -----------------------------------------------------------------------
    if sign_d_be is not None:
        hs_digest = state.get_hs_hash()
        sig_der = sign_ecdsa_sha256(sign_d_be, hs_digest)
        # Build CertVerify message
        cv_body = (
            b'\x04\x01'               # hash=SHA256, sig=RSA (native uses 0x0401)
            + struct.pack('>H', len(sig_der))
            + sig_der
        )
        cv_hs = make_hs_message(0x0f, cv_body)  # CertificateVerify
        state.feed_hs(cv_hs)
    else:
        cv_hs = b''

    # -----------------------------------------------------------------------
    # ChangeCipherSpec + Finished
    # -----------------------------------------------------------------------
    hs_hash_for_finished = state.get_hs_hash()
    verify_data = prf(master, 'client finished', hs_hash_for_finished, 12)
    proto_log('>>>', 'plain', b'\x14\x00\x00\x0c' + verify_data)

    finished_body = verify_data
    finished_hs = make_hs_message(0x14, finished_body)  # Finished

    # Build second client burst: Certificate + CKE + CertVerify (in one HS record)
    hs_records_combined = cert_hs + cke_hs + (cv_hs if cv_hs else b'')
    ccs_record     = make_tls_record(TLS_CHANGE_CS, b'\x01')
    # Encrypt Finished
    fin_cipher = state.encrypt(TLS_HANDSHAKE, finished_hs)
    fin_record = make_tls_record(TLS_HANDSHAKE, fin_cipher)

    burst = b'\x44\x00\x00\x00'
    burst += make_tls_record(TLS_HANDSHAKE, hs_records_combined)
    burst += ccs_record
    burst += fin_record

    proto_log('>>>', 'enc', burst)
    sensor.ctrl_out(REQ_CMD, value=1, data=burst)

    # -----------------------------------------------------------------------
    # Receive server CCS + Finished
    # -----------------------------------------------------------------------
    raw_sfin = sensor.ctrl_in(REQ_RESP, 1)  # trigger
    raw_sfin = sensor.ctrl_in(REQ_RESP, 0x200)

    # Parse server Finished to verify
    off = 0
    while off < len(raw_sfin):
        if off + 5 > len(raw_sfin):
            break
        stype = raw_sfin[off]
        slen  = struct.unpack_from('>H', raw_sfin, off + 3)[0]
        sbody = raw_sfin[off + 5: off + 5 + slen]
        if stype == TLS_CHANGE_CS:
            pass
        elif stype == TLS_HANDSHAKE:
            # Decrypt server Finished
            srv_fin_plain = state.decrypt(TLS_HANDSHAKE, sbody)
            proto_log('<<<', 'plain', srv_fin_plain)
        elif stype == TLS_ALERT:
            raise RuntimeError(
                f"TLS Alert from server: {sbody.hex()}")
        off += 5 + slen

    return state


# ---------------------------------------------------------------------------
# App commands (encrypted IOCTL layer)
# ---------------------------------------------------------------------------
def app_cmd(sensor, tls_state, payload, resp_len, value=6):
    """
    Send one encrypted app command. payload = raw plaintext (no TLS framing).
    Pads TLS record to 8-byte alignment with zero bytes (native format).
    """
    proto_log('>>>', 'plain', payload)
    gcm_body = tls_state.encrypt(TLS_APP_DATA, payload)
    rec = make_tls_record(TLS_APP_DATA, gcm_body)
    # Pad to 8-byte alignment
    pad = (-len(rec)) % 8
    rec_padded = rec + bytes(pad)
    sensor.ctrl_out(REQ_CMD, value=value, data=rec_padded)
    raw = sensor.ctrl_in(REQ_RESP, 1)  # returns full response
    rec_type = raw[0]
    rec_len  = struct.unpack_from('>H', raw, 3)[0]
    rec_data = raw[5: 5 + rec_len]
    plain = tls_state.decrypt(rec_type, rec_data)
    proto_log('<<<', 'plain', plain)
    return plain


# ---------------------------------------------------------------------------
# list-db command sequence
# ---------------------------------------------------------------------------
def do_list_db(sensor, tls_state):
    """
    Issue GET_RECORD_COUNT then iterate STORAGE_QUERY.
    Native trace sequence:
      >>> plain 9B: 820000000000000207  (GET_RECORD_COUNT, value=6)
      <<< plain 34B: 0000...count at [13]...
      >>> plain 2B: 9e01  x2  (STORAGE_QUERY_INIT, value=7)
      >>> plain 21B: 9f02 + 3*00 + 16*ff  (STORAGE_QUERY_ALL, value=2)
      <<< plain N: count(2) + ? + records...
      >>> plain 21B: 9f03 + 3*00 + id(16)  (FETCH_RECORD, value=2)
      <<< plain 4B: status
    """
    # GET_RECORD_COUNT
    gc_cmd = bytes.fromhex('820000000000000207')
    gc_resp = app_cmd(sensor, tls_state, gc_cmd, value=6)
    status = struct.unpack_from('<H', gc_resp, 0)[0]
    if status != 0:
        raise RuntimeError(f"GET_RECORD_COUNT failed: {status:#06x}")
    count = gc_resp[0x0d] if len(gc_resp) > 0x0d else 0
    print(f"Record count: {count}")

    # STORAGE_QUERY_INIT x2
    for _ in range(2):
        app_cmd(sensor, tls_state, bytes.fromhex('9e01'), value=7)

    # STORAGE_QUERY_ALL wildcard: 9f02 + 3 zeros + 16 xff
    query_cmd = bytes.fromhex('9f02' + '00' * 3 + 'ff' * 16)
    query_resp = app_cmd(sensor, tls_state, query_cmd, value=2)
    status = struct.unpack_from('<H', query_resp, 0)[0]
    if status != 0:
        raise RuntimeError(f"STORAGE_QUERY failed: {status:#06x}")
    # Count in response at [2:4] (LE u16), records start at [4], each 16 bytes
    rec_count = struct.unpack_from('<H', query_resp, 2)[0] if len(query_resp) > 3 else 0
    rec_ids = []
    for i in range(rec_count):
        off = 4 + i * 16
        if off + 16 <= len(query_resp):
            rec_ids.append(query_resp[off: off + 16])
    print(f"Records found: {len(rec_ids)}")
    for rid in rec_ids:
        print(f"  ID: {rid.hex()}")
        # Fetch record
        fetch_cmd = bytes.fromhex('9f03' + '00' * 3) + rid[:16]
        fetch_resp = app_cmd(sensor, tls_state, fetch_cmd, value=2)
        f_status = struct.unpack_from('<H', fetch_resp, 0)[0]
        print(f"    status: {f_status:#06x}")


# ---------------------------------------------------------------------------
# Challenge construction (using PairingData)
# ---------------------------------------------------------------------------
def build_challenge(host_142, sign_d_be):
    """
    Build the 408-byte challenge body to send with REQ_READY.
    Format: 93 + HOST_142(142) + 4700 + DER_ECDSA_sig + zero_padding
    The ECDSA signature is over SHA256(HOST_142).
    Returns 408 bytes.
    """
    digest = hashlib.sha256(host_142).digest()
    sig_der = sign_ecdsa_sha256(sign_d_be, digest)
    body = bytes([0x93]) + host_142 + b'\x47\x00' + sig_der
    body += bytes(408 - len(body))
    assert len(body) == 408
    return body


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------
def main_list_db():
    """Full flow: init -> ready -> TLS -> list-db."""
    print("Connecting to sensor...")
    sensor = Sensor()

    print("Running init phases...")
    sensor.init_phases()

    print("REQ_READY...")
    ready_resp = sensor.req_ready()
    print(f"  ready status: {ready_resp.hex()}")

    # Load PairingData from Wine registry
    print("Loading PairingData...")
    try:
        raw_blob = load_pairing_data()
        # The blob may need DPAPI decryption.
        # If already decrypted (i.e., known format starts with 0200...):
        if raw_blob[:2] == b'\x02\x00':
            pairing_blob = raw_blob
        else:
            raise RuntimeError(
                "PairingData needs DPAPI decryption. "
                "Run b.exe first to populate the registry with decrypted data, "
                "or implement offline DPAPI unwrap.")
        host_142, pub_key32, dev_142, dev_sig = load_pairing_from_blob(pairing_blob)
    except Exception as e:
        print(f"  WARNING: PairingData not available ({e})")
        print("  Using hardcoded session values from trace (session-specific!)")
        # These are from the native trace -- will NOT work in a new session
        host_142 = bytes.fromhex(
            "3f5f170018fb0dcbf6ee75b28e68c82db6ce2547cc659632f8170d35e769c74f"
            "32efdbb30000000000000000000000000000000000000000000000000000000000"
            "0000000000000000158de761a89d2e262f61804e4b216728b52cba09be72eee6e3"
            "6903eccc7556c9000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000002"
        )[:142]
        pub_key32 = bytes.fromhex(
            "b851e1b012ca65858a81377efab1e9b2c47c0f3cab2a3da14aa4fd6c7c1f1eb5"
        )
        sign_d_be = None  # CertVerify will be skipped
    else:
        # sign_d_be would come from decrypting ECS2 signing key from PairingData
        sign_d_be = None  # TODO: extract from PairingData

    print("Starting TLS handshake...")
    try:
        tls_state = do_tls_handshake(sensor, host_142, pub_key32, sign_d_be)
    except Exception as e:
        print(f"TLS handshake failed: {e}")
        raise

    print("TLS established. Running list-db...")
    do_list_db(sensor, tls_state)


def main():
    if len(sys.argv) < 2:
        print("Usage: sensor.py <command>")
        print("Commands: list-db")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'list-db':
        main_list_db()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == '__main__':
    main()
