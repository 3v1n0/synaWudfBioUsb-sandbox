#!/usr/bin/env python3
"""
Minimal Python driver for Kensington VeriMark DT (047d:00f2).

Protocol:
  Phase 1: 3x(REQ_START + init_cmds)
  Phase 2: REQ_READY (challenge optional, returns 0000)
  Phase 3: TLS 1.2 (0xc02e, ECDH-ECDSA-AES256-GCM-SHA384)
  Phase 4: Encrypted IOCTL over AES-256-GCM

All PairingData fields are hardcoded constants from b.exe trace.
No Wine dependency.

Usage:
  PROTO_TRACE=1 python3 sensor.py list-db
"""

import struct, sys, os, hashlib, hmac as _hmac, time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

try:
    import usb.core, usb.util
except ImportError:
    print("Install pyusb: pip install pyusb"); sys.exit(1)

# ---------------------------------------------------------------------------
# Constants from b.exe trace
# ---------------------------------------------------------------------------

# PairingData Host_142: 3f5f1700 + X_le(32) + 36*00 + Y_le(32) + 38*00
HOST_142 = bytes.fromhex(
    "3f5f170018fb0dcbf6ee75b28e68c82db6ce2547cc659632f8170d35e769c74f"
    "32efdbb30000000000000000000000000000000000000000000000000000000000"
    "0000000000000000158de761a89d2e262f61804e4b216728b52cba09be72eee6e3"
    "0369ccec5576c90000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000")[:142]

# Host public key X (BE, matches host_142[4:36] reversed)
HOST_X_BE = bytes.fromhex(
    "b3dbef324fc769e7350d17f8329665cc4725ceb62dc8688eb275eef6cb0dfb18")
# Host public key Y (BE, matches host_142[72:104] reversed)
HOST_Y_BE = bytes.fromhex(
    "c95675ccec0369e3e6ee72be09ba2cb52867214b4e80612f262e9da861e78d15")

# PairingData Tag 2 = client private key (LE), reversed to BE = signing D
# D*G = (HOST_X_BE, HOST_Y_BE)
TAG2_BE = bytes.fromhex(
    "cca803106523ed52964f95a3742b85b349cba81759fd52387c0547a8af9d577f")

# Device key blob (DEV_142): 3f5f1700 + X_le(32) + 36*00 + Y_le(32) + 38*00
DEV_142 = bytes.fromhex(
    "3f5f1700"
    "bf20df2201448cb6176874b8761b0ebc0221f054189a9e4c27f40a82dd20df63"
    + "00" * 36
    + "f3c06fdf0931982443c338ea82dbbe603f07b3dbaa45b1516aad5e81817af34e"
    + "00" * 38)[:142]

PROTO_TRACE = os.environ.get('PROTO_TRACE') == '1'

# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def prf(secret, label, seed, out_len):
    """TLS 1.2 PRF with SHA-384 (P_hash)."""
    s = label.encode() + seed
    out = b''
    a = _hmac.new(secret, s, hashlib.sha384).digest()
    while len(out) < out_len:
        out += _hmac.new(secret, a + s, hashlib.sha384).digest()
        a = _hmac.new(secret, a, hashlib.sha384).digest()
    return out[:out_len]

def _proto(bytes_len, layer, data):
    if PROTO_TRACE:
        n = 0
        off = 0
        while off < len(data):
            chunk = data[off:off+64]
            addr = f"0x{off:04x}" if len(data) > 64 else ""
            print(f"[proto] {layer} {addr} {chunk.hex()}")
            n += 1
            off += 64

class TLSKeys:
    """AES-256-GCM encrypt/decrypt per TLS record."""

    def __init__(self, master, cli_rand, srv_rand):
        km = prf(master, "key expansion", cli_rand + srv_rand, 72)
        self.client_enc = km[0:32]
        self.server_enc = km[32:64]
        self.client_iv4 = km[64:68]
        self.server_iv4 = km[68:72]
        self.client_seq = 0
        self.server_seq = 0

    @staticmethod
    def _aad(seq, typ, ver, plen):
        return struct.pack('>Q', seq) + bytes([typ]) + ver + struct.pack('>H', plen)

    def encrypt(self, typ, plain, explicit=b''):
        if not explicit:
            explicit = os.urandom(8)
        nonce = self.client_iv4 + explicit
        aes = Cipher(algorithms.AES(self.client_enc), modes.GCM(nonce),
                     backend=default_backend()).encryptor()
        aes.authenticate_additional_data(self._aad(self.client_seq, typ, b'\x03\x03', len(plain)))
        ct = aes.update(plain) + aes.finalize()
        self.client_seq += 1
        return explicit + ct + aes.tag

    def decrypt(self, typ, body):
        explicit, ct, tag = body[:8], body[8:-16], body[-16:]
        nonce = self.server_iv4 + explicit
        aes = Cipher(algorithms.AES(self.server_enc), modes.GCM(nonce, tag),
                     backend=default_backend()).decryptor()
        aes.authenticate_additional_data(self._aad(self.server_seq, typ, b'\x03\x03', len(ct)))
        pt = aes.update(ct) + aes.finalize()
        self.server_seq += 1
        return pt


def sign_ecdsa_sha256(priv_d_be, digest32):
    d_int = int.from_bytes(priv_d_be, 'big')
    priv = ec.derive_private_key(d_int, ec.SECP256R1(), default_backend())
    return priv.sign(digest32, ec.ECDSA(ec_utils.Prehashed(hashes.SHA256())))


# ---------------------------------------------------------------------------
# USB Sensor
# ---------------------------------------------------------------------------

REQ_START = 0x19
REQ_ACK   = 0x17
REQ_READY = 0x1a
REQ_CMD   = 0x16
REQ_RESP  = 0x17

TLS_VER       = b'\x03\x03'
CIPHER_SUITE  = b'\xc0\x2e'
TLS_CHANGE_CS = 0x14
TLS_HANDSHAKE = 0x16


class Sensor:
    def __init__(self):
        dev = usb.core.find(idVendor=0x047d, idProduct=0x00f2)
        if dev is None:
            raise RuntimeError("Sensor 047d:00f2 not found")
        try:
            dev.set_configuration()
        except usb.core.USBError:
            pass
        self.dev = dev

    def ctrl_out(self, bRequest, wValue=0, wIndex=0, data=b''):
        if data:
            self.dev.ctrl_transfer(0x41, bRequest, wValue, wIndex, data, timeout=5000)
        else:
            self.dev.ctrl_transfer(0x41, bRequest, wValue, wIndex, timeout=5000)

    def ctrl_in(self, bRequest, wLength, wValue=0, wIndex=0):
        return self.dev.ctrl_transfer(0xc1, bRequest, wValue, wIndex, wLength, timeout=5000)

    def init_phases(self):
        """Three rounds of REQ_START + init_cmds."""
        for round_n in range(3):
            self.ctrl_out(REQ_START, value=1)
            ack = self.ctrl_in(REQ_ACK, 1)
            assert ack == b'\x01', f"round {round_n}: ack={ack.hex()}"
            for cmd_hex in [
                    "0100000000000000",
                    "8e09002d000000000000000000000000000000000000000000000000000000",
                    "8e1a007d025303000000000000000000000000000000000000000000000000",
                    "1900000000000000",
            ]:
                self.ctrl_out(REQ_CMD, value=1, data=bytes.fromhex(cmd_hex))
                # We don't parse responses, just consume them
                resp = self.ctrl_in(REQ_RESP, 0x100)
                _proto(len(resp), f"init_r{round_n}", resp)

    def req_ready(self):
        self.ctrl_out(REQ_READY, value=1)
        return self.ctrl_in(REQ_RESP, 0x400)


# ---------------------------------------------------------------------------
# TLS Handshake
# ---------------------------------------------------------------------------

def make_hs_message(msg_type, body):
    return bytes([msg_type]) + struct.pack('>I', len(body))[1:] + body


def tls_handshake(sensor):
    """Full TLS 1.2 handshake. Returns TLSKeys."""
    hs_hash = hashlib.sha256()
    def feed_hs(data):
        hs_hash.update(data)

    # Ephemeral ECDH key pair
    eph_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    eph_pub = eph_key.public_key().public_numbers()
    eph_x_be = eph_pub.x.to_bytes(32, 'big')
    eph_y_be = eph_pub.y.to_bytes(32, 'big')

    # Client random
    cli_rand = struct.pack('>I', int(time.time()) & 0xffffffff) + os.urandom(28)

    # ClientHello
    ch_body = (
        TLS_VER
        + cli_rand                    # random (32)
        + b'\x07' + bytes(7)          # session_id len=7 + 7 zero bytes
        + b'\x00\x0c'                 # cipher suite list len=12
        + b'\xc0\x05'                 # TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
        + CIPHER_SUITE                # 0xc02e
        + b'\x00\x3d'
        + b'\x00\x8d'
        + b'\x00\xa8'
        + b'\x00\xa9'
        + b'\x00'                      # compression: length=0
        + b'\x00\x0a'                  # ext_len_total=10
        + b'\x00\x04'                  # ext type=0x0004 (supported_groups)
        + b'\x00\x02'
        + b'\x00\x17'                  # secp256r1
        + b'\x00\x0b'                  # ext ec_point_formats
        + b'\x00\x02'
        + b'\x01\x00'                  # uncompressed
        + b'\x00\x00\x00\x00'          # trailing zeros
    )
    ch_hs = make_hs_message(0x01, ch_body)
    feed_hs(ch_hs)
    ch_rec = bytes([TLS_HANDSHAKE]) + b'\x03\x01' + struct.pack('>H', len(ch_hs)) + ch_hs
    _proto(len(ch_rec), ">>> CH", ch_rec)

    # Send CH
    sensor.ctrl_out(REQ_CMD, value=4, data=b'\x44\x00\x00\x00' + ch_rec)
    raw = sensor.ctrl_in(REQ_RESP, 0x400)

    # Parse server response
    if raw[:4] == b'\x44\x00\x00\x00':
        raw = raw[4:]
    _proto(len(raw), "<<< server", raw)

    srv_rand = None
    off = 0
    while off + 5 <= len(raw):
        rtype = raw[off]
        rlen = struct.unpack_from('>H', raw, off + 3)[0]
        rbody = raw[off + 5: off + 5 + rlen]
        off += 5 + rlen
        if rtype != TLS_HANDSHAKE:
            continue
        hoff = 0
        while hoff < len(rbody):
            ht = rbody[hoff]
            hl = struct.unpack_from('>I', b'\x00' + rbody[hoff+1:hoff+4])[0]
            hmsg = rbody[hoff: hoff + 4 + hl]
            feed_hs(hmsg)
            if ht == 0x02:
                # hmsg = type(1) + len(3) + body(hl)
                # body = ver(2) + random(32) + session_id(1+s_id_len) + ...
                # random at body[2:34] = hmsg[6:38]
                srv_rand = hmsg[6:38]
            elif ht == 0x0d:  # CertificateRequest
                pass
            elif ht == 0x0e:  # ServerHelloDone
                pass
            hoff += 4 + hl

    if srv_rand is None:
        raise RuntimeError("No ServerHello in response")

    # Device ECDH static key from DEV_142
    dev_x_int = int.from_bytes(DEV_142[4:36][::-1], 'big')
    dev_y_int = int.from_bytes(DEV_142[72:104][::-1], 'big')
    device_pub = ec.EllipticCurvePublicNumbers(
        dev_x_int, dev_y_int, ec.SECP256R1()).public_key(default_backend())

    # ECDH key agreement
    ecdh_x = eph_key.exchange(ec.ECDH(), device_pub)
    master = prf(ecdh_x, "master secret", cli_rand + srv_rand, 48)
    ks = TLSKeys(master, cli_rand, srv_rand)

    # Client Certificate (400 bytes)
    run_marker = cli_rand[4:6]
    cert_data = (run_marker + HOST_142 + struct.pack('<H', 32)
                 + HOST_X_BE + bytes(222))
    assert len(cert_data) == 400
    cert_hs_body = (b'\x00\x01\x90' + b'\x00\x01\x90' + cert_data)
    cert_hs = make_hs_message(0x0b, cert_hs_body)
    feed_hs(cert_hs)

    # ClientKeyExchange
    cke_body = b'\x04' + eph_x_be + eph_y_be
    cke_hs = make_hs_message(0x10, cke_body)
    feed_hs(cke_hs)

    # CertificateVerify
    hs_digest = hs_hash.digest()
    sig_der = sign_ecdsa_sha256(TAG2_BE, hs_digest)
    cv_hs = make_hs_message(0x0f, sig_der)
    feed_hs(cv_hs)
    _proto(len(sig_der), "sig-der", sig_der)

    # Finished
    verify = prf(master, "client finished", hs_hash.digest(), 12)
    fin_hs = make_hs_message(0x14, verify)

    # Build burst: Cert + CKE + CertVerify (plain HS) + CCS + Finished (enc)
    hs_plain = cert_hs + cke_hs + cv_hs
    hs_rec = bytes([TLS_HANDSHAKE]) + b'\x03\x03' + struct.pack('>H', len(hs_plain)) + hs_plain
    ccs_rec = bytes([TLS_CHANGE_CS]) + b'\x03\x03\x00\x01\x01'
    fin_cipher = ks.encrypt(TLS_HANDSHAKE, fin_hs)
    fin_rec = bytes([TLS_HANDSHAKE]) + b'\x03\x03' + struct.pack('>H', len(fin_cipher)) + fin_cipher
    burst = b'\x44\x00\x00\x00' + hs_rec + ccs_rec + fin_rec
    _proto(len(burst), ">>> burst", burst)
    sensor.ctrl_out(REQ_CMD, value=7, data=burst)

    # Receive server CCS + Finished
    raw_sfin = sensor.ctrl_in(REQ_RESP, 0x200)
    _proto(len(raw_sfin), "<<< sfin", raw_sfin)

    # Verify server Finished
    off = 0
    while off + 5 <= len(raw_sfin):
        rtype = raw_sfin[off]
        rlen = struct.unpack_from('>H', raw_sfin, off + 3)[0]
        rbody = raw_sfin[off + 5: off + 5 + rlen]
        off += 5 + rlen
        if rtype == TLS_HANDSHAKE:
            pt = ks.decrypt(TLS_HANDSHAKE, rbody)
            _proto(len(pt), "<<< sfin-pt", pt)
            # pt[0]=type(0x14), pt[1:4]=len(3), pt[4:]=verify_data
            srv_verify = pt[4:]
            _proto(len(srv_verify), "srv-verify", srv_verify)

    return ks


# ---------------------------------------------------------------------------
# App commands (encrypted)
# ---------------------------------------------------------------------------

def app_cmd(sensor, ks, plain, value=7):
    """Send encrypted app command, return decrypted response."""
    plain_padded = plain + b'\x00' * ((8 - len(plain) % 8) % 8) if len(plain) % 8 else plain
    body = ks.encrypt(0x16, plain_padded)
    rec = bytes([0x16]) + b'\x03\x03' + struct.pack('>H', len(body)) + body
    burst = b'\x44\x00\x00\x00' + rec
    _proto(len(burst), ">>> app", burst)
    sensor.ctrl_out(REQ_CMD, value=value, data=burst)
    raw = sensor.ctrl_in(REQ_RESP, 0x200)
    if raw[:4] == b'\x44\x00\x00\x00':
        raw = raw[4:]
    _proto(len(raw), "<<< app", raw)
    off = 0
    while off + 5 <= len(raw):
        rtype = raw[off]
        rlen = struct.unpack_from('>H', raw, off + 3)[0]
        rbody = raw[off + 5: off + 5 + rlen]
        off += 5 + rlen
        if rtype == 0x17:  # App data
            pt = ks.decrypt(0x17, rbody)
            return pt
    raise RuntimeError("No app data response")


def list_db(sensor, ks):
    """Enumerate fingerprint database."""
    # First send GET_RECORD_COUNT
    cmd = bytes.fromhex("820000000000000207")
    _proto(len(cmd), "get-record-count", cmd)
    resp = app_cmd(sensor, ks, cmd, value=6)
    count = struct.unpack_from('<H', resp, 0)[0]
    print(f"  Record count: {count}")

    if count == 0:
        return

    # STORAGE_QUERY_INIT
    qinit = bytes.fromhex("9e01")
    _proto(len(qinit), "query-init", qinit)
    app_cmd(sensor, ks, qinit, value=7)

    # STORAGE_QUERY_ALL
    qall = bytes.fromhex("9f0200000016" + "ff" * 16)
    _proto(len(qall), "query-all", qall)
    resp = app_cmd(sensor, ks, qall, value=2)
    n_records = struct.unpack_from('<H', resp, 0)[0]
    print(f"  Records found: {n_records}")

    # FETCH each record
    for i in range(n_records):
        rec_id = bytes(16)  # or from query response
        fetch_cmd = bytes.fromhex("9f03000000") + rec_id
        _proto(len(fetch_cmd), f"fetch-{i}", fetch_cmd)
        resp = app_cmd(sensor, ks, fetch_cmd, value=2)
        status = struct.unpack_from('<H', resp, 0)[0]
        print(f"    Record {i}: status={status:#06x}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2 or sys.argv[1] != 'list-db':
        print("Usage: python3 sensor.py list-db"); sys.exit(1)

    print("Init phases...")
    sensor = Sensor()
    sensor.init_phases()

    print("REQ_READY...")
    ready = sensor.req_ready()
    print(f"  ready={ready.hex()}")

    print("TLS handshake...")
    ks = tls_handshake(sensor)
    print("  TLS OK")

    print("list-db...")
    list_db(sensor, ks)
    print("Done")


if __name__ == '__main__':
    main()
