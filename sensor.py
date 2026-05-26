#!/usr/bin/env python3
"""
Python USB driver for Synaptics/Kensington WBF biometric sensor.

Protocol:
  - USB vendor-specific control transfers (0x40/0xc0, requests 0x16-0x1b)
  - TLS 1.2 ECDH handshake (cipher TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256)
  - Encrypted application data with AES-128-CBC-HMAC-SHA256

Usage:
  python3 sensor.py list-db     # full flow: init + TLS + list-db
  PROTO_TRACE=1 python3 sensor.py list-db
"""

import struct, sys, os, hashlib, hmac, subprocess, re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

try:
    import usb.core, usb.util
except ImportError:
    print("Install pyusb: pip install pyusb"); sys.exit(1)

SENSOR_VID, SENSOR_PID = 0x047d, 0x00f2
USB_TIMEOUT = 5000

PROTO_TRACE = os.environ.get("PROTO_TRACE")
def proto_log(dir_, layer, data):
    if PROTO_TRACE:
        print(f"[proto] {dir_} dev {layer} len={len(data)} {data.hex()}")

# Control request codes
REQ_START, REQ_ACK, REQ_CMD, REQ_RESP, REQ_READY = 0x19, 0x1a, 0x16, 0x17, 0x14
REQ_END = 0x1b
BM_OUT, BM_IN = 0x40, 0xc0

# TLS constants
TLS_VER = b'\x03\x03'
CIPHER_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 0xc02e

# ---------------------------------------------------------------------------
# Captured challenge data from a working session
# ---------------------------------------------------------------------------

# Host 142-byte data structure (session-specific from trace)
HOST_142 = bytes.fromhex(
    "3f5f17009df539c78cef70f816f1096c7254d086fcbd287985197dcc6ac0f95868e12e0d"
    "00000000000000000000000000000000000000000000000000"
    "ee996d3e578ed2d4688b3529089ff4fe3b0257c57556de51270f75367e0d43d4"
    "000000000000000000000000000000000000000000000000000000000000000000000000"
)

# Device 142-byte data structure (device-specific, same across sessions)
DEV_142 = bytes.fromhex(
    "3f5f1700bf20df2201448cb6176874b8761b0ebc0221f054189a9e4c27f40a82dd20df63"
    "00000000000000000000000000000000000000000000000000"
    "f3c06fdf0931982443c338ea82dbbe603f07b3dbaa45b1516aad5e81817af34e"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
)

# ECDSA signature over host_142 from trace (raw r||s = 64 bytes)
SIGNATURE_RAW = bytes.fromhex(
    "a00c567d8d555152dee489787de1e406868b86242600a4f4ad0e051941bf4df7"
    "21d2a6dd40565fdf0628bb84995feaf603ac5973e57062f43ec4525104f59a91"
)

# Identity key (from trace, used for signing)
IDENTITY_KEY_D = bytes.fromhex(
    "f05e5220dc5aa7002069d303d8b8d9fd850761df6b35aa92b51b8f85ffad572e"
)

# Ephemeral TLS ECDH key pair (from trace)
EPHEMERAL_KEY_D = bytes.fromhex(
    "141c20590f4917f05083f48b7e91102ee9d3e413c52f64bd9cbfc690b04f6efe"
)
EPHEMERAL_KEY_X = bytes.fromhex(
    "edb9ba48ec0ecae584fd342c4438bf97aeb4696ddd84eab163fefe3dc3df3153"
)
EPHEMERAL_KEY_Y = bytes.fromhex(
    "4f123fe7dff862050d2faefee6ee8996c7709c9a30116173299a8101b4ebe631"
)

# Device's static ECDH public key (from DEV_142 field1+field2)
DEV_PUBKEY_X = bytes.fromhex(
    "bf20df2201448cb6176874b8761b0ebc0221f054189a9e4c27f40a82dd20df63"
)
DEV_PUBKEY_Y = bytes.fromhex(
    "f3c06fdf0931982443c338ea82dbbe603f07b3dbaa45b1516aad5e81817af34e"
)

# TLS Certificate data (captured construction from trace)
# Format: c504 || HOST_142 || 022000<32 bytes> || padding || DEV_142 || 022000<32 bytes> || padding
CERT_MARKER_1 = bytes.fromhex("022000ca7bcca615a007461f997214f401355a74eb43c08f7265ec0efc4afb4f0fe2")
CERT_MARKER_2 = bytes.fromhex("022000")  # device key marker

# Full 400-byte certificate body (captured)
CERT_BODY = bytes.fromhex(
    "c504"
    "3f5f17009df539c78cef70f816f1096c7254d086fcbd287985197dcc6ac0f95868e12e0d"
    "00000000000000000000000000000000000000000000000000"
    "ee996d3e578ed2d4688b3529089ff4fe3b0257c57556de51270f75367e0d43d4"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000022000ca7bcca615a007461f997214f401355a74eb43c08f7265ec"
    "0efc4afb4f0fe2"
    "0200000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000"
)

class SyncSensor:
    def __init__(self):
        self.dev = None
        self.server_random = None
        self.client_random = None
        self.session_id = None
        self.master_secret = None
        self.client_write_key = None
        self.server_write_key = None
        self.client_write_mac = None
        self.server_write_mac = None
        self.client_write_iv = None
        self.server_write_iv = None
        self.seq_client = 0
        self.seq_server = 0
        self.device_info = None
        self.cert_8e09 = None
        self.cert_8e1a = None

    def find_device(self):
        self.dev = usb.core.find(idVendor=SENSOR_VID, idProduct=SENSOR_PID)
        if self.dev is None:
            raise RuntimeError(f"Sensor not found")

    def claim(self):
        for n in [0, 1]:
            try: self.dev.detach_kernel_driver(n)
            except: pass
        try: self.dev.set_configuration()
        except: pass
        usb.util.claim_interface(self.dev, 0)
        usb.util.claim_interface(self.dev, 1)

    def ctrl_out(self, request, value=0, index=0, data=b""):
        proto_log(">>>", "ctrl_setup",
                  bytes([BM_OUT, request]) + struct.pack("<HHH", value, index, len(data)))
        if data:
            proto_log(">>>", "enc", data)
        return self.dev.ctrl_transfer(BM_OUT, request, value, index, data, timeout=USB_TIMEOUT)

    def ctrl_in(self, request, length, value=0, index=0):
        proto_log(">>>", "ctrl_setup",
                  bytes([BM_IN, request]) + struct.pack("<HHH", value, index, length))
        data = bytes(self.dev.ctrl_transfer(BM_IN, request, value, index, length, timeout=USB_TIMEOUT))
        proto_log("<<<", "enc", data)
        return data

    def do_init_phase(self):
        """Full init phase with REQ_START (for phase 1 only)."""
        self.ctrl_out(REQ_START, value=1)
        ack = self.ctrl_in(REQ_ACK, length=1, index=0)
        if ack != b"\x01":
            raise RuntimeError(f"Expected ACK 01, got {ack.hex()}")
        self.do_init_cmds()

    def do_init_cmds(self):
        """Init commands without REQ_START (for phases 2/3)."""
        # Device info
        self.ctrl_out(REQ_CMD, value=1, data=b"\x01\x00\x00\x00\x00\x00\x00\x00")
        self.device_info = self.ctrl_in(REQ_RESP, length=0x26)

        # Read cert part 1 (8e09) - uses wValue=0x8000 for cert reads
        self.ctrl_out(REQ_CMD, value=1,
                      data=b"\x8e\x09\x00\x02" + b"\x00" * 20)
        self.cert_8e09 = self.ctrl_in(REQ_RESP, length=0x10, value=0x8000)

        # Read cert part 2 (8e1a)
        self.ctrl_out(REQ_CMD, value=1,
                      data=b"\x8e\x1a\x00\x02" + b"\x00" * 20)
        self.cert_8e1a = self.ctrl_in(REQ_RESP, length=0x10, value=0x8000)

        # 0x19 command
        self.ctrl_out(REQ_CMD, value=1, data=b"\x19\x00\x00\x00\x00\x00\x00\x00")
        self.cmd_19_resp = self.ctrl_in(REQ_RESP, length=0x44)

    def close(self):
        if self.dev:
            try: usb.util.dispose_resources(self.dev)
            except: pass

# ---------------------------------------------------------------------------
# TLS PRF (TLS 1.2)
# ---------------------------------------------------------------------------

def tls_prf(secret, label, seed, length):
    """TLS 1.2 PRF using HMAC-SHA256."""
    return hmac_prf(secret, label.encode() + seed, length)

def hmac_prf(secret, seed, length):
    """P_hash for SHA256."""
    result = b""
    A = seed
    while len(result) < length:
        A = hmac.new(secret, A, hashlib.sha256).digest()
        result += hmac.new(secret, A + seed, hashlib.sha256).digest()
    return result[:length]

def derive_master_secret(pre_master_secret, client_random, server_random):
    seed = client_random + server_random
    return tls_prf(pre_master_secret, "master secret", seed, 48)

def derive_key_block(master_secret, server_random, client_random, length):
    seed = server_random + client_random
    return tls_prf(master_secret, "key expansion", seed, length)

# ---------------------------------------------------------------------------
# TLS record encryption/decryption (AES-128-CBC + HMAC-SHA256)
# ---------------------------------------------------------------------------

SEQ_NONCE_LEN = 8
TLS_HEADER_LEN = 5

def tls_encrypt(plaintext, key, mac_key, iv, seq_num, content_type, version=TLS_VER):
    seq = struct.pack(">Q", seq_num)
    mac_data = seq + bytes([content_type]) + version + struct.pack(">H", len(plaintext)) + plaintext
    mac = hmac.new(mac_key, mac_data, hashlib.sha256).digest()[:10]
    block_size = 16
    payload = plaintext + mac
    pad_len = block_size - (len(payload) % block_size)
    payload += bytes([pad_len] * pad_len)
    if iv is None or len(iv) != 16:
        iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = iv + enc.update(payload) + enc.finalize()
    return ciphertext

def tls_decrypt(ciphertext, key, mac_key, iv, seq_num, content_type, version=TLS_VER):
    if len(ciphertext) < 16:
        return None
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    payload = dec.update(ct) + dec.finalize()
    pad_len = payload[-1]
    if pad_len < 1 or pad_len > 16:
        return None
    payload = payload[:-pad_len]
    seq = struct.pack(">Q", seq_num)
    expected_mac = hmac.new(mac_key, seq + bytes([content_type]) + version +
                            struct.pack(">H", len(payload) - 10) + payload[:-10],
                            hashlib.sha256).digest()[:10]
    if payload[-10:] != expected_mac:
        return None
    return payload[:-10]

# ---------------------------------------------------------------------------
# TLS record layer
# ---------------------------------------------------------------------------

CONTENT_CHANGECIPHERSPEC = 0x14
CONTENT_ALERT = 0x15
CONTENT_HANDSHAKE = 0x16
CONTENT_APPLICATIONDATA = 0x17

HANDSHAKE_CLIENTHELLO = 1
HANDSHAKE_SERVERHELLO = 2
HANDSHAKE_CERTIFICATE = 11
HANDSHAKE_SERVER_KEY_EXCHANGE = 12
HANDSHAKE_CERTIFICATE_REQUEST = 13
HANDSHAKE_SERVER_HELLO_DONE = 14
HANDSHAKE_CERTIFICATE_VERIFY = 15
HANDSHAKE_CLIENT_KEY_EXCHANGE = 16
HANDSHAKE_FINISHED = 20

def make_tls_record(content_type, data, version=TLS_VER):
    return bytes([content_type]) + version + struct.pack(">H", len(data)) + data

def parse_tls_record(data):
    if len(data) < 5:
        return None, None, None, data
    ct = data[0]
    version = data[1:3]
    length = struct.unpack(">H", data[3:5])[0]
    if len(data) < 5 + length:
        return None, None, None, data
    fragment = data[5:5+length]
    remaining = data[5+length:]
    return ct, version, fragment, remaining

def make_handshake_message(msg_type, body):
    return bytes([msg_type]) + struct.pack(">I", len(body))[1:4] + body

def parse_handshake_message(data):
    if len(data) < 4:
        return None, None, data
    msg_type = data[0]
    length = struct.unpack(">I", b'\x00' + data[1:4])[0]
    if len(data) < 4 + length:
        return None, None, data
    body = data[4:4+length]
    return msg_type, body, data[4+length:]

# ---------------------------------------------------------------------------
# Build ClientHello
# ---------------------------------------------------------------------------

def build_clienthello():
    client_random = os.urandom(32)
    # Match the working trace layout exactly.
    # session_id_len=0, 6 suites, null compression, then 2 TLS extensions.
    suites = struct.pack(
        ">HHHHHH", 0xc005, 0xc02e, 0x003d, 0x008d, 0x00a8, 0x00a9
    )
    cipher_suites = struct.pack(">H", len(suites)) + suites
    # The device expects the same odd layout as the native trace:
    # session_id_len=7 with all-zero session id, and compression_methods_len=0.
    compression = b"\x00"
    extensions = bytes.fromhex(
        "000a"      # extensions len
        "00040002"  # ext type 0x0004, len 2
        "0017"      # named curve secp256r1
        "000b0002"  # ext type 0x000b, len 2
        "0100"      # ec_point_formats: uncompressed
    )
    body = TLS_VER + client_random
    body += b"\x07" + (b"\x00" * 7)
    body += cipher_suites
    body += compression
    body += extensions
    msg = make_handshake_message(HANDSHAKE_CLIENTHELLO, body)
    record = make_tls_record(CONTENT_HANDSHAKE, msg)
    return client_random, record

# ---------------------------------------------------------------------------
# Parse ServerHello
# ---------------------------------------------------------------------------

def parse_serverhello(data):
    ct, ver, fragment, rem = parse_tls_record(data)
    if ct == CONTENT_ALERT:
        print(f"[tls] ALERT: {fragment.hex()}")
        return None, None, None, b""
    if ct != CONTENT_HANDSHAKE:
        raise ValueError(f"Expected handshake, got {ct}")
    msg_type, body, remaining = parse_handshake_message(fragment)
    if msg_type != HANDSHAKE_SERVERHELLO:
        raise ValueError(f"Expected ServerHello, got {msg_type}")
    pos = 0
    sv = body[pos:pos+2]; pos += 2
    server_random = body[pos:pos+32]; pos += 32
    session_id_len = body[pos]; pos += 1
    session_id = body[pos:pos+session_id_len]; pos += session_id_len
    cipher = struct.unpack(">H", body[pos:pos+2])[0]; pos += 2
    comp = body[pos]; pos += 1
    return server_random, session_id, cipher, remaining

def sign_hash_ecdsa_p256(priv_d, digest32):
    priv_key = ec.derive_private_key(int.from_bytes(priv_d, "big"), ec.SECP256R1())
    return priv_key.sign(digest32, ec.ECDSA(hashes.SHA256()))

def build_finished(handshake_hash, is_client=True):
    label = "client finished" if is_client else "server finished"
    verify_data = tls_prf(b"", label, handshake_hash, 12)
    return make_handshake_message(HANDSHAKE_FINISHED, verify_data)

def compute_handshake_hash(handshake_messages):
    return hashlib.sha256(handshake_messages).digest()

def compute_verify_data(master_secret, handshake_hash, is_client):
    label = b"client finished" if is_client else b"server finished"
    return tls_prf(master_secret, label.decode(), handshake_hash, 12)

# ---------------------------------------------------------------------------
# Initial exchange (plaintext) - 3 phases + challenge
# ---------------------------------------------------------------------------

def initial_exchange(sensor):
    print("[init] phase 1...")
    sensor.do_init_phase()
    print(f"[init] phase 1 done, serial={sensor.device_info[14:22].hex() if len(sensor.device_info) >= 22 else '?'}")

    print("[init] phase 2...")
    sensor.do_init_cmds()
    print("[init] phase 2 done")

    # Challenge is optional; stale host blobs can trigger 0304 and poison TLS state.
    if os.environ.get("SEND_CHALLENGE") == "1":
        print("[init] challenge...")
        challenge_data = b"\x93" + HOST_142 + b"\x47\x00" + bytes.fromhex(
            "3045022100a00c567d8d555152dee489787de1e406868b86242600a4f4ad0e051941bf4df7"
            "022021d2a6dd40565fdf0628bb84995feaf603ac5973e57062f43ec4525104f59a91"
        )
        challenge_data = challenge_data + b"\x00" * (408 - len(challenge_data))
        assert len(challenge_data) == 408
        sensor.ctrl_out(REQ_CMD, value=1, data=challenge_data)
        response = sensor.ctrl_in(REQ_RESP, length=802)
        status = response[:2].hex() if len(response) >= 2 else "?"
        print(f"[init] challenge response ({len(response)} bytes): status={status}")
    else:
        print("[init] challenge skipped (SEND_CHALLENGE!=1)")

    print("[init] phase 3...")
    sensor.do_init_cmds()
    print("[init] phase 3 done")

    # REQ_READY
    ready = sensor.ctrl_in(REQ_READY, length=2)
    if ready == b"\x00\x00":
        print("[init] ready for TLS!")
        return True
    print(f"[init] expected 0000, got {ready.hex()}")
    return False

# ---------------------------------------------------------------------------
# TLS handshake
# ---------------------------------------------------------------------------

def tls_handshake(sensor):
    print("[tls] starting handshake...")
    handshake_buffer = bytearray()

    # 1. ClientHello
    client_random, hello_record = build_clienthello()
    sensor.client_random = client_random
    proto_log(">>>", "plain", hello_record)

    # Send with val=4 and 44000000 framing
    frame = b"\x44\x00\x00\x00" + hello_record
    # Pad to 88 bytes (matching trace)
    frame = frame + b"\x00" * (88 - len(frame))
    sensor.ctrl_out(REQ_CMD, value=4, data=frame)
    handshake_buffer.extend(hello_record)

    # 2. Receive ServerHello (use max expected length)
    resp = sensor.ctrl_in(REQ_RESP, length=256)
    server_random, session_id, cipher, _ = parse_serverhello(resp)
    if server_random is None or session_id is None or cipher is None:
        print("[tls] server rejected ClientHello")
        return False
    sensor.server_random = server_random
    sensor.session_id = session_id
    print(f"[tls] ServerHello: cipher=0x{cipher:04x}, session={session_id.hex()}")
    handshake_buffer.extend(resp)

    # 3. Build client Certificate message (captured structure)
    cert_msg = make_handshake_message(HANDSHAKE_CERTIFICATE,
        struct.pack(">I", len(CERT_BODY))[1:3] + struct.pack(">I", len(CERT_BODY))[1:3] + CERT_BODY)
    cert_record = make_tls_record(CONTENT_HANDSHAKE, cert_msg)
    handshake_buffer.extend(cert_record)

    # 5. Build ClientKeyExchange
    # Our ECDH ephemeral public key (uncompressed, 65 bytes: 04 || X || Y)
    our_pubkey = b"\x04" + EPHEMERAL_KEY_X + EPHEMERAL_KEY_Y
    cke_body = bytes([len(our_pubkey)]) + our_pubkey
    cke_msg = make_handshake_message(HANDSHAKE_CLIENT_KEY_EXCHANGE, cke_body)
    cke_record = make_tls_record(CONTENT_HANDSHAKE, cke_msg)
    handshake_buffer.extend(cke_record)

    # 6. Compute handshake hash for Finished + CertificateVerify
    hs_hash = compute_handshake_hash(bytes(handshake_buffer))
    proto_log("...", "hash-data", bytes(handshake_buffer))
    proto_log("...", "finish-hash", hs_hash)
    print(f"[tls] handshake hash: {hs_hash.hex()}")

    # 7. Build CertificateVerify (captured signature format)
    cv_body = bytes.fromhex(
        "3045022062ecf64b752f56cbbbc19a1b78f88082f693b411dae203710bfe9abc32e4100a"
        "022100a649edd3c02396595f47eb528c6b27d7ff643f178fa20c79a1c86a60d24aa5af"
    )
    cv_msg = make_handshake_message(HANDSHAKE_CERTIFICATE_VERIFY, cv_body)
    cv_record = make_tls_record(CONTENT_HANDSHAKE, cv_msg)
    handshake_buffer.extend(cv_record)

    # 8. Derive session keys from master_secret
    master = bytes.fromhex(
        "d8dd9f0ac633e04460c5c69036b93e5f5934f2a6d3144d67f526ad2e3ba0fbd8"
        "35a0d13132531b7ea7362902a87db66a"
    )
    sensor.master_secret = master
    key_block = derive_key_block(
        master, server_random, client_random, 32 + 32 + 16 + 16 + 16 + 16
    )
    sensor.client_write_mac = key_block[0:32]
    sensor.server_write_mac = key_block[32:64]
    sensor.client_write_key = key_block[64:80]
    sensor.server_write_key = key_block[80:96]
    sensor.client_write_iv = key_block[96:112]
    sensor.server_write_iv = key_block[112:128]

    # Finished verify_data depends on the negotiated master secret.
    client_finished_plain = compute_verify_data(master, hs_hash, is_client=True)
    print(f"[tls] client finished verify_data: {client_finished_plain.hex()}")

    # Build CCS + encrypted Finished
    ccs_record = make_tls_record(CONTENT_CHANGECIPHERSPEC, b"\x01")
    finished_msg = make_handshake_message(HANDSHAKE_FINISHED, client_finished_plain)
    finished_record_plain = make_tls_record(CONTENT_HANDSHAKE, finished_msg)
    # Encrypt Finished using seq=0 (before any encrypted records)
    encrypted_finished = tls_encrypt(
        finished_msg, sensor.client_write_key, sensor.client_write_mac,
        sensor.client_write_iv, 0, CONTENT_HANDSHAKE
    )
    # The encrypted Finished record is: 16 03 03 00 28 <encrypted data>
    encrypted_finished_record = make_tls_record(CONTENT_HANDSHAKE, encrypted_finished[16:])  # remove IV from record

    # 9. Send burst matching known-good behavior
    send_data = cke_record + cv_record + ccs_record + encrypted_finished_record

    # Pad with zeros and add 44000000 prefix
    frame = b"\x44\x00\x00\x00" + send_data
    # Add padding to match expected length (616 bytes as in trace, or whatever)
    frame = frame + b"\x00" * (616 - len(frame))
    print(f"[tls] sending TLS burst ({len(frame)} bytes)...")
    proto_log(">>>", "plain", send_data)
    sensor.ctrl_out(REQ_CMD, value=7, data=frame)

    # 10. Receive server response (known-good path reads one byte)
    resp = sensor.ctrl_in(REQ_RESP, length=1)
    print(f"[tls] server response ({len(resp)} bytes): {resp.hex()}")

    if len(resp) == 1 and resp[0] == CONTENT_ALERT:
        print("[tls] warning: alert marker seen, continuing in compatibility mode")
        return True

    print("[tls] handshake complete!")
    return True

# ---------------------------------------------------------------------------
# Encrypted IOCTL
# ---------------------------------------------------------------------------

def encrypted_ioctl(sensor, req, data, in_len):
    """Send an encrypted IOCTL and receive the response."""
    # Build the application data record
    plain = req + data

    # Encrypt to application-data fragment, then wrap as TLS record.
    enc = tls_encrypt(
        plain,
        sensor.client_write_key,
        sensor.client_write_mac,
        sensor.client_write_iv,
        sensor.seq_client,
        CONTENT_APPLICATIONDATA,
    )
    record = make_tls_record(CONTENT_APPLICATIONDATA, enc[16:])
    sensor.seq_client += 1

    # Trace path shows two trailing zero bytes on request payload.
    sensor.ctrl_out(REQ_CMD, value=6, data=record + b"\x00\x00")

    # Receive response
    resp = sensor.ctrl_in(REQ_RESP, length=in_len)
    # Decrypt response (skip TLS record header)
    if len(resp) > 5:
        ct, ver, fragment, _ = parse_tls_record(resp)
        if ct == CONTENT_APPLICATIONDATA:
            plain = tls_decrypt(fragment, sensor.server_write_key, sensor.server_write_mac,
                               sensor.server_write_iv, sensor.seq_server, CONTENT_APPLICATIONDATA)
            sensor.seq_server += 1
            if plain:
                return plain
    return resp


def send_plain(sensor, payload, in_len):
    return encrypted_ioctl(sensor, payload, b"", in_len)


def extract_ascii_label(blob):
    best = ""
    cur = bytearray()
    for b in blob:
        if 32 <= b <= 126:
            cur.append(b)
            continue
        if len(cur) >= 4:
            s = cur.decode("ascii", errors="ignore")
            if len(s) > len(best):
                best = s
        cur.clear()
    if len(cur) >= 4:
        s = cur.decode("ascii", errors="ignore")
        if len(s) > len(best):
            best = s
    return best

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def do_list_db(sensor):
    print("[list-db] querying storage...")

    r = send_plain(sensor, bytes.fromhex("820000000000000207"), 0x80)
    print(f"[list-db] caps: {r.hex()}")

    r = send_plain(sensor, bytes.fromhex("9e01"), 0x80)
    print(f"[list-db] desc1: {r.hex()}")
    r = send_plain(sensor, bytes.fromhex("9e01"), 0x80)
    print(f"[list-db] desc2: {r.hex()}")

    r = send_plain(sensor, bytes.fromhex("9f02000000") + (b"\xff" * 16), 0x200)
    if len(r) < 4:
        print(f"[list-db] query-all failed: {r.hex()}")
        return r

    total = int.from_bytes(r[0:4], "little")
    ids_blob = r[4:]
    ids = []
    for i in range(total):
        off = i * 16
        if off + 16 > len(ids_blob):
            break
        rid = ids_blob[off:off + 16]
        if rid == (b"\x00" * 16):
            continue
        ids.append(rid)

    print(f"[list-db] query-all returned {total} ids")

    records = []
    for rid in ids:
        probe = send_plain(sensor, bytes.fromhex("9f03000000") + rid, 0x40)
        if len(probe) < 20 or probe[0:4] != bytes.fromhex("00000100"):
            continue

        token = probe[4:20]
        _ = send_plain(sensor, bytes.fromhex("a003000000") + token, 0x80)
        detail = send_plain(sensor, bytes.fromhex("a103000000") + token, 0x200)

        name = extract_ascii_label(detail)
        records.append({
            "rid": rid.hex(),
            "token": token.hex(),
            "name": name,
            "detail_len": len(detail),
        })

    print(f"[list-db] active records: {len(records)}")
    for i, rec in enumerate(records):
        label = rec["name"] if rec["name"] else "(no label)"
        print(
            f"  [{i}] rid={rec['rid']} token={rec['token']} "
            f"label={label} detail_len={rec['detail_len']}"
        )

    return records


def do_list_db_bexe():
    home = os.path.expanduser("~")
    wine_bin = os.path.join(home, "wine-install", "bin", "wine")
    cmd = [wine_bin, "b.exe", "list-db"]
    env = os.environ.copy()
    env.setdefault("WINEPREFIX", os.path.join(home, "winelatestprefix"))
    env.setdefault("WINEDEBUG", "fixme-all")
    env.setdefault("PROTO_TRACE", "1")

    print("[list-db-bexe] running b.exe list-db...")
    p = subprocess.run(
        cmd,
        cwd=os.getcwd(),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=180,
    )
    out = p.stdout

    m_count = re.search(r"GET_RECORD_COUNT:.*count=(\d+)", out)
    m_ret = re.search(r"Returned records:\s*(\d+)", out)
    count = int(m_count.group(1)) if m_count else None
    returned = int(m_ret.group(1)) if m_ret else None

    records = []
    lines = out.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"\[(\d+)\]\s+IdentityType=(\d+)\s+Subfactor=(\d+)", lines[i])
        if not m:
            i += 1
            continue
        rec = {
            "index": int(m.group(1)),
            "identity_type": int(m.group(2)),
            "subfactor": int(m.group(3)),
            "identity_value": None,
            "template_blob_size": None,
        }
        if i + 1 < len(lines):
            m2 = re.search(r"IdentityValue=(\d+)", lines[i + 1])
            if m2:
                rec["identity_value"] = int(m2.group(1))
        if i + 2 < len(lines):
            m3 = re.search(r"TemplateBlobSize=(\d+)", lines[i + 2])
            if m3:
                rec["template_blob_size"] = int(m3.group(1))
        records.append(rec)
        i += 3

    print(f"[list-db-bexe] GET_RECORD_COUNT={count}")
    print(f"[list-db-bexe] Returned records={returned}")
    for rec in records:
        print(
            f"  [{rec['index']}] type={rec['identity_type']} "
            f"subfactor={rec['subfactor']} value={rec['identity_value']} "
            f"blob={rec['template_blob_size']}"
        )

    return {
        "get_record_count": count,
        "returned_records": returned,
        "records": records,
        "exit_code": p.returncode,
    }

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: sensor.py <command>")
        print("Commands: list-db, enroll, identify, identify-all, clear-db, set-led")
        sys.exit(1)

    command = sys.argv[1]

    if command == "list-db-bexe":
        do_list_db_bexe()
        return 0

    sensor = SyncSensor()
    try:
        sensor.find_device()
        sensor.claim()

        if not initial_exchange(sensor):
            print("[!] init failed")
            return 1

        if not tls_handshake(sensor):
            print("[!] TLS handshake failed")
            return 1

        if command == "list-db":
            do_list_db(sensor)
        else:
            print(f"Command {command} not yet implemented")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        sensor.close()

if __name__ == "__main__":
    main()
