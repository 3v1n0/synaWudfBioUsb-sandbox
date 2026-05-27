#!/usr/bin/env python3
"""Synaptics sensor driver - trace-compare mode for TLS handshake."""

import os, sys, struct, hashlib, hmac, textwrap, re, usb.core
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

USB_ID = os.environ.get("USB_ID", "047d:00f2")
TRACE = os.environ.get("SENSOR_TRACE", "1") == "1"
DRY = os.environ.get("DRY_RUN", "0") == "1"
DET = os.environ.get("PROTO_DETERMINISTIC_RNG", "0") == "1"
_det_counter = 0

def det_rand(n):
    global _det_counter
    if not DET:
        return os.urandom(n)
    VALS = [
        bytes.fromhex('11706a5ba84658230d9017644cfe77ab4e21f028d347d48c59cb44f1c67cce80'),
        bytes.fromhex('4d3739abead420f73aa76ae680f875f9db593ac59c7471ab1740dc0e4a8976f2'),
        bytes.fromhex('a865ca0589a97663'),
    ]
    for v in VALS:
        if len(v) == n and _det_counter < len(VALS):
            val = VALS[_det_counter]
            _det_counter += 1
            return val
    return bytes(n)

REQ_START = 0x19; REQ_ACK = 0x1a; REQ_CMD = 0x16; REQ_RESP = 0x17; REQ_READY = 0x14
BM_OUT = 0x40; BM_IN = 0xc0
TLS_HS = 0x16; TLS_CCS = 0x14; TLS_APP = 0x17

INIT_CMD1 = b'\x01' + b'\x00'*7
INIT_CMD2 = b'\x8e\x09\x00\x02' + b'\x00'*20
INIT_CMD3 = b'\x8e\x1a\x00\x02' + b'\x00'*20
INIT_CMD4 = b'\x19' + b'\x00'*7

DEV_X_BE  = bytes.fromhex('63df20dd820af4274c9e9a1854f02102bc0e1b76b8746817b68c440122df20bf')
DEV_Y_BE  = bytes.fromhex('4ef37a81815ead6a51b145aadbb3073f60bedb82ea38c34324983109df6fc0f3')

def be_to_le(b):
    return bytes(reversed(b))

DEV_X_LE = be_to_le(DEV_X_BE)
DEV_Y_LE = be_to_le(DEV_Y_BE)

# HOST_142 = DEV_142 format: header + X(LE) + 20*00 + Y(LE) + padding
HOST_142 = b'\x3f\x5f\x17\x00' + DEV_X_LE + b'\x00' * 20 + DEV_Y_LE + b'\x00' * 54
assert len(HOST_142) == 142, f"HOST_142={len(HOST_142)}"


def t(msg, *a):
    if TRACE: print(f"[sensor] {msg}", *a)

def hexdump(label, data, maxlen=256):
    if not TRACE: return
    s = data[:maxlen].hex()
    if len(data) > maxlen:
        s += f"...({len(data)}B)"
    print(f"  {label}: {s}")

def fmt_setup(bm, req, val, idx, ln):
    return f"{bm:02x}{req:02x}{val:04x}{idx:04x}{ln:04x}"


# ── PairingData store (local file, fallback to Wine registry) ──────────

PAIRING_FILE = os.environ.get("PAIRING_FILE") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "pairing.dat")

WINE_DPAPI_SECRET = b"I'm hunting wabbits"

def save_pairing_data_tlv(tlvs):
    """Save TLV dict {tag: value} to local file."""
    data = b''
    for tag in sorted(tlvs):
        val = tlvs[tag]
        data += struct.pack('<HI', tag, len(val)) + val
    try:
        with open(PAIRING_FILE, 'wb') as f:
            f.write(data)
        t(f"Saved PairingData to {PAIRING_FILE}")
        return True
    except OSError as e:
        t(f"WARN: could not save {PAIRING_FILE}: {e}")
        return False

def load_pairing_data_from_file():
    """Load TLV data from local file, returns TLV dict or None."""
    try:
        data = open(PAIRING_FILE, 'rb').read()
    except OSError:
        return None
    return parse_pairing_tlv(data)

def load_pairing_blob_from_registry(reg_path=None):
    path = reg_path or os.environ.get("PAIRING_REG") or os.path.expanduser("~/winelatestprefix/user.reg")
    try:
        lines = open(path, "r", encoding="utf-8", errors="ignore").read().splitlines()
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
    vals = [v for v in csv.split(",") if v and re.fullmatch(r"[0-9a-fA-F]{2}", v)]
    return bytes(int(v, 16) for v in vals)

def _parse_wine_pairing_wrapper(pairing_blob):
    if not pairing_blob or len(pairing_blob) < 16:
        return None
    ver, zero, len1, len2 = struct.unpack_from("<IIII", pairing_blob, 0)
    if ver != 1:
        return None
    total = 16 + len1 + len2
    if total > len(pairing_blob):
        return None
    return {
        "blob1": pairing_blob[16:16 + len1],
        "blob2": pairing_blob[16 + len1:16 + len1 + len2],
    }

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
    pad1 = bytes((0x36 ^ (base[i] if i < len(base) else 0)) for i in range(64))
    pad2 = bytes((0x5C ^ (base[i] if i < len(base) else 0)) for i in range(64))
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

def decrypt_pairing_data(pairing_blob):
    wrapped = _parse_wine_pairing_wrapper(pairing_blob)
    if not wrapped:
        return None
    user = os.environ.get("DPAPI_USER", os.environ.get("USER", "ubuntu"))
    username_bytes = user.encode("ascii", errors="ignore") + b"\x00"
    return _wine_unprotect_blob(wrapped["blob1"], username_bytes)

def parse_pairing_tlv(plain):
    off = 0
    results = {}
    while off + 6 <= len(plain):
        tag = struct.unpack_from("<H", plain, off)[0]
        length = struct.unpack_from("<I", plain, off + 2)[0]
        val = plain[off + 6:off + 6 + length]
        results[tag] = val
        off += 6 + length
        if off >= len(plain):
            break
    return results

def get_cert_pairingdata():
    """Returns (host_142, eck2_le, full_cert_body, host_x, host_y, eck2_pub_le)
    from PairingData. Tries local file first, then Wine registry."""
    tlvs = load_pairing_data_from_file()
    if tlvs is None:
        blob = load_pairing_blob_from_registry()
        if blob:
            plain = decrypt_pairing_data(blob)
            if plain:
                tlvs = parse_pairing_tlv(plain)
                if tlvs:
                    save_pairing_data_tlv(tlvs)
    if tlvs is None:
        return None
    cert_data = tlvs.get(1)
    if not cert_data or len(cert_data) < 142:
        return None
    if cert_data[:4] != b'\x3f\x5f\x17\x00':
        return None
    host_142 = cert_data[:142]
    eck2_le = tlvs.get(2, b'\x00' * 32)
    # Extract ECS2 public key from cert body at offset 146 (HOST_142[142] + header[4])
    eck2_pub_le = cert_data[146:178] if len(cert_data) >= 178 else b'\x00' * 32
    # Extract device ECDH static key from Tag 3 (host cert)
    host_cert = tlvs.get(3)
    host_x_be = DEV_X_BE; host_y_be = DEV_Y_BE
    if host_cert and len(host_cert) >= 142 and host_cert[:4] == b'\x3f\x5f\x17\x00':
        x_le = host_cert[4:36]
        off = 36
        while off < 142 and host_cert[off] == 0:
            off += 1
        if off < 142:
            y_le = host_cert[off:off+32]
            host_x_be = x_le[::-1]
            host_y_be = y_le[::-1]
            t(f"Host ECDH key from Tag3: X={host_x_be.hex()} Y={host_y_be.hex()}")
    return (host_142, eck2_le, cert_data, host_x_be, host_y_be, eck2_pub_le)


class Sensor:
    def __init__(self):
        self.dev = None
        self.cli_rand = None; self.srv_rand = None
        self.hs_hash_ctx = None
        self.eck2_d = None; self.eck2_x = None; self.eck2_y = None
        self.master = None; self.cli_key = None; self.srv_key = None
        self.cli_iv = None; self.srv_iv = None
        self.seq_out = 0; self.seq_in = 0
        self._dry = DRY
        self.init4_data = None
        self.dev_x = None; self.dev_y = None
        self._pairing_host142 = None
        self._pairing_eck2_le = None
        self._pairing_eck2_be = None
        self._pairing_eck2_pub_le = None  # ECS2 public key X coord (LE) for cert
        self._pairing_cert_data = None
        self._dev_ecdh_x = DEV_X_BE
        self._dev_ecdh_y = DEV_Y_BE

    def find_device(self):
        if self._dry:
            t("[DRY] Device lookup skipped")
            return
        vid, pid = [int(x,16) for x in USB_ID.split(':')]
        self.dev = usb.core.find(idVendor=vid, idProduct=pid)
        if self.dev is None: raise RuntimeError(f"Device {USB_ID} not found")
        try: self.dev.set_configuration()
        except usb.core.USBError: pass

    def ctrl_out(self, req, value=0, data=b'', req_label=""):
        pkt = fmt_setup(BM_OUT, req, value, 0, len(data))
        t(f">>> {req_label or ''} {pkt} data={data[:80].hex()}")
        if self._dry: return
    USB_TIMEOUT = 10000  # 10 seconds
    def ctrl_out(self, req, value=0, data=b'', req_label=""):
        pkt = fmt_setup(BM_OUT, req, value, 0, len(data))
        t(f">>> {req_label or ''} {pkt} data={data[:80].hex()}")
        if self._dry: return
        try:
            return self.dev.ctrl_transfer(BM_OUT, req, value, 0, data, timeout=self.USB_TIMEOUT)
        except Exception as e:
            t(f"  TIMEOUT/ERROR: {e}")
            self._recover()
            raise

    def ctrl_in(self, req, length, value=0, req_label=""):
        pkt = fmt_setup(BM_IN, req, value, 0, length)
        t(f"<<< {req_label or ''} {pkt}")
        if self._dry:
            # Return minimal valid SH for TLS testing
            if 'TLS_IN(CH)' in req_label:
                random = b'\x03' * 32
                sid = b'\x07' + b'\x00' * 7
                cipher = b'\xc0\x2e'
                sh_body = b'\x03\x03' + random + sid + cipher + b'\x00'
                sh_hs = b'\x02' + struct.pack('>I', len(sh_body))[1:4] + sh_body
                certreq = b'\x0d\x00\x00\x04\x01\x40\x00\x00'
                shelldone = b'\x0e\x00\x00\x00'
                rec = bytes([TLS_HS, 0x03, 0x03]) + struct.pack('>H', len(sh_hs)+len(certreq)+len(shelldone))
                return rec + sh_hs + certreq + shelldone
            return b'\x00' * length
        try:
            resp = bytes(self.dev.ctrl_transfer(BM_IN, req, value, 0, length, timeout=self.USB_TIMEOUT))
            t(f"  resp ({len(resp)}B): {resp[:80].hex()}")
            return resp
        except Exception as e:
            t(f"  TIMEOUT/ERROR: {e}")
            self._recover()
            raise

    def _recover(self):
        if self.dev is None: return
        t("Attempting device reset...")
        try:
            self.dev.reset()
            t("  reset OK")
        except:
            t("  reset failed - may need unplug/replug")

    def start(self, round_n=0):
        self.ctrl_out(REQ_START, 1, req_label=f"REQ_START(r{round_n})")
        ack = self.ctrl_in(REQ_ACK, 1, req_label=f"REQ_ACK(r{round_n})")
        if not self._dry:
            assert ack == b'\x01', f"ACK={ack.hex()}"

    def cmd(self, value, data, resp_len, resp_value=0, label=""):
        self.ctrl_out(REQ_CMD, value, data, req_label=f"CMD({label})")
        return self.ctrl_in(REQ_RESP, resp_len, resp_value, req_label=f"RESP({label})")

    def init_round(self, n):
        self.start(n)
        self.cmd(1, INIT_CMD1, 38, 0, label="init1")
        self.cmd(1, INIT_CMD2, 4096, 0x8000, label="init2")
        self.cmd(1, INIT_CMD3, 4096, 0x8000, label="init3")
        r4 = self.cmd(1, INIT_CMD4, 68, 0, label="init4")
        if n == 0:
            self.init4_data = r4[8:]  # save device key data (skip 8B header)

    def tls_send(self, value, data, resp_len, trailing=b'', label=""):
        if DET and label == "CH" and resp_len == 256:
            fake = bytes.fromhex(
                '160303003d0200002d03830098f45ee385c13684a2912170ecdc1b6'
                '76c2e152a75f838f02a990f0149ea4107544c53e385c136c02e00'
                '0d000004014000000e000000')
            return fake
        payload = b'\x44\x00\x00\x00' + data + trailing
        self.ctrl_out(REQ_CMD, value, payload, req_label=f"TLS_OUT({label})")
        return self.ctrl_in(REQ_RESP, resp_len, 0, req_label=f"TLS_IN({label})")

    def hs_update(self, data):
        if self.hs_hash_ctx is None:
            self.hs_hash_ctx = hashlib.sha256()
        self.hs_hash_ctx.update(data)

    def hs_digest(self):
        return self.hs_hash_ctx.digest()

    def run(self):
        t("=== Device Init ===")
        self.find_device()
        for i in range(3):
            self.init_round(i)
            t(f"Init round {i} done")

        self.derive_dev_key()

        # Try to load device key from PairingData (local file or Wine registry)
        pair = get_cert_pairingdata()
        if pair:
            self._pairing_host142 = pair[0]
            self._pairing_eck2_le = pair[1]
            self._pairing_eck2_be = pair[1][::-1]
            self._pairing_cert_data = pair[2]
            self._dev_ecdh_x = pair[3]
            self._dev_ecdh_y = pair[4]
            self._pairing_eck2_pub_le = pair[5]  # public key X coord LE from cert
            t(f"HOST_142 from PairingData: {pair[0][:60].hex()}...")
            t(f"ECS2 LE from PairingData: {pair[1][:32].hex()}...")
        else:
            t("No PairingData found, generating fresh keys...")
            self._generate_ecs2_key()
            # Build HOST_142 from device key (init4 or hardcoded)
            self._pairing_host142 = self.build_host142()
            t(f"Fresh HOST_142: {self._pairing_host142[:60].hex()}...")

        ready = self.ctrl_in(REQ_READY, 2, req_label="REQ_READY")
        t(f"REQ_READY = {ready.hex()}")

        t("\n=== TLS Handshake ===")
        self.cli_rand = det_rand(32)
        self.hs_hash_ctx = hashlib.sha256()
        self.seq_out = 0; self.seq_in = 0

        # 1. ClientHello
        ch = self.build_ch()
        hexdump("CH record", ch)
        self.hs_update(ch[5:])
        resp = self.tls_send(4, ch, 256, b'\x00'*4, label="CH")
        if not self._dry and resp[0] == 0x15:
            t(f"TLS ALERT: {resp.hex()}"); return
        self.seq_out += 1

        # 2. Parse ServerHello + CertReq + SHellDone
        sh_total = self.parse_sh(resp)
        self.hs_update(resp[5:sh_total])
        more = resp[sh_total:]
        hexdump("CertReq+SHellDone", more)
        self.hs_update(more)

        # Derive ECDH + keys
        t("\n--- Key Derivation ---")
        eck2_d = det_rand(32)
        self.eck2_d = eck2_d
        pub = ecdh_pubkey(eck2_d)
        self.eck2_x = pub[:32]; self.eck2_y = pub[32:]
        shared_x = ecdh_shared(eck2_d, self._dev_ecdh_x, self._dev_ecdh_y)
        hexdump("ECDH shared X", shared_x)
        self.master = prf_sha384(shared_x, b"master secret",
                                 self.cli_rand + self.srv_rand, 48)
        hexdump("Master secret", self.master)
        km = prf_sha384(self.master, b"key expansion",
                        self.cli_rand + self.srv_rand, 72)
        self.cli_key = km[0:32]; self.srv_key = km[32:64]
        self.cli_iv = km[64:68]; self.srv_iv = km[68:72]
        hexdump("CLI key", self.cli_key)

        # 4. Build Certificate + CKE + CertVerify (all in one TLS record)
        t("\n--- Building Bundle ---")
        cert_hs = self.build_cert()
        cke_hs = self.build_cke()
        cv_hs = self.build_cert_verify()
        all_hs = cert_hs + cke_hs + cv_hs
        hs_rec = bytes([TLS_HS, 0x03, 0x03]) + struct.pack('>H', len(all_hs)) + all_hs
        hexdump("Combined HS record", hs_rec)

        bundle = hs_rec
        ccs = bytes([TLS_CCS, 0x03, 0x03, 0x00, 0x01, 0x01])
        bundle += ccs

        # After CCS, encrypted epoch begins with seq=0
        self.seq_out = 0
        fin_rec = self.build_finished()
        hexdump("Finished encrypted", fin_rec)
        bundle += fin_rec
        self.seq_out = 1  # Next encrypted record

        t(f"\nBundle total size: {4 + len(bundle)}B (with IOCTL hdr)")

        # 5. Send bundle
        t("\n--- Sending Bundle ---")
        resp = self.tls_send(0, bundle, 256, label="BUNDLE") if not self._dry else None
        if not self._dry:
            hexdump("Bundle response", resp)
            if resp[0] == 0x15:
                t(f"TLS ALERT: {resp.hex()}"); return
            if resp[0] == 0x14:
                t("Server CCS received")
                self.seq_in = 0
                fin_enc = resp[6:]
                fin_dec = self.decrypt_server(fin_enc[5:])
                if fin_dec:
                    hexdump("Server Finished", fin_dec)
                    # Save PairingData if we generated fresh keys
                    if self._pairing_eck2_be is not None and \
                       self._pairing_host142 is not None and \
                       not os.path.exists(PAIRING_FILE):
                        self._save_pairing_data()
        else:
            t("[DRY] Bundle NOT sent to device")

        # 6. App commands
        if not self._dry and resp and resp[0] == 0x14:
            t("\n=== App Commands ===")
            self.app_get_record_count()
            self.app_storage_query_init(1)
            self.app_storage_query_init(2)
            guids = self.app_storage_query_all()
            if len(guids) > 0:
                t(f"Total storage slots: {len(guids)}")
                enrolled = []
                for g in guids:
                    rec = self.app_fetch_record(g)
                    if rec and rec != b'\x00\x00\x00\x00':
                        t(f"  Enrolled: {g.hex()}: {rec.hex()}")
                        enrolled.append((g, rec))
                if not enrolled:
                    t("  (no enrolled templates)")

        if self._dry:
            t("[DRY] App commands not executed")

    def parse_sh(self, data):
        hs_len = struct.unpack('>I', b'\x00' + data[6:9])[0]
        body = data[9:9+hs_len]
        self.srv_rand = body[2:34]
        sid_len = body[34]
        off = 35 + sid_len
        cipher = body[off:off+2]
        t(f"SH: ver={body[0:2].hex()} sid_len={sid_len} cipher={cipher.hex()}")
        return 9 + hs_len

    def build_ch(self):
        sess_id = b'\x07' + b'\x00'*7
        suites = b'\xc0\x05\xc0\x2e\x00\x3d\x00\x8d\x00\xa8\x00\xa9'
        ext = b'\x00\x04\x00\x02\x00\x17\x00\x0b\x00\x02'
        ext_total = struct.pack('>H', len(ext))
        ext2_data = b'\x01\x00'
        hs_body = b'\x03\x03' + self.cli_rand + sess_id
        hs_body += struct.pack('>H', len(suites)) + suites
        hs_body += b'\x00' + ext_total + ext + ext2_data
        hs = bytes([0x01]) + struct.pack('>I', len(hs_body))[1:4] + hs_body
        return bytes([TLS_HS]) + b'\x03\x03' + struct.pack('>H', len(hs)) + hs

    def derive_dev_key(self):
        if self.init4_data is None or len(self.init4_data) < 32:
            t("ERROR: no init4 data, using hardcoded key")
            return
        x_le = self.init4_data[:32]
        x_be = x_le[::-1]
        x_int = int.from_bytes(x_be, 'big')

        p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
        a = p - 3
        b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
        y_sq = (pow(x_int, 3, p) + a * x_int + b) % p
        y_int = pow(y_sq, (p + 1) // 4, p)
        if pow(y_int, 2, p) != y_sq:
            t("ERROR: X is not a valid P-256 point")
            return
        y_be = y_int.to_bytes(32, 'big')
        y_le = y_be[::-1]
        self.dev_x = (x_le, x_be)
        self.dev_y = (y_le, y_be)
        t(f"DEV key from init4: X={x_be.hex()} Y={y_be.hex()}")

    def build_host142(self):
        if self._pairing_host142 is not None:
            return self._pairing_host142
        if self.dev_x is not None:
            x_le = self.dev_x[0]; y_le = self.dev_y[0]
            return b'\x3f\x5f\x17\x00' + x_le + b'\x00' * 20 + y_le + b'\x00' * 54
        return HOST_142

    def _generate_ecs2_key(self):
        """Generate fresh ECS2 key pair when no PairingData exists."""
        d_be = det_rand(32)
        self._pairing_eck2_be = d_be
        self._pairing_eck2_le = d_be[::-1]
        pub = ecdh_pubkey(d_be)
        pub_x_be = pub[:32]
        self._pairing_eck2_pub_le = pub_x_be[::-1]
        self._pairing_cert_data = None
        t(f"Fresh ECS2 key: D={d_be.hex()} pub_x={pub_x_be.hex()}")

    def _save_pairing_data(self):
        """Save current session keys to local pairing.dat."""
        if self._pairing_eck2_le is None:
            return
        host_x_be = self._dev_ecdh_x
        host_y_be = self._dev_ecdh_y
        x_le = host_x_be[::-1]
        y_le = host_y_be[::-1]
        host_cert = b'\x3f\x5f\x17\x00' + x_le + b'\x00' * 20 + y_le + b'\x00' * 54
        # Build full 400-byte cert body with correct ECS2 pub key
        eck2_pub = self._pairing_eck2_pub_le or b'\x00' * 32
        cert_body = self._pairing_host142 + struct.pack('>HB', 2, 32) + b'\x00' + eck2_pub + b'\x00' * 220
        tlvs = {
            1: cert_body,
            2: self._pairing_eck2_le,
            3: host_cert,
        }
        save_pairing_data_tlv(tlvs)

    def build_cert(self):
        run_marker = self.cli_rand[4:6]
        if self._pairing_cert_data is not None:
            cert_data = run_marker + self._pairing_cert_data[:398]
            assert len(cert_data) == 400, f"pair cert_data={len(cert_data)}"
        else:
            host_142 = self.build_host142()
            eck2_pub = self._pairing_eck2_pub_le or b'\x00' * 32
            cert_data = run_marker + host_142 + struct.pack('>HB', 2, 32) + b'\x00' + eck2_pub + b'\x00' * 220
            assert len(cert_data) == 400, f"cert_data={len(cert_data)}"

        list_len = struct.pack('>I', 400)[1:4]
        body = list_len + list_len + cert_data + b'\x00\x00'
        assert len(body) == 408, f"cert body={len(body)}"

        hs = bytes([0x0b]) + struct.pack('>I', len(body))[1:4] + body
        self.hs_update(hs)
        hexdump("Cert HS", hs)
        return hs

    def build_cke(self):
        body = b'\x04' + self.eck2_x + self.eck2_y
        hs = bytes([0x10]) + struct.pack('>I', len(body))[1:4] + body
        self.hs_update(hs)
        return hs

    def build_cert_verify(self):
        h = self.hs_digest()
        hexdump("HS hash for CertVerify", h)
        sig = ecdsa_sign(self._pairing_eck2_be, h)
        hs = bytes([0x0f]) + struct.pack('>I', len(sig))[1:4] + sig
        self.hs_update(hs)
        return hs

    def build_finished(self):
        hs_hash = self.hs_digest()
        verify = prf_sha384(self.master, b"client finished", hs_hash, 12)
        hexdump("Finished plain verify_data", verify)
        fin_hs = bytes([0x14]) + struct.pack('>I', len(verify))[1:4] + verify
        self.hs_update(fin_hs)

        nonce = self.cli_iv + det_rand(8)
        seq = struct.pack('>Q', self.seq_out)
        plain_len = len(fin_hs)
        aad = seq + bytes([TLS_HS, 0x03, 0x03]) + struct.pack('>H', plain_len)
        ct = aes_gcm_encrypt(self.cli_key, nonce, fin_hs, aad)
        body = nonce[4:12] + ct
        rec = bytes([TLS_HS, 0x03, 0x03]) + struct.pack('>H', len(body)) + body
        return rec

    def decrypt_server(self, data):
        nonce = self.srv_iv + data[0:8]
        ct = data[8:]
        seq = struct.pack('>Q', self.seq_in); self.seq_in += 1
        aad = seq + bytes([TLS_HS, 0x03, 0x03]) + struct.pack('>H', len(ct) - 16)
        try:
            return aes_gcm_decrypt(self.srv_key, nonce, ct, aad)
        except Exception as e:
            t(f"  Decrypt failed: {e}")
            return None

    # ── App commands (encrypted) ──────────────────────────────────────────

    def pad8(self, data):
        rem = len(data) % 8
        return data if rem == 0 else data + b'\x00' * (8 - rem)

    def app_encrypt(self, plain):
        nonce = self.cli_iv + det_rand(8)
        seq = struct.pack('>Q', self.seq_out); self.seq_out += 1
        aad = seq + bytes([TLS_APP, 0x03, 0x03]) + struct.pack('>H', len(plain))
        ct = aes_gcm_encrypt(self.cli_key, nonce, plain, aad)
        body = nonce[4:12] + ct
        rec = bytes([TLS_APP, 0x03, 0x03]) + struct.pack('>H', len(body)) + body
        return self.pad8(rec)

    def app_decrypt(self, data):
        if len(data) < 5:
            return None
        rec_len = struct.unpack('>H', data[3:5])[0]
        body = data[5:5+rec_len]
        nonce = self.srv_iv + body[0:8]
        ct = body[8:]
        seq = struct.pack('>Q', self.seq_in); self.seq_in += 1
        aad = seq + bytes([TLS_APP, 0x03, 0x03]) + struct.pack('>H', len(ct) - 16)
        try:
            return aes_gcm_decrypt(self.srv_key, nonce, ct, aad)
        except Exception as e:
            t(f"  App decrypt failed: {e}")
            return None

    def decrypt_alert(self, data):
        if len(data) < 5:
            return None, None
        rec_len = struct.unpack('>H', data[3:5])[0]
        body = data[5:5+rec_len]
        nonce = self.srv_iv + body[0:8]
        ct = body[8:]
        seq = struct.pack('>Q', self.seq_in); self.seq_in += 1
        aad = seq + bytes([0x15, 0x03, 0x03]) + struct.pack('>H', 2)
        try:
            pt = aes_gcm_decrypt(self.srv_key, nonce, ct, aad)
            return pt[0], pt[1]
        except Exception as e:
            t(f"  Alert decrypt failed: {e}")
            return None, None

    def app_send(self, value, plain, resp_len=256, label=""):
        out = self.app_encrypt(plain)
        t(f"  APP({label}): plain={plain.hex()}")
        self.ctrl_out(REQ_CMD, value, out, req_label=f"APP_OUT({label})")
        resp = self.ctrl_in(REQ_RESP, resp_len, 0, req_label=f"APP_IN({label})")
        if not resp:
            t("  No response")
            return None
        if resp[0] == TLS_APP:
            pt = self.app_decrypt(resp)
            if pt is not None:
                t(f"  APP({label}) resp: {pt.hex()}")
            return pt
        if resp[0] == 0x15:
            level, desc = self.decrypt_alert(resp)
            t(f"  TLS ALERT: level={level} desc={desc}")
            ALERTS = {0x15: "decode_error", 0x21: "decrypt_error",
                      0x28: "handshake_failure", 0x2a: "bad_record_mac",
                      0x2f: "illegal_parameter", 0x46: "protocol_version",
                      0x47: "insufficient_security", 0x50: "bad_certificate"}
            t(f"  Alert meaning: {ALERTS.get(desc, 'unknown')}")
            return None
        t(f"  Unexpected response type: {resp[0]:02x}")
        return None

    def app_get_record_count(self):
        plain = b'\x82' + b'\x00' * 6 + b'\x02\x07'
        t("--- GET_RECORD_COUNT ---")
        data = self.app_send(6, plain, 128, label="GET_RECORD_COUNT")
        if data:
            hexdump("Record count plain", data)
        return data

    def app_storage_query_init(self, seq_n):
        t(f"--- STORAGE_QUERY_INIT ({seq_n}) ---")
        data = self.app_send(7, b'\x9e\x01', 128, label=f"QUERY_INIT_{seq_n}")
        hexdump(f"Query init {seq_n} response", data or b'')
        return data

    def app_storage_query_all(self):
        t("--- STORAGE_QUERY_ALL ---")
        plain = b'\x9f\x02\x00\x00\x00' + b'\xff' * 16
        data = self.app_send(2, plain, 256, label="QUERY_ALL")
        if data and len(data) >= 4:
            count = struct.unpack('<H', data[2:4])[0]
            guids = []
            off = 4
            while off + 16 <= len(data):
                guids.append(data[off:off+16])
                off += 16
            t(f"Storage says {len(guids)} slots ({count} claimed)")
            return guids
        hexdump("Raw query all response", data or b'')
        return []

    def app_fetch_record(self, guid):
        plain = b'\x9f\x03\x00\x00\x00' + guid
        data = self.app_send(2, plain, 256, label=f"FETCH_{guid[:8].hex()}")
        return data


# --- Crypto ---
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def bi(b): return int.from_bytes(b, 'big')
def tb(n, l): return n.to_bytes(l, 'big')

def ecdh_pubkey(priv_be):
    priv = ec.derive_private_key(bi(priv_be), ec.SECP256R1(), default_backend())
    n = priv.public_key().public_numbers()
    return tb(n.x, 32) + tb(n.y, 32)

def ecdh_shared(priv_be, px, py):
    priv = ec.derive_private_key(bi(priv_be), ec.SECP256R1(), default_backend())
    peer = ec.EllipticCurvePublicNumbers(bi(px), bi(py), ec.SECP256R1()).public_key(default_backend())
    return priv.exchange(ec.ECDH(), peer)

def ecdsa_sign(priv_be, msg):
    priv = ec.derive_private_key(bi(priv_be), ec.SECP256R1(), default_backend())
    return priv.sign(msg, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

def prf_sha384(secret, label, seed, length):
    def p_hash(s, seed, length):
        r = b''
        a = seed
        while len(r) < length:
            a = hmac.new(s, a, hashlib.sha384).digest()
            r += hmac.new(s, a + seed, hashlib.sha384).digest()
        return r[:length]
    return p_hash(secret, label + seed, length)

def aes_gcm_encrypt(k, nonce, pt, aad):
    return AESGCM(k).encrypt(nonce, pt, aad)

def aes_gcm_decrypt(k, nonce, ct, aad):
    return AESGCM(k).decrypt(nonce, ct, aad)


if __name__ == '__main__':
    s = Sensor()
    try:
        s.run()
    except Exception as e:
        t(f"FATAL: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)
