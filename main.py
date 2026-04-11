from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import numpy as np

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class TextRequest(BaseModel):
    text: str
    shift: int = 3
    method: str = "caesar"
    key: str = ""


# ──────────────────────────────────────────
# REQUEST MODEL FOR BLOCK CIPHER MODES
# ──────────────────────────────────────────

class BlockModeRequest(BaseModel):
    text: str               # plaintext (ASCII)
    key: str = "KEYKEY"    # symmetric key string
    iv: str = "INITVECT"   # IV / nonce (8 chars recommended)
    mode: str = "cbc"       # ecb | cbc | cfb | ofb | ctr
    block_size: int = 8     # block size in characters (bytes)


# ──────────────────────────────────────────
# BLOCK CIPHER HELPER — XOR-based pseudo-AES
# ──────────────────────────────────────────
# NOTE: This is an *educational* simulation. Real-world usage must use
# a proper library such as PyCryptodome (AES) or Python's `cryptography`
# package. The "encryption" here is a repeating-XOR block cipher that
# mimics the structural behaviour of each mode without actual AES internals.

def _pad(text: str, block_size: int) -> str:
    """PKCS#7-style padding to align to block_size."""
    pad_len = block_size - (len(text) % block_size)
    return text + chr(pad_len) * pad_len


def _unpad(text: str) -> str:
    """Remove PKCS#7 padding."""
    if not text:
        return text
    pad_len = ord(text[-1])
    return text[:-pad_len]


def _bytes(s: str) -> list[int]:
    return [ord(c) for c in s]


def _str(b: list[int]) -> str:
    return "".join(chr(x & 0xFF) for x in b)


def _xor_blocks(a: list[int], b: list[int]) -> list[int]:
    return [x ^ y for x, y in zip(a, b)]


def _pseudo_encrypt_block(block: list[int], key: list[int]) -> list[int]:
    """
    Simulate a block cipher E(key, block).
    Uses two rounds of XOR + rotate — structurally sufficient for
    demonstrating mode behaviour; NOT cryptographically secure.
    """
    n = len(block)
    key_padded = [key[i % len(key)] for i in range(n)]
    # Round 1: XOR with key
    r1 = _xor_blocks(block, key_padded)
    # Round 2: byte-rotate left by 1 then XOR with reversed key
    r2 = r1[1:] + r1[:1]
    rev_key = key_padded[::-1]
    r3 = _xor_blocks(r2, rev_key)
    return r3


def _split_blocks(data: list[int], block_size: int) -> list[list[int]]:
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]


def _hex(b: list[int]) -> str:
    return " ".join(f"{x:02x}" for x in b)


# ──────────────────────────────────────────
# ECB — Electronic Codebook
# ──────────────────────────────────────────

def ecb_encrypt(text: str, key: str, block_size: int):
    """
    Each block is encrypted independently with the same key.
    Identical plaintext blocks → identical ciphertext blocks (the ECB weakness).
    """
    padded = _pad(text, block_size)
    key_b  = _bytes(key)
    blocks = _split_blocks(_bytes(padded), block_size)

    steps, cipher_blocks = [], []
    for i, blk in enumerate(blocks):
        enc = _pseudo_encrypt_block(blk, key_b)
        cipher_blocks.append(enc)
        steps.append({
            "block": i + 1,
            "plaintext_block": _str(blk),
            "plaintext_hex": _hex(blk),
            "ciphertext_hex": _hex(enc),
            "note": "Encrypted independently — no IV, no chaining"
        })

    result_bytes = [b for blk in cipher_blocks for b in blk]
    return steps, _hex(result_bytes), result_bytes


# ──────────────────────────────────────────
# CBC — Cipher Block Chaining
# ──────────────────────────────────────────

def cbc_encrypt(text: str, key: str, iv: str, block_size: int):
    """
    Each block XORed with previous ciphertext block before encryption.
    First block uses IV. Requires sequential encryption; parallel decryption OK.
    """
    padded = _pad(text, block_size)
    key_b  = _bytes(key)
    iv_b   = _bytes(iv[:block_size].ljust(block_size, '\x00'))
    blocks = _split_blocks(_bytes(padded), block_size)

    steps, cipher_blocks = [], []
    prev = iv_b

    for i, blk in enumerate(blocks):
        xored = _xor_blocks(blk, prev)          # XOR with previous C (or IV)
        enc   = _pseudo_encrypt_block(xored, key_b)
        cipher_blocks.append(enc)
        steps.append({
            "block": i + 1,
            "plaintext_block": _str(blk),
            "plaintext_hex": _hex(blk),
            "xor_with": "IV" if i == 0 else f"C{i}",
            "after_xor_hex": _hex(xored),
            "ciphertext_hex": _hex(enc),
            "note": f"P{i+1} ⊕ {'IV' if i == 0 else f'C{i}'} → E(key) → C{i+1}"
        })
        prev = enc

    result_bytes = [b for blk in cipher_blocks for b in blk]
    return steps, _hex(result_bytes), result_bytes


# ──────────────────────────────────────────
# CFB — Cipher Feedback
# ──────────────────────────────────────────

def cfb_encrypt(text: str, key: str, iv: str, block_size: int):
    """
    Previous ciphertext block is *encrypted*, then XORed with plaintext.
    Self-synchronising stream cipher. Encrypt sequential; decrypt parallel.
    """
    padded = _pad(text, block_size)
    key_b  = _bytes(key)
    iv_b   = _bytes(iv[:block_size].ljust(block_size, '\x00'))
    blocks = _split_blocks(_bytes(padded), block_size)

    steps, cipher_blocks = [], []
    shift_reg = iv_b          # initialised with IV

    for i, blk in enumerate(blocks):
        enc_reg = _pseudo_encrypt_block(shift_reg, key_b)   # E(shift_register)
        ci      = _xor_blocks(blk, enc_reg)                 # P ⊕ E(prev_C)
        cipher_blocks.append(ci)
        steps.append({
            "block": i + 1,
            "plaintext_block": _str(blk),
            "plaintext_hex": _hex(blk),
            "encrypted_register_hex": _hex(enc_reg),
            "ciphertext_hex": _hex(ci),
            "note": f"E({'IV' if i == 0 else f'C{i}'}) ⊕ P{i+1} → C{i+1}"
        })
        shift_reg = ci         # feedback: ciphertext becomes next register

    result_bytes = [b for blk in cipher_blocks for b in blk]
    return steps, _hex(result_bytes), result_bytes


# ──────────────────────────────────────────
# OFB — Output Feedback
# ──────────────────────────────────────────

def ofb_encrypt(text: str, key: str, iv: str, block_size: int):
    """
    Keystream generated by chaining E(E(...(IV))) — independent of plaintext.
    XOR keystream with plaintext. No error propagation. Pre-computable keystream.
    Reusing IV with same key is catastrophic.
    """
    padded = _pad(text, block_size)
    key_b  = _bytes(key)
    iv_b   = _bytes(iv[:block_size].ljust(block_size, '\x00'))
    blocks = _split_blocks(_bytes(padded), block_size)

    steps, cipher_blocks = [], []
    output_block = iv_b      # initialised with IV

    for i, blk in enumerate(blocks):
        output_block = _pseudo_encrypt_block(output_block, key_b)  # keystream block
        ci = _xor_blocks(blk, output_block)                         # P ⊕ keystream
        cipher_blocks.append(ci)
        steps.append({
            "block": i + 1,
            "plaintext_block": _str(blk),
            "plaintext_hex": _hex(blk),
            "keystream_hex": _hex(output_block),
            "ciphertext_hex": _hex(ci),
            "note": f"Keystream O{i+1} = E(O{i}) — independent of plaintext"
        })

    result_bytes = [b for blk in cipher_blocks for b in blk]
    return steps, _hex(result_bytes), result_bytes


# ──────────────────────────────────────────
# CTR — Counter Mode
# ──────────────────────────────────────────

def ctr_encrypt(text: str, key: str, nonce: str, block_size: int):
    """
    Nonce concatenated with an incrementing counter is encrypted per block.
    Fully parallelisable (encrypt + decrypt). Supports random-access decryption.
    No padding required (stream-like). Counter must never repeat for same key.
    """
    key_b   = _bytes(key)
    nonce_b = _bytes(nonce[:block_size // 2].ljust(block_size // 2, '\x00'))
    data_b  = _bytes(text)   # no padding needed in CTR

    steps, cipher_bytes = [], []

    for i in range(0, len(data_b), block_size):
        chunk     = data_b[i:i + block_size]
        counter   = i // block_size
        # Build counter block: nonce || counter (as bytes)
        ctr_bytes = list(nonce_b) + list(counter.to_bytes(block_size - len(nonce_b), 'big'))
        ctr_bytes = ctr_bytes[:block_size]
        keystream = _pseudo_encrypt_block(ctr_bytes, key_b)[:len(chunk)]
        ci        = _xor_blocks(chunk, keystream)
        cipher_bytes.extend(ci)
        steps.append({
            "block": counter + 1,
            "counter_value": counter,
            "counter_block_hex": _hex(ctr_bytes),
            "plaintext_hex": _hex(chunk),
            "keystream_hex": _hex(keystream),
            "ciphertext_hex": _hex(ci),
            "note": f"E(Nonce‖{counter}) ⊕ P{counter+1} — fully parallelisable"
        })

    return steps, _hex(cipher_bytes), cipher_bytes


# ──────────────────────────────────────────
# BLOCK MODE ENDPOINT
# ──────────────────────────────────────────

@app.post("/block_encrypt")
def block_encrypt(req: BlockModeRequest):
    """
    Encrypt using a block cipher mode of operation.

    modes: ecb | cbc | cfb | ofb | ctr

    Returns per-block step-by-step details alongside the final ciphertext hex.
    """
    mode       = req.mode.lower()
    text       = req.text
    key        = req.key or "KEYKEY"
    iv         = req.iv or "INITVECT"
    block_size = max(4, min(req.block_size, 32))  # clamp 4–32

    if mode == "ecb":
        steps, hex_out, raw = ecb_encrypt(text, key, block_size)
    elif mode == "cbc":
        steps, hex_out, raw = cbc_encrypt(text, key, iv, block_size)
    elif mode == "cfb":
        steps, hex_out, raw = cfb_encrypt(text, key, iv, block_size)
    elif mode == "ofb":
        steps, hex_out, raw = ofb_encrypt(text, key, iv, block_size)
    elif mode == "ctr":
        steps, hex_out, raw = ctr_encrypt(text, key, iv, block_size)
    else:
        return {"error": f"Unknown block mode '{mode}'. Use: ecb, cbc, cfb, ofb, ctr"}

    return {
        "input":         text,
        "mode":          mode.upper(),
        "key":           key,
        "iv":            iv if mode != "ecb" else None,
        "block_size":    block_size,
        "block_count":   len(steps),
        "steps":         steps,
        "ciphertext_hex": hex_out,
        "note": (
            "Educational XOR-based simulation. "
            "For production use AES via PyCryptodome or the `cryptography` package."
        )
    }


# ──────────────────────────────────────────
# SUBSTITUTION CIPHERS (unchanged)
# ──────────────────────────────────────────

def caesar_cipher(text, shift):
    result = ""
    steps = []
    for char in text:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            shifted = chr((ord(char) - base + shift) % 26 + base)
        else:
            shifted = char
        steps.append({"original": char, "shifted": shifted})
        result += shifted
    return steps, result


def atbash_cipher(text):
    result = ""
    steps = []
    for char in text:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            shifted = chr(base + (25 - (ord(char) - base)))
        else:
            shifted = char
        steps.append({"original": char, "shifted": shifted})
        result += shifted
    return steps, result


def vigenere_cipher(text, key):
    result = ""
    steps = []
    key = key.lower()
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 97
            base = 65 if char.isupper() else 97
            shifted = chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            shifted = char
        steps.append({"original": char, "shifted": shifted})
        result += shifted
    return steps, result


def rot13_cipher(text):
    result = ""
    steps = []
    for char in text:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            shifted = chr((ord(char) - base + 13) % 26 + base)
        else:
            shifted = char
        steps.append({"original": char, "shifted": shifted})
        result += shifted
    return steps, result


def beaufort_cipher(text, key):
    result = ""
    steps = []
    key = key.upper()
    key_index = 0
    for char in text:
        if char.isalpha():
            k = ord(key[key_index % len(key)]) - 65
            p = ord(char.upper()) - 65
            shifted_ord = (k - p) % 26
            shifted = chr(shifted_ord + 65)
            if char.islower():
                shifted = shifted.lower()
            key_index += 1
        else:
            shifted = char
        steps.append({"original": char, "shifted": shifted})
        result += shifted
    return steps, result


def playfair_cipher(text, key):
    key = key.upper().replace("J", "I")
    seen = []
    for ch in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch.isalpha() and ch not in seen:
            seen.append(ch)
    table = [seen[i*5:(i+1)*5] for i in range(5)]
    pos = {ch: (r, c) for r, row in enumerate(table) for c, ch in enumerate(row)}

    plain = text.upper().replace("J", "I")
    plain = "".join(ch for ch in plain if ch.isalpha())
    i = 0
    digraphs = []
    while i < len(plain):
        a = plain[i]
        b = plain[i+1] if i+1 < len(plain) else "X"
        if a == b:
            digraphs.append((a, "X"))
            i += 1
        else:
            digraphs.append((a, b))
            i += 2

    steps = []
    result = ""
    for a, b in digraphs:
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            ea = table[ra][(ca + 1) % 5]
            eb = table[rb][(cb + 1) % 5]
        elif ca == cb:
            ea = table[(ra + 1) % 5][ca]
            eb = table[(rb + 1) % 5][cb]
        else:
            ea = table[ra][cb]
            eb = table[rb][ca]
        steps.append({"original": a + b, "shifted": ea + eb})
        result += ea + eb

    return steps, result


def hill_cipher(text, key):
    import math

    DEFAULT_KEY = [[3, 3], [2, 5]]

    def parse_matrix(k):
        nums = [int(ch) for ch in k if ch.isdigit()]
        return [[nums[0], nums[1]], [nums[2], nums[3]]] if len(nums) >= 4 else DEFAULT_KEY

    def mod_inverse(a, m):
        return next((x for x in range(1, m) if (a * x) % m == 1), None)

    mat = parse_matrix(key)
    det = (mat[0][0]*mat[1][1] - mat[0][1]*mat[1][0]) % 26
    if mod_inverse(det, 26) is None:
        mat = DEFAULT_KEY

    plain = "".join(ch.upper() for ch in text if ch.isalpha())
    if len(plain) % 2 != 0:
        plain += "X"

    steps = []
    result = ""
    for i in range(0, len(plain), 2):
        p1 = ord(plain[i]) - 65
        p2 = ord(plain[i+1]) - 65
        c1 = (mat[0][0]*p1 + mat[0][1]*p2) % 26
        c2 = (mat[1][0]*p1 + mat[1][1]*p2) % 26
        orig = plain[i] + plain[i+1]
        enc  = chr(c1+65) + chr(c2+65)
        steps.append({
            "original": orig,
            "shifted":  enc,
            "matrix":   f"[[{mat[0][0]},{mat[0][1]}],[{mat[1][0]},{mat[1][1]}]]",
            "vector":   f"[{p1},{p2}] → [{c1},{c2}]"
        })
        result += enc

    return steps, result


# ──────────────────────────────────────────
# TRANSPOSITION CIPHER (unchanged)
# ──────────────────────────────────────────

def rail_fence_cipher(text, rails=3):
    fence = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for char in text:
        fence[rail].append(char)
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    result = "".join("".join(row) for row in fence)
    return [{"original": text, "shifted": result}], result


# ──────────────────────────────────────────
# ASYMMETRIC DEMO RSA (unchanged)
# ──────────────────────────────────────────

def simple_rsa_encrypt(text):
    e, n = 5, 91
    steps, result = [], []
    for char in text:
        cipher = (ord(char) ** e) % n
        result.append(str(cipher))
        steps.append({"original": char, "shifted": str(cipher)})
    return steps, " ".join(result)


# ──────────────────────────────────────────
# SUBSTITUTION / CLASSIC CIPHER ENDPOINT
# ──────────────────────────────────────────

@app.post("/encrypt")
def encrypt(req: TextRequest):
    if req.method == "caesar":
        steps, result = caesar_cipher(req.text, req.shift)
    elif req.method == "atbash":
        steps, result = atbash_cipher(req.text)
    elif req.method == "vigenere":
        steps, result = vigenere_cipher(req.text, req.key or "key")
    elif req.method == "railfence":
        steps, result = rail_fence_cipher(req.text)
    elif req.method == "rsa":
        steps, result = simple_rsa_encrypt(req.text)
    elif req.method == "rot13":
        steps, result = rot13_cipher(req.text)
    elif req.method == "beaufort":
        steps, result = beaufort_cipher(req.text, req.key or "key")
    elif req.method == "playfair":
        steps, result = playfair_cipher(req.text, req.key or "keyword")
    elif req.method == "hill":
        steps, result = hill_cipher(req.text, req.key or "")
    else:
        return {"error": "Invalid method"}

    return {
        "input":  req.text,
        "method": req.method,
        "steps":  steps,
        "output": result
    }


# ──────────────────────────────────────────
# HTML ROUTES (unchanged)
# ──────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def load_main():
    with open("main.html", "r") as f:
        return f.read()

@app.get("/cipher.html", response_class=HTMLResponse)
def load_cipher_html():
    with open("cipher.html") as f:
        return f.read()

@app.get("/MOCB.html", response_class=HTMLResponse)
def load_MOCB_html():
    with open("MOCB.html") as f:
        return f.read()
