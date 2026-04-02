#!/usr/bin/env python3
"""
Encryption Tool - File and text encryption/decryption using AES-256.

Provides secure encryption using AES-256-CBC with PBKDF2 key derivation.
Supports both text and file encryption with password-based keys.

Usage:
    python encryption_tool.py encrypt -t "secret message" -p mypassword
    python encryption_tool.py decrypt -t <encrypted_text> -p mypassword
    python encryption_tool.py encrypt -f secret.txt -p mypassword
    python encryption_tool.py decrypt -f secret.txt.enc -p mypassword

Author: SebMRX
"""

import os
import sys
import json
import hmac
import struct
import hashlib
import base64
import argparse
import getpass
from collections import namedtuple


# AES implementation (pure Python — no external dependencies)
# Based on FIPS 197 specification

# AES S-Box
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16,
]

# Inverse S-Box
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

# Round constants
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF


def gmul(a, b):
    """Galois field multiplication."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def sub_bytes(state):
    return [SBOX[b] for b in state]


def inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]


def shift_rows(state):
    s = list(state)
    # Row 1: shift left by 1
    s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
    # Row 2: shift left by 2
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    # Row 3: shift left by 3
    s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
    return s


def inv_shift_rows(state):
    s = list(state)
    s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]
    return s


def mix_columns(state):
    s = list(state)
    for i in range(4):
        c = i * 4
        a = s[c:c + 4]
        s[c + 0] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3]
        s[c + 1] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3]
        s[c + 2] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3)
        s[c + 3] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2)
    return s


def inv_mix_columns(state):
    s = list(state)
    for i in range(4):
        c = i * 4
        a = s[c:c + 4]
        s[c + 0] = gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9)
        s[c + 1] = gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13)
        s[c + 2] = gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11)
        s[c + 3] = gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14)
    return s


def add_round_key(state, round_key):
    return [s ^ k for s, k in zip(state, round_key)]


def key_expansion(key):
    """Expand 256-bit key into round keys."""
    key_len = len(key)
    nk = key_len // 4  # 8 for AES-256
    nr = 14  # 14 rounds for AES-256
    w = list(key)

    for i in range(nk, 4 * (nr + 1)):
        temp = w[(i - 1) * 4:i * 4]
        if i % nk == 0:
            # RotWord + SubWord + Rcon
            temp = [SBOX[temp[1]], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]]
            temp[0] ^= RCON[(i // nk) - 1]
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        prev = w[(i - nk) * 4:(i - nk + 1) * 4]
        w.extend([p ^ t for p, t in zip(prev, temp)])

    return w


def aes_encrypt_block(plaintext, expanded_key):
    """Encrypt a single 16-byte block with AES-256."""
    nr = 14
    state = list(plaintext)

    # Column-major order
    state = [state[r + 4 * c] for c in range(4) for r in range(4)]
    state = add_round_key(state, expanded_key[0:16])

    for rnd in range(1, nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, expanded_key[rnd * 16:(rnd + 1) * 16])

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, expanded_key[nr * 16:(nr + 1) * 16])

    # Back to row-major
    result = [0] * 16
    for c in range(4):
        for r in range(4):
            result[r + 4 * c] = state[c * 4 + r]
    return bytes(result)


def aes_decrypt_block(ciphertext, expanded_key):
    """Decrypt a single 16-byte block with AES-256."""
    nr = 14
    state = list(ciphertext)

    state = [state[r + 4 * c] for c in range(4) for r in range(4)]
    state = add_round_key(state, expanded_key[nr * 16:(nr + 1) * 16])

    for rnd in range(nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, expanded_key[rnd * 16:(rnd + 1) * 16])
        state = inv_mix_columns(state)

    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, expanded_key[0:16])

    result = [0] * 16
    for c in range(4):
        for r in range(4):
            result[r + 4 * c] = state[c * 4 + r]
    return bytes(result)


def pkcs7_pad(data):
    """Apply PKCS#7 padding to make data a multiple of 16 bytes."""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data):
    """Remove PKCS#7 padding."""
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def pbkdf2_sha256(password, salt, iterations=100000, key_len=32):
    """Derive encryption key from password using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, key_len)


def encrypt_data(plaintext, password):
    """
    Encrypt data with AES-256-CBC using a password.

    Format: salt(16) + iv(16) + hmac(32) + ciphertext
    """
    salt = os.urandom(16)
    iv = os.urandom(16)

    # Derive 64 bytes: 32 for encryption, 32 for HMAC
    key_material = pbkdf2_sha256(password, salt, iterations=100000, key_len=64)
    enc_key = key_material[:32]
    hmac_key = key_material[32:]

    expanded_key = key_expansion(list(enc_key))

    # PKCS#7 padding
    padded = pkcs7_pad(plaintext)

    # CBC mode encryption
    ciphertext = b""
    prev_block = iv
    for i in range(0, len(padded), 16):
        block = padded[i:i + 16]
        xored = bytes(a ^ b for a, b in zip(block, prev_block))
        encrypted = aes_encrypt_block(xored, expanded_key)
        ciphertext += encrypted
        prev_block = encrypted

    # HMAC for integrity verification
    mac = hmac.new(hmac_key, salt + iv + ciphertext, hashlib.sha256).digest()

    return salt + iv + mac + ciphertext


def decrypt_data(encrypted, password):
    """
    Decrypt AES-256-CBC encrypted data.

    Verifies HMAC before decryption.
    """
    if len(encrypted) < 80:  # 16 + 16 + 32 + 16 minimum
        raise ValueError("Invalid encrypted data (too short)")

    salt = encrypted[:16]
    iv = encrypted[16:32]
    stored_mac = encrypted[32:64]
    ciphertext = encrypted[64:]

    # Derive keys
    key_material = pbkdf2_sha256(password, salt, iterations=100000, key_len=64)
    enc_key = key_material[:32]
    hmac_key = key_material[32:]

    # Verify HMAC first (authenticate-then-decrypt)
    computed_mac = hmac.new(hmac_key, salt + iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(stored_mac, computed_mac):
        raise ValueError("Authentication failed — wrong password or corrupted data")

    expanded_key = key_expansion(list(enc_key))

    # CBC mode decryption
    plaintext = b""
    prev_block = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        decrypted = aes_decrypt_block(block, expanded_key)
        plaintext += bytes(a ^ b for a, b in zip(decrypted, prev_block))
        prev_block = block

    return pkcs7_unpad(plaintext)


def encrypt_text(text, password):
    """Encrypt text and return base64-encoded result."""
    encrypted = encrypt_data(text.encode("utf-8"), password)
    return base64.b64encode(encrypted).decode("ascii")


def decrypt_text(encoded, password):
    """Decrypt base64-encoded encrypted text."""
    encrypted = base64.b64decode(encoded)
    return decrypt_data(encrypted, password).decode("utf-8")


def encrypt_file(filepath, password):
    """Encrypt a file. Creates <filename>.enc"""
    with open(filepath, "rb") as f:
        data = f.read()

    encrypted = encrypt_data(data, password)
    out_path = filepath + ".enc"

    with open(out_path, "wb") as f:
        f.write(encrypted)

    return out_path, len(data)


def decrypt_file(filepath, password):
    """Decrypt a .enc file. Removes .enc extension."""
    with open(filepath, "rb") as f:
        encrypted = f.read()

    decrypted = decrypt_data(encrypted, password)

    if filepath.endswith(".enc"):
        out_path = filepath[:-4]
    else:
        out_path = filepath + ".dec"

    with open(out_path, "wb") as f:
        f.write(decrypted)

    return out_path, len(decrypted)


def main():
    parser = argparse.ArgumentParser(
        description="Encryption Tool - AES-256-CBC file and text encryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python encryption_tool.py encrypt -t "Hello, World!" -p mypassword
  python encryption_tool.py decrypt -t <base64_string> -p mypassword
  python encryption_tool.py encrypt -f document.pdf -p mypassword
  python encryption_tool.py decrypt -f document.pdf.enc -p mypassword
        """,
    )
    parser.add_argument("action", choices=["encrypt", "decrypt"], help="Action to perform")
    parser.add_argument("-t", "--text", help="Text to encrypt/decrypt")
    parser.add_argument("-f", "--file", help="File to encrypt/decrypt")
    parser.add_argument("-p", "--password", help="Password (omit for secure prompt)")

    args = parser.parse_args()

    if not args.text and not args.file:
        parser.error("Specify either --text or --file")

    password = args.password
    if not password:
        password = getpass.getpass("Enter password: ")
        if args.action == "encrypt":
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("[!] Passwords do not match.")
                sys.exit(1)

    try:
        if args.text:
            if args.action == "encrypt":
                result = encrypt_text(args.text, password)
                print(f"\n[+] Encrypted text:\n{result}")
            else:
                result = decrypt_text(args.text, password)
                print(f"\n[+] Decrypted text:\n{result}")

        elif args.file:
            if args.action == "encrypt":
                out_path, size = encrypt_file(args.file, password)
                print(f"\n[+] File encrypted: {out_path}")
                print(f"    Original size: {size:,} bytes")
            else:
                out_path, size = decrypt_file(args.file, password)
                print(f"\n[+] File decrypted: {out_path}")
                print(f"    Decrypted size: {size:,} bytes")

    except ValueError as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"\n[!] File not found: {args.file}")
        sys.exit(1)


if __name__ == "__main__":
    main()
