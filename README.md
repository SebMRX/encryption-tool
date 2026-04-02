# Encryption Tool

A pure-Python AES-256-CBC encryption tool for files and text. No external dependencies.

## Features

- **AES-256-CBC** encryption (implemented from scratch per FIPS 197)
- **PBKDF2-HMAC-SHA256** key derivation (100,000 iterations)
- **HMAC-SHA256** authentication (encrypt-then-MAC)
- **PKCS#7 padding**
- Encrypt/decrypt both **text** and **files**
- Password-based — no key management needed
- Zero external dependencies

## Security Design

```
Encrypted format: [salt 16B] [IV 16B] [HMAC 32B] [ciphertext...]

1. Random 16-byte salt + 16-byte IV generated per encryption
2. PBKDF2 derives 64 bytes from password+salt (32B enc key + 32B HMAC key)
3. Plaintext padded with PKCS#7, encrypted with AES-256-CBC
4. HMAC-SHA256 computed over (salt + IV + ciphertext)
5. On decryption: HMAC verified BEFORE decryption (authenticate-then-decrypt)
```

## Installation

```bash
git clone https://github.com/SebMRX/encryption-tool.git
cd encryption-tool
```

## Usage

```bash
# Encrypt text
python encryption_tool.py encrypt -t "Top secret message" -p mypassword

# Decrypt text
python encryption_tool.py decrypt -t "base64_encrypted_string" -p mypassword

# Encrypt a file
python encryption_tool.py encrypt -f secret_document.pdf -p mypassword
# → creates secret_document.pdf.enc

# Decrypt a file
python encryption_tool.py decrypt -f secret_document.pdf.enc -p mypassword
# → restores secret_document.pdf

# Interactive (password hidden)
python encryption_tool.py encrypt -f myfile.txt
```

## Example

```bash
$ python encryption_tool.py encrypt -t "Hello, World!" -p demo123

[+] Encrypted text:
7f3a2b...base64string...==

$ python encryption_tool.py decrypt -t "7f3a2b...base64string...==" -p demo123

[+] Decrypted text:
Hello, World!
```

## Why Pure Python?

This implementation includes a complete AES-256 cipher built from scratch following the FIPS 197 specification. While production systems should use libraries like `cryptography` or `PyCryptodome`, this project demonstrates understanding of:

- Galois Field arithmetic (GF(2^8))
- S-Box substitution and key expansion
- CBC mode of operation
- PKCS#7 padding scheme
- Key derivation and message authentication

## Disclaimer

This is an **educational project** demonstrating cryptographic concepts. For production use, prefer established libraries like Python's `cryptography` package.

## License

MIT License
