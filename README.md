# Encryption Tool

encrypts and decrypts text and files using AES-256-CBC. the whole aes cipher is implemented from scratch in pure python, no libraries

## how it works

- aes-256 implemented following FIPS 197 spec (sbox, mixcolumns, key expansion etc)
- pbkdf2-hmac-sha256 for key derivation (100k iterations)
- hmac-sha256 for integrity check (encrypt then mac)
- pkcs7 padding
- random salt + iv per encryption

## usage

```
# encrypt text
python encryption_tool.py encrypt -t "secret message" -p mypassword

# decrypt text
python encryption_tool.py decrypt -t "base64string" -p mypassword

# encrypt file
python encryption_tool.py encrypt -f document.pdf -p mypassword

# decrypt file
python encryption_tool.py decrypt -f document.pdf.enc -p mypassword
```

if you dont pass -p it will ask for password securely

this is an educational project to understand crypto internals. for production stuff use the cryptography library
