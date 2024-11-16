# Cryptographic library and app

A comprehensive cryptographic library and command-line application implementing both symmetric and asymmetric encryption algorithms at the 128-bit security level.

## Features

### Symmetric Services

- SHA-3 hash functions (224, 256, 384, 512-bit security levels)
- SHAKE extendable output functions
- Message Authentication Code (MAC)
- Symmetric encryption/decryption

### Asymmetric Services

- ECIES (Elliptic Curve Integrated Encryption Scheme)
- Elliptic Schnorr Digital Signatures
- Key pair generation
- Public key-based encryption
- Digital signature generation and verification

## Usage

### Symmetric Operations

```bash
# Compute hash
java Main hash <input_file> <output_file> <security_level> [options]

# Compute MAC
java Main mac <input_file> <output_file> <passphrase> <security_level> <mac_length> [options]

# Encrypt
java Main encrypt <input_file> <output_file> <passphrase> [options]

# Decrypt
java Main decrypt <input_file> <output_file> <passphrase> [options]
```

### Asymmetric Operations

```bash
# Generate key pair
java Main genkey <public_key_file> <passphrase> [options]

# ECIES encrypt
java Main ecencrypt <input_file> <output_file> <public_key_file> [options]

# ECIES decrypt
java Main ecdecrypt <input_file> <output_file> <passphrase> [options]

# Sign file
java Main sign <signature_file> <input_file> <passphrase> [options]

# Verify signature
java Main verify <input_file> <signature_file> <public_key_file> [options]
```

## Attribution

Uses specifications found in https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf for the SHA-3/SHAKE implementation.

Uses specifications found in 

## Contributing

Nathan Hinthorne and Trae Claar
