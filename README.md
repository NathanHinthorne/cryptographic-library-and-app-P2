# Cryptographic library and app

A comprehensive cryptographic library and command-line application implementing asymmetric encryption algorithms at the 128-bit security level.

## Features

### Asymmetric Services

- ECIES (Elliptic Curve Integrated Encryption Scheme)
- Elliptic Schnorr Digital Signatures
- Key pair generation
- Public key-based encryption
- Digital signature generation and verification

## Usage

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

## Tasks

### Nathan's Tasks

- Edwards:
  - [ ] Constructor
  - [ ] gen()
  - [ ] toString()

- Point:
  - [x] equals()
  - [x] negate()
  - [x] add()

### Trae's Tasks

- Edwards:
  - [x] isPoint()
  - [x] getPoint()

- Point:
  - [x] Constructors
  - [x] isZero()
  - [x] mul()
  - [x] toString()

## Attribution

Uses specifications found in https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf for the SHA-3/SHAKE implementation.

Uses specifications found in 

## Contributing

Nathan Hinthorne and Trae Claar
