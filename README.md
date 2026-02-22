# Advanced Password Hash Cracker

A comprehensive, production-ready Python tool for identifying and cracking password hashes using dictionary attacks. Supports multiple hash algorithms with automatic hash type identification.

## Features

- **Automatic Hash Identification**: Automatically detects hash types based on patterns and length
- **Multiple Hash Support**: Supports 20+ hash algorithms including:
  - MD5, SHA1, SHA224, SHA256, SHA384, SHA512
  - SHA3-224, SHA3-256, SHA3-384, SHA3-512
  - BLAKE2b, BLAKE2s
  - bcrypt, Argon2, scrypt
  - PBKDF2-SHA256, PBKDF2-SHA512
  - MD5-crypt, SHA256-crypt, SHA512-crypt
  - NTLM, MySQL
- **Dictionary Attack**: Fast wordlist-based password cracking
- **Batch Processing**: Crack multiple hashes from a file
- **Progress Tracking**: Real-time progress updates during cracking
- **Production Ready**: Comprehensive error handling and testing

## Installation

1. Clone or download this repository

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Identify Hash Type

```bash
python main.py --identify <hash>
```

Example:
```bash
python main.py --identify 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
```

### Crack a Single Hash

```bash
python main.py --crack <hash> --wordlist <wordlist_file>
```

Example:
```bash
python main.py --crack 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 --wordlist wordlist.txt
```

### Crack with Specific Hash Type

```bash
python main.py --crack <hash> --wordlist <wordlist_file> --type sha256
```

### Crack Multiple Hashes from File

```bash
python main.py --file <hash_file> --wordlist <wordlist_file> [--output <output_file>]
```

Example:
```bash
python main.py --file hashes.txt --wordlist wordlist.txt --output results.txt
```

The hash file should contain one hash per line (comments starting with # are ignored).

## Command Line Options

```
--identify, -i HASH        Identify the type of a hash
--crack, -c HASH          Crack a single hash
--file, -f FILE           Crack hashes from a file (one hash per line)
--wordlist, -w FILE       Path to wordlist file (required for cracking)
--type, -t TYPE           Specify hash type (md5, sha1, sha256, sha512, bcrypt, etc.)
--output, -o FILE         Output file for results (when using --file)
```

## Supported Hash Types

- `md5` - MD5 hash
- `sha1` - SHA-1 hash
- `sha224` - SHA-224 hash
- `sha256` - SHA-256 hash
- `sha384` - SHA-384 hash
- `sha512` - SHA-512 hash
- `sha3_224` - SHA3-224 hash
- `sha3_256` - SHA3-256 hash
- `sha3_384` - SHA3-384 hash
- `sha3_512` - SHA3-512 hash
- `blake2b` - BLAKE2b hash
- `blake2s` - BLAKE2s hash
- `bcrypt` - bcrypt hash
- `argon2` - Argon2 hash
- `scrypt` - scrypt hash
- `pbkdf2_sha256` - PBKDF2 with SHA-256
- `pbkdf2_sha512` - PBKDF2 with SHA-512
- `md5_crypt` - MD5-crypt
- `sha256_crypt` - SHA-256-crypt
- `sha512_crypt` - SHA-512-crypt
- `ntlm` - NTLM hash
- `mysql` - MySQL hash

## Wordlist Format

The wordlist file should be a plain text file with one password per line. UTF-8 encoding is supported.

Example wordlist:
```
password
password123
admin
123456
test
```

## Programmatic Usage

You can also use the cracker programmatically:

```python
from hash_cracker import HashCracker, HashIdentifier

# Identify hash type
hash_string = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
hash_types = HashIdentifier.identify(hash_string)
print(f"Hash type: {hash_types[0]}")

# Crack hash
cracker = HashCracker("wordlist.txt")
password = cracker.crack(hash_string)
if password:
    print(f"Password found: {password}")
```

## Testing

Run the comprehensive test suite:

```bash
python test_hash_cracker.py
```

Or using unittest:

```bash
python -m unittest test_hash_cracker.py -v
```

## Performance

The cracker is optimized for speed:
- Efficient hash verification
- Progress updates every 10,000 attempts
- Memory-efficient wordlist reading
- Fast hash type identification

## Security Note

This tool is intended for:
- Educational purposes
- Security research
- Legitimate password recovery (your own passwords)
- Penetration testing with proper authorization

**Do not use this tool for unauthorized access to systems or accounts.**

## Requirements

- Python 3.7+
- bcrypt >= 4.0.1
- argon2-cffi >= 23.1.0
- passlib >= 1.7.4

## License

This project is provided as-is for educational purposes.

## Author

Created as a college project demonstrating password hash cracking techniques.
