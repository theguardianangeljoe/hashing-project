#!/usr/bin/env python3
"""
Command-line interface for the Password Hash Cracker
"""

import argparse
import sys
import os
from pathlib import Path
from hash_cracker import HashCracker, HashIdentifier


def identify_hash(hash_string: str):
    """Identify hash type"""
    print(f"\nAnalyzing hash: {hash_string}")
    print("-" * 60)
    
    possible_types = HashIdentifier.identify(hash_string)
    
    if not possible_types or possible_types[0] == 'unknown':
        print("[-] Could not identify hash type")
        print(f"  Hash length: {len(hash_string)}")
        print(f"  Hash format: {hash_string[:20]}...")
    else:
        print(f"[+] Most likely hash type: {possible_types[0]}")
        if len(possible_types) > 1:
            print(f"\nOther possible types:")
            for hash_type in possible_types[1:]:
                print(f"  - {hash_type}")
    
    print("-" * 60)


def crack_hash(hash_string: str, wordlist_path: str, hash_type: str = None):
    """Crack a single hash"""
    if not os.path.exists(wordlist_path):
        print(f"[-] Error: Wordlist file not found: {wordlist_path}")
        sys.exit(1)
    
    cracker = HashCracker(wordlist_path)
    
    try:
        password = cracker.crack(hash_string, hash_type)
        if password:
            print(f"\n{'='*60}")
            print(f"SUCCESS! Password found: {password}")
            print(f"{'='*60}")
            return password
        else:
            print(f"\n{'='*60}")
            print("Password not found in wordlist")
            print(f"{'='*60}")
            return None
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


def crack_file(hash_file: str, wordlist_path: str, hash_type: str = None, output_file: str = None):
    """Crack hashes from a file"""
    if not os.path.exists(hash_file):
        print(f"[-] Error: Hash file not found: {hash_file}")
        sys.exit(1)
    
    if not os.path.exists(wordlist_path):
        print(f"[-] Error: Wordlist file not found: {wordlist_path}")
        sys.exit(1)
    
    # Read hashes from file
    hashes = []
    try:
        with open(hash_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                hash_val = line.strip()
                if hash_val and not hash_val.startswith('#'):
                    hashes.append(hash_val)
    except Exception as e:
        print(f"[-] Error reading hash file: {e}")
        sys.exit(1)
    
    if not hashes:
        print("[-] No hashes found in file")
        sys.exit(1)
    
    print(f"Found {len(hashes)} hash(es) to crack")
    
    cracker = HashCracker(wordlist_path)
    results = cracker.crack_multiple(hashes, hash_type)
    
    # Display results
    print(f"\n{'='*60}")
    print("CRACKING RESULTS")
    print(f"{'='*60}")
    
    cracked_count = 0
    for hash_val, password in results.items():
        if password:
            print(f"[+] {hash_val[:40]}... -> {password}")
            cracked_count += 1
        else:
            print(f"[-] {hash_val[:40]}... -> NOT FOUND")
    
    print(f"\nSummary: {cracked_count}/{len(hashes)} passwords cracked")
    
    # Write to output file if specified
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                for hash_val, password in results.items():
                    if password:
                        f.write(f"{hash_val}:{password}\n")
            print(f"\nResults saved to: {output_file}")
        except Exception as e:
            print(f"[-] Error writing output file: {e}")
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Password Hash Cracker - Supports multiple hash algorithms',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Identify hash type
  python main.py --identify 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
  
  # Crack a single hash
  python main.py --crack 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 --wordlist wordlist.txt
  
  # Crack with specific hash type
  python main.py --crack <hash> --wordlist wordlist.txt --type sha256
  
  # Crack multiple hashes from file
  python main.py --file hashes.txt --wordlist wordlist.txt --output results.txt
        """
    )
    
    parser.add_argument('--identify', '-i', metavar='HASH',
                       help='Identify the type of a hash')
    
    parser.add_argument('--crack', '-c', metavar='HASH',
                       help='Crack a single hash')
    
    parser.add_argument('--file', '-f', metavar='FILE',
                       help='Crack hashes from a file (one hash per line)')
    
    parser.add_argument('--wordlist', '-w', metavar='FILE', required=False,
                       help='Path to wordlist file')
    
    parser.add_argument('--type', '-t', metavar='TYPE',
                       help='Specify hash type (md5, sha1, sha256, sha512, bcrypt, etc.)')
    
    parser.add_argument('--output', '-o', metavar='FILE',
                       help='Output file for results (when using --file)')
    
    args = parser.parse_args()
    
    # Check if no arguments provided
    if not args.identify and not args.crack and not args.file:
        parser.print_help()
        sys.exit(1)
    
    # Identify hash
    if args.identify:
        identify_hash(args.identify)
        return
    
    # Check wordlist requirement
    if not args.wordlist:
        print("[-] Error: --wordlist is required for cracking operations")
        sys.exit(1)
    
    # Crack single hash
    if args.crack:
        crack_hash(args.crack, args.wordlist, args.type)
        return
    
    # Crack from file
    if args.file:
        crack_file(args.file, args.wordlist, args.type, args.output)
        return


if __name__ == '__main__':
    main()
