"""
Example usage of the Password Hash Cracker
"""

from hash_cracker import HashCracker, HashIdentifier
import hashlib

# Example 1: Identify a hash type
print("=" * 60)
print("Example 1: Hash Identification")
print("=" * 60)
hash_string = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
possible_types = HashIdentifier.identify(hash_string)
print(f"Hash: {hash_string}")
print(f"Identified type: {possible_types[0]}")
if len(possible_types) > 1:
    print(f"Other possibilities: {', '.join(possible_types[1:])}")

# Example 2: Crack a hash
print("\n" + "=" * 60)
print("Example 2: Cracking a Hash")
print("=" * 60)
password = "password123"
md5_hash = hashlib.md5(password.encode()).hexdigest()
print(f"Original password: {password}")
print(f"MD5 hash: {md5_hash}")

cracker = HashCracker("wordlist.txt")
cracked_password = cracker.crack(md5_hash, "md5")
if cracked_password:
    print(f"\n[+] Successfully cracked! Password: {cracked_password}")
else:
    print("\n[-] Password not found in wordlist")

# Example 3: Crack multiple hashes
print("\n" + "=" * 60)
print("Example 3: Cracking Multiple Hashes")
print("=" * 60)
passwords = ["admin", "test", "hello"]
hashes = [hashlib.md5(p.encode()).hexdigest() for p in passwords]
print(f"Trying to crack {len(hashes)} hashes...")

results = cracker.crack_multiple(hashes, "md5")
for hash_val, password in results.items():
    if password:
        print(f"[+] {hash_val[:20]}... -> {password}")
    else:
        print(f"[-] {hash_val[:20]}... -> NOT FOUND")

print("\n" + "=" * 60)
print("Examples completed!")
print("=" * 60)
