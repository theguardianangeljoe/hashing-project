"""
Advanced Password Hash Cracker
Supports multiple hash algorithms with automatic identification and cracking
"""

import hashlib
import bcrypt
import argon2
import passlib.hash as phash
import re
import os
import sys
from typing import Optional, Tuple, Dict, List
from pathlib import Path


class HashIdentifier:
    """Identifies hash types based on patterns and length"""
    
    HASH_PATTERNS = {
        'md5': (r'^[a-fA-F0-9]{32}$', 32),
        'sha1': (r'^[a-fA-F0-9]{40}$', 40),
        'sha224': (r'^[a-fA-F0-9]{56}$', 56),
        'sha256': (r'^[a-fA-F0-9]{64}$', 64),
        'sha384': (r'^[a-fA-F0-9]{96}$', 96),
        'sha512': (r'^[a-fA-F0-9]{128}$', 128),
        'bcrypt': (r'^\$2[aby]?\$\d{1,2}\$[./A-Za-z0-9]{53}$', None),
        'argon2': (r'^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$', None),
        'scrypt': (r'^\$scrypt\$', None),
        'pbkdf2_sha256': (r'^\$pbkdf2-sha256\$', None),
        'pbkdf2_sha512': (r'^\$pbkdf2-sha512\$', None),
        'sha3_224': (r'^[a-fA-F0-9]{56}$', 56),
        'sha3_256': (r'^[a-fA-F0-9]{64}$', 64),
        'sha3_384': (r'^[a-fA-F0-9]{96}$', 96),
        'sha3_512': (r'^[a-fA-F0-9]{128}$', 128),
        'blake2b': (r'^[a-fA-F0-9]{128}$', 128),
        'blake2s': (r'^[a-fA-F0-9]{64}$', 64),
        'ntlm': (r'^[a-fA-F0-9]{32}$', 32),
        'mysql': (r'^[a-fA-F0-9]{40}$', 40),
        'md5_crypt': (r'^\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$', None),
        'sha256_crypt': (r'^\$5\$[./A-Za-z0-9]{16}\$[./A-Za-z0-9]{43}$', None),
        'sha512_crypt': (r'^\$6\$[./A-Za-z0-9]{16}\$[./A-Za-z0-9]{86}$', None),
    }
    
    @staticmethod
    def identify(hash_string: str) -> List[str]:
        """
        Identify possible hash types for a given hash string
        
        Args:
            hash_string: The hash string to identify
            
        Returns:
            List of possible hash types (most likely first)
        """
        hash_string = hash_string.strip()
        possible_types = []
        
        # Check against patterns
        for hash_type, (pattern, length) in HashIdentifier.HASH_PATTERNS.items():
            if length and len(hash_string) == length:
                if re.match(pattern, hash_string):
                    possible_types.append(hash_type)
            elif re.match(pattern, hash_string):
                possible_types.append(hash_type)
        
        # Additional heuristics
        if hash_string.startswith('$2'):
            if 'bcrypt' not in possible_types:
                possible_types.insert(0, 'bcrypt')
        elif hash_string.startswith('$argon2'):
            if 'argon2' not in possible_types:
                possible_types.insert(0, 'argon2')
        elif hash_string.startswith('$5$'):
            if 'sha256_crypt' not in possible_types:
                possible_types.insert(0, 'sha256_crypt')
        elif hash_string.startswith('$6$'):
            if 'sha512_crypt' not in possible_types:
                possible_types.insert(0, 'sha512_crypt')
        elif hash_string.startswith('$1$'):
            if 'md5_crypt' not in possible_types:
                possible_types.insert(0, 'md5_crypt')
        elif hash_string.startswith('$pbkdf2'):
            if 'pbkdf2_sha256' not in possible_types and 'pbkdf2_sha512' not in possible_types:
                if 'sha256' in hash_string.lower():
                    possible_types.insert(0, 'pbkdf2_sha256')
                else:
                    possible_types.insert(0, 'pbkdf2_sha512')
        
        # If no matches, try length-based guessing
        if not possible_types:
            length = len(hash_string)
            if length == 32:
                possible_types.extend(['md5', 'ntlm'])
            elif length == 40:
                possible_types.extend(['sha1', 'mysql'])
            elif length == 64:
                possible_types.extend(['sha256', 'sha3_256', 'blake2s'])
            elif length == 128:
                possible_types.extend(['sha512', 'sha3_512', 'blake2b'])
        
        return possible_types if possible_types else ['unknown']


class HashCracker:
    """Main hash cracking class"""
    
    def __init__(self, wordlist_path: Optional[str] = None):
        """
        Initialize the hash cracker
        
        Args:
            wordlist_path: Path to wordlist file
        """
        self.wordlist_path = wordlist_path
        self.cracked = False
        self.password = None
        self.attempts = 0
        
    def _read_wordlist(self) -> List[str]:
        """Read words from wordlist file"""
        if not self.wordlist_path or not os.path.exists(self.wordlist_path):
            raise FileNotFoundError(f"Wordlist not found: {self.wordlist_path}")
        
        words = []
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word:
                        words.append(word)
        except Exception as e:
            raise IOError(f"Error reading wordlist: {e}")
        
        return words
    
    def crack(self, hash_string: str, hash_type: Optional[str] = None, 
              wordlist: Optional[List[str]] = None) -> Optional[str]:
        """
        Crack a hash using wordlist
        
        Args:
            hash_string: The hash to crack
            hash_type: Specific hash type (if None, will auto-identify)
            wordlist: Optional list of words to try (if None, uses file)
            
        Returns:
            Cracked password if found, None otherwise
        """
        hash_string = hash_string.strip()
        
        # Auto-identify hash type if not provided
        if not hash_type:
            possible_types = HashIdentifier.identify(hash_string)
            if not possible_types or possible_types[0] == 'unknown':
                raise ValueError(f"Could not identify hash type: {hash_string}")
            hash_type = possible_types[0]
            if len(possible_types) > 1:
                print(f"Identified hash type: {hash_type} (also possible: {', '.join(possible_types[1:])})")
            else:
                print(f"Identified hash type: {hash_type}")
        
        # Get wordlist
        if wordlist is None:
            wordlist = self._read_wordlist()
        
        # Reset state
        self.cracked = False
        self.password = None
        self.attempts = 0
        
        # Try cracking with identified hash type
        print(f"Attempting to crack {hash_type} hash...")
        print(f"Trying {len(wordlist)} passwords from wordlist...")
        
        for word in wordlist:
            self.attempts += 1
            
            # Show progress every 10000 attempts
            if self.attempts % 10000 == 0:
                print(f"Attempted {self.attempts} passwords...", end='\r')
            
            try:
                if self._verify_hash(word, hash_string, hash_type):
                    self.cracked = True
                    self.password = word
                    print(f"\n[+] Password found after {self.attempts} attempts!")
                    return word
            except Exception as e:
                # Skip errors and continue
                continue
        
        print(f"\n[-] Password not found in wordlist after {self.attempts} attempts")
        return None
    
    def _verify_hash(self, password: str, hash_string: str, hash_type: str) -> bool:
        """Verify if password matches hash"""
        try:
            hash_string_clean = hash_string.strip().lower()
            if hash_type == 'md5':
                computed = hashlib.md5(password.encode()).hexdigest()
                return computed == hash_string_clean
            
            elif hash_type == 'sha1':
                computed = hashlib.sha1(password.encode()).hexdigest()
                return computed == hash_string_clean
            
            elif hash_type == 'sha224':
                computed = hashlib.sha224(password.encode()).hexdigest()
                return computed == hash_string_clean
            
            elif hash_type == 'sha256':
                computed = hashlib.sha256(password.encode()).hexdigest()
                return computed == hash_string_clean
            
            elif hash_type == 'sha384':
                computed = hashlib.sha384(password.encode()).hexdigest()
                return computed == hash_string_clean
            
            elif hash_type == 'sha512':
                computed = hashlib.sha512(password.encode()).hexdigest()
                return computed == hash_string_clean
            
            elif hash_type == 'sha3_224':
                computed = hashlib.sha3_224(password.encode()).hexdigest()
                return computed == hash_string_clean
            
            elif hash_type == 'sha3_256':
                computed = hashlib.sha3_256(password.encode()).hexdigest()
                return computed == hash_string_clean
            
            elif hash_type == 'sha3_384':
                computed = hashlib.sha3_384(password.encode()).hexdigest()
                return computed == hash_string_clean
            
            elif hash_type == 'sha3_512':
                computed = hashlib.sha3_512(password.encode()).hexdigest()
                return computed == hash_string_clean
            
            elif hash_type == 'blake2b':
                computed = hashlib.blake2b(password.encode()).hexdigest()
                return computed == hash_string_clean
            
            elif hash_type == 'blake2s':
                computed = hashlib.blake2s(password.encode()).hexdigest()
                return computed == hash_string_clean
            
            elif hash_type == 'bcrypt':
                try:
                    return bcrypt.checkpw(password.encode(), hash_string.encode())
                except:
                    return False
            
            elif hash_type == 'argon2':
                try:
                    ph = argon2.PasswordHasher()
                    ph.verify(hash_string, password)
                    return True
                except:
                    return False
            
            elif hash_type == 'scrypt':
                try:
                    return phash.scrypt.verify(password, hash_string)
                except:
                    return False
            
            elif hash_type == 'pbkdf2_sha256':
                try:
                    return phash.pbkdf2_sha256.verify(password, hash_string)
                except:
                    return False
            
            elif hash_type == 'pbkdf2_sha512':
                try:
                    return phash.pbkdf2_sha512.verify(password, hash_string)
                except:
                    return False
            
            elif hash_type == 'md5_crypt':
                try:
                    return phash.md5_crypt.verify(password, hash_string)
                except:
                    return False
            
            elif hash_type == 'sha256_crypt':
                try:
                    return phash.sha256_crypt.verify(password, hash_string)
                except:
                    return False
            
            elif hash_type == 'sha512_crypt':
                try:
                    return phash.sha512_crypt.verify(password, hash_string)
                except:
                    return False
            
            elif hash_type == 'ntlm':
                # NTLM is MD4, but we'll use a simple approach
                try:
                    # NTLM is actually MD4, but Python doesn't have MD4
                    # This is a simplified check
                    md4_hash = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
                    return md4_hash == hash_string
                except:
                    return False
            
            elif hash_type == 'mysql':
                # MySQL uses SHA1 twice
                hash1 = hashlib.sha1(password.encode()).hexdigest()
                hash2 = hashlib.sha1(hash1.encode()).hexdigest()
                return hash2 == hash_string_clean
            
            else:
                return False
                
        except Exception:
            return False
    
    def crack_multiple(self, hash_list: List[str], hash_type: Optional[str] = None) -> Dict[str, Optional[str]]:
        """
        Crack multiple hashes
        
        Args:
            hash_list: List of hash strings to crack
            hash_type: Optional hash type for all hashes
            
        Returns:
            Dictionary mapping hash -> password (or None if not found)
        """
        results = {}
        wordlist = self._read_wordlist() if self.wordlist_path else []
        
        for i, hash_string in enumerate(hash_list, 1):
            print(f"\n[{i}/{len(hash_list)}] Processing hash: {hash_string[:20]}...")
            password = self.crack(hash_string, hash_type, wordlist)
            results[hash_string] = password
        
        return results
