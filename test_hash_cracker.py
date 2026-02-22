"""
Comprehensive test suite for Password Hash Cracker
"""

import unittest
import hashlib
import bcrypt
import os
import tempfile
from hash_cracker import HashIdentifier, HashCracker


class TestHashIdentifier(unittest.TestCase):
    """Test hash identification functionality"""
    
    def test_identify_md5(self):
        """Test MD5 hash identification"""
        md5_hash = hashlib.md5(b"password123").hexdigest()
        types = HashIdentifier.identify(md5_hash)
        self.assertIn('md5', types)
        self.assertEqual(types[0], 'md5')
    
    def test_identify_sha1(self):
        """Test SHA1 hash identification"""
        sha1_hash = hashlib.sha1(b"password123").hexdigest()
        types = HashIdentifier.identify(sha1_hash)
        self.assertIn('sha1', types)
        self.assertEqual(types[0], 'sha1')
    
    def test_identify_sha256(self):
        """Test SHA256 hash identification"""
        sha256_hash = hashlib.sha256(b"password123").hexdigest()
        types = HashIdentifier.identify(sha256_hash)
        self.assertIn('sha256', types)
        self.assertEqual(types[0], 'sha256')
    
    def test_identify_sha512(self):
        """Test SHA512 hash identification"""
        sha512_hash = hashlib.sha512(b"password123").hexdigest()
        types = HashIdentifier.identify(sha512_hash)
        self.assertIn('sha512', types)
        self.assertEqual(types[0], 'sha512')
    
    def test_identify_bcrypt(self):
        """Test bcrypt hash identification"""
        bcrypt_hash = bcrypt.hashpw(b"password123", bcrypt.gensalt()).decode()
        types = HashIdentifier.identify(bcrypt_hash)
        self.assertIn('bcrypt', types)
        self.assertEqual(types[0], 'bcrypt')
    
    def test_identify_sha224(self):
        """Test SHA224 hash identification"""
        sha224_hash = hashlib.sha224(b"password123").hexdigest()
        types = HashIdentifier.identify(sha224_hash)
        self.assertIn('sha224', types)
    
    def test_identify_sha384(self):
        """Test SHA384 hash identification"""
        sha384_hash = hashlib.sha384(b"password123").hexdigest()
        types = HashIdentifier.identify(sha384_hash)
        self.assertIn('sha384', types)
    
    def test_identify_sha3_256(self):
        """Test SHA3-256 hash identification"""
        sha3_hash = hashlib.sha3_256(b"password123").hexdigest()
        types = HashIdentifier.identify(sha3_hash)
        self.assertIn('sha3_256', types)


class TestHashCracker(unittest.TestCase):
    """Test hash cracking functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create temporary wordlist
        self.wordlist_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        self.wordlist_file.write("password\n")
        self.wordlist_file.write("password123\n")
        self.wordlist_file.write("admin\n")
        self.wordlist_file.write("123456\n")
        self.wordlist_file.write("test\n")
        self.wordlist_file.write("hello\n")
        self.wordlist_file.close()
        self.wordlist_path = self.wordlist_file.name
    
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.wordlist_path):
            os.unlink(self.wordlist_path)
    
    def test_crack_md5(self):
        """Test MD5 hash cracking"""
        password = "password123"
        md5_hash = hashlib.md5(password.encode()).hexdigest()
        
        cracker = HashCracker(self.wordlist_path)
        result = cracker.crack(md5_hash, 'md5')
        
        self.assertEqual(result, password)
        self.assertTrue(cracker.cracked)
        self.assertEqual(cracker.password, password)
    
    def test_crack_sha1(self):
        """Test SHA1 hash cracking"""
        password = "password123"
        sha1_hash = hashlib.sha1(password.encode()).hexdigest()
        
        cracker = HashCracker(self.wordlist_path)
        result = cracker.crack(sha1_hash, 'sha1')
        
        self.assertEqual(result, password)
    
    def test_crack_sha256(self):
        """Test SHA256 hash cracking"""
        password = "password123"
        sha256_hash = hashlib.sha256(password.encode()).hexdigest()
        
        cracker = HashCracker(self.wordlist_path)
        result = cracker.crack(sha256_hash, 'sha256')
        
        self.assertEqual(result, password)
    
    def test_crack_sha512(self):
        """Test SHA512 hash cracking"""
        password = "password123"
        sha512_hash = hashlib.sha512(password.encode()).hexdigest()
        
        cracker = HashCracker(self.wordlist_path)
        result = cracker.crack(sha512_hash, 'sha512')
        
        self.assertEqual(result, password)
    
    def test_crack_sha224(self):
        """Test SHA224 hash cracking"""
        password = "password123"
        sha224_hash = hashlib.sha224(password.encode()).hexdigest()
        
        cracker = HashCracker(self.wordlist_path)
        result = cracker.crack(sha224_hash, 'sha224')
        
        self.assertEqual(result, password)
    
    def test_crack_sha384(self):
        """Test SHA384 hash cracking"""
        password = "password123"
        sha384_hash = hashlib.sha384(password.encode()).hexdigest()
        
        cracker = HashCracker(self.wordlist_path)
        result = cracker.crack(sha384_hash, 'sha384')
        
        self.assertEqual(result, password)
    
    def test_crack_sha3_256(self):
        """Test SHA3-256 hash cracking"""
        password = "password123"
        sha3_hash = hashlib.sha3_256(password.encode()).hexdigest()
        
        cracker = HashCracker(self.wordlist_path)
        result = cracker.crack(sha3_hash, 'sha3_256')
        
        self.assertEqual(result, password)
    
    def test_crack_sha3_512(self):
        """Test SHA3-512 hash cracking"""
        password = "password123"
        sha3_hash = hashlib.sha3_512(password.encode()).hexdigest()
        
        cracker = HashCracker(self.wordlist_path)
        result = cracker.crack(sha3_hash, 'sha3_512')
        
        self.assertEqual(result, password)
    
    def test_crack_blake2b(self):
        """Test BLAKE2b hash cracking"""
        password = "password123"
        blake2b_hash = hashlib.blake2b(password.encode()).hexdigest()
        
        cracker = HashCracker(self.wordlist_path)
        result = cracker.crack(blake2b_hash, 'blake2b')
        
        self.assertEqual(result, password)
    
    def test_crack_blake2s(self):
        """Test BLAKE2s hash cracking"""
        password = "password123"
        blake2s_hash = hashlib.blake2s(password.encode()).hexdigest()
        
        cracker = HashCracker(self.wordlist_path)
        result = cracker.crack(blake2s_hash, 'blake2s')
        
        self.assertEqual(result, password)
    
    def test_crack_bcrypt(self):
        """Test bcrypt hash cracking"""
        password = "password123"
        bcrypt_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        
        cracker = HashCracker(self.wordlist_path)
        result = cracker.crack(bcrypt_hash, 'bcrypt')
        
        self.assertEqual(result, password)
    
    def test_crack_auto_identify(self):
        """Test automatic hash type identification"""
        password = "password123"
        sha256_hash = hashlib.sha256(password.encode()).hexdigest()
        
        cracker = HashCracker(self.wordlist_path)
        result = cracker.crack(sha256_hash)  # No hash type specified
        
        self.assertEqual(result, password)
    
    def test_crack_not_found(self):
        """Test when password is not in wordlist"""
        password = "nonexistentpassword999"
        md5_hash = hashlib.md5(password.encode()).hexdigest()
        
        cracker = HashCracker(self.wordlist_path)
        result = cracker.crack(md5_hash, 'md5')
        
        self.assertIsNone(result)
        self.assertFalse(cracker.cracked)
    
    def test_crack_multiple(self):
        """Test cracking multiple hashes"""
        passwords = ["password123", "admin", "test"]
        hashes = [hashlib.md5(p.encode()).hexdigest() for p in passwords]
        
        cracker = HashCracker(self.wordlist_path)
        results = cracker.crack_multiple(hashes, 'md5')
        
        self.assertEqual(len(results), 3)
        self.assertEqual(results[hashes[0]], "password123")
        self.assertEqual(results[hashes[1]], "admin")
        self.assertEqual(results[hashes[2]], "test")
    
    def test_crack_with_wordlist_list(self):
        """Test cracking with wordlist as list"""
        password = "password123"
        md5_hash = hashlib.md5(password.encode()).hexdigest()
        
        wordlist = ["wrong", "password123", "admin"]
        cracker = HashCracker()
        result = cracker.crack(md5_hash, 'md5', wordlist)
        
        self.assertEqual(result, password)
    
    def test_mysql_hash(self):
        """Test MySQL hash cracking"""
        password = "password123"
        # MySQL uses SHA1(SHA1(password))
        hash1 = hashlib.sha1(password.encode()).hexdigest()
        mysql_hash = hashlib.sha1(hash1.encode()).hexdigest()
        
        cracker = HashCracker(self.wordlist_path)
        result = cracker.crack(mysql_hash, 'mysql')
        
        self.assertEqual(result, password)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling"""
    
    def test_empty_wordlist(self):
        """Test with empty wordlist"""
        wordlist_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        wordlist_file.close()
        
        cracker = HashCracker(wordlist_file.name)
        md5_hash = hashlib.md5(b"test").hexdigest()
        
        result = cracker.crack(md5_hash, 'md5')
        self.assertIsNone(result)
        
        os.unlink(wordlist_file.name)
    
    def test_invalid_hash_type(self):
        """Test with invalid hash type"""
        wordlist_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        wordlist_file.write("test\n")
        wordlist_file.close()
        
        cracker = HashCracker(wordlist_file.name)
        md5_hash = hashlib.md5(b"test").hexdigest()
        
        # Should return False for unknown hash type
        result = cracker._verify_hash("test", md5_hash, "unknown_type")
        self.assertFalse(result)
        
        os.unlink(wordlist_file.name)
    
    def test_nonexistent_wordlist(self):
        """Test with nonexistent wordlist file"""
        cracker = HashCracker("nonexistent_file.txt")
        
        with self.assertRaises(FileNotFoundError):
            cracker.crack("test_hash", 'md5')


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestHashIdentifier))
    suite.addTests(loader.loadTestsFromTestCase(TestHashCracker))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    exit(0 if success else 1)
