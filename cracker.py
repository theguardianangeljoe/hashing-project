import hashlib
import time

def dictionary_attack(hash_value, hash_type):
    attempts = 0
    start_time = time.time()

    with open("wordlist.txt", "r") as file:
        for word in file:
            attempts += 1
            word = word.strip()

            if hash_type == "MD5":
                hashed = hashlib.md5(word.encode()).hexdigest()
            elif hash_type == "SHA1":
                hashed = hashlib.sha1(word.encode()).hexdigest()
            elif hash_type == "SHA256":
                hashed = hashlib.sha256(word.encode()).hexdigest()
            elif hash_type == "SHA512":
                hashed = hashlib.sha512(word.encode()).hexdigest()
            else:
                return None, attempts, 0

            if hashed == hash_value:
                end_time = time.time()
                return word, attempts, round(end_time - start_time, 4)

    end_time = time.time()
    return None, attempts, round(end_time - start_time, 4)