import hashlib
import random
import string
import re

def generate_hash(password, algorithm):
    password = password.encode()

    if algorithm == "MD5":
        return hashlib.md5(password).hexdigest()
    elif algorithm == "SHA1":
        return hashlib.sha1(password).hexdigest()
    elif algorithm == "SHA256":
        return hashlib.sha256(password).hexdigest()
    elif algorithm == "SHA512":
        return hashlib.sha512(password).hexdigest()
    else:
        return "Unsupported Algorithm"


def detect_hash(hash_string):
    length = len(hash_string)

    if length == 32:
        return "MD5"
    elif length == 40:
        return "SHA1"
    elif length == 64:
        return "SHA256"
    elif length == 128:
        return "SHA512"
    else:
        return "Unknown"


def analyze_strength(password):
    score = 0

    if len(password) >= 8:
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[0-9]", password):
        score += 1
    if re.search(r"[!@#$%^&*]", password):
        score += 1

    if score <= 2:
        return "Weak"
    elif score == 3:
        return "Medium"
    else:
        return "Strong"


def generate_secure_password(length=12):
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(characters) for _ in range(length))