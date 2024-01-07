import hashlib
import base64
import os

def generate_hash(hash_type, salt, value):
    """
    Generate a hashed value using specified hash type, salt, and the original value.

    :param hash_type: Type of hash function (e.g., 'sha1').
    :param salt: Salt value for hashing.
    :param value: The original value to be hashed.
    :return: A string representing the generated hash.
    """
    if not hash_type:
        hash_type = "sha1"
    if not salt:
        salt = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')

    hash_obj = hashlib.new(hash_type)
    hash_obj.update(salt.encode('utf-8') + value)
    hashed_bytes = hash_obj.digest()

    return f"${hash_type}${salt}${base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')}"

def is_hash_match(hash_type, salt, value, target_hash):
    """
    Check if a generated hash matches the target hash.

    :param hash_type: Type of hash function.
    :param salt: Salt value used in hashing.
    :param value: The original value to be hashed.
    :param target_hash: The target hash value to compare against.
    :return: Boolean indicating whether the hash matches the target.
    """
    try:
        generated_hash = generate_hash(hash_type, salt, value)
        return generated_hash == target_hash
    except hashlib.NoSuchAlgorithmException as e:
        raise Exception(f"Error while computing hash of type {hash_type}: {e}")

def find_password_in_wordlist(hash_type, salt, target_hash, wordlist_path):
    """
    Find the password in a wordlist that matches the target hash.

    :param hash_type: Type of hash function.
    :param salt: Salt value for hashing.
    :param target_hash: Hash value to find.
    :param wordlist_path: Path to the wordlist file.
    :return: The password if found, None otherwise.
    """
    with open(wordlist_path, 'r', encoding='latin-1') as password_list:
        for password in password_list:
            if is_hash_match(hash_type, salt, password.strip().encode('utf-8'), target_hash):
                return password.strip()
    return None

# Example usage
hash_type = "sha1"
salt = "d"
target_hash = "$sha1$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I="
wordlist_path = '/usr/share/wordlists/rockyou.txt'

found_password = find_password_in_wordlist(hash_type, salt, target_hash, wordlist_path)
if found_password:
    print(f'PASSWORD IS : {found_password}')
else:
    print('Password not found in wordlist.')
