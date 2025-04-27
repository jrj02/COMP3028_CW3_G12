import base64

def convert_to_john_format(original_hash: str) -> str:
    salt_hex, hash_hex = original_hash.split('$')
    salt = bytes.fromhex(salt_hex)
    hsh = bytes.fromhex(hash_hex)
    salt_b64 = base64.b64encode(salt).decode()
    hash_b64 = base64.b64encode(hsh).decode()
    return f"$pbkdf2-sha256$100000${salt_b64}${hash_b64}"

# Example usage
original = input("Enter original salt$hash: ")
john_format = convert_to_john_format(original)
print("John-compatible hash:")
print(john_format)
