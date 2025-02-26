from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import binascii


# DeriveKey class example using PBKDF2
class DeriveKey:
    def __init__(self, password, salt, key_length=16):
        self.password = password
        self.salt = salt
        self.key_length = key_length

    def derive_key(self):
        return PBKDF2(self.password, self.salt, dkLen=self.key_length)


# Example usage
# password = "my_secret_password"

# Generate a random, strong password and salt
password = binascii.hexlify(get_random_bytes(16)).decode('utf-8')
salt = get_random_bytes(16)
derive_key = DeriveKey(password, salt)
key = derive_key.derive_key()

# Initialize the cipher object for encryption
cipher_encrypt = AES.new(key, AES.MODE_ECB)

# Message to be encrypted
message = "This is a secret message!"
padded_message = message + (16 - len(message) % 16) * chr(16 - len(message) % 16)

# Encrypt the message
encrypted_bytes = cipher_encrypt.encrypt(padded_message.encode())
encrypted_message = binascii.hexlify(encrypted_bytes).decode('utf-8')

print(f"Encrypted message: {encrypted_message}")

# Initialize the cipher object for decryption
cipher_decrypt = AES.new(key, AES.MODE_ECB)

# Decrypt the message
decrypted_bytes = cipher_decrypt.decrypt(binascii.unhexlify(encrypted_message))
decrypted_message = decrypted_bytes[:-decrypted_bytes[-1]].decode('utf-8')

print(f"Decrypted message: {decrypted_message}")
