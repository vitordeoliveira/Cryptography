import base64
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from os import urandom
from cryptography.hazmat.backends import default_backend
import hashlib

# Generate Diffie-Hellman parameters
parameters = dh.generate_parameters(generator=2, key_size=2048)

# Generate private key
private_key = parameters.generate_private_key()

# Get public key
public_key = private_key.public_key()

# Serialize public key to bytes
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Send public_key_bytes to other party

# Receive other party's public key as public_key_bytes

# Deserialize other party's public key from bytes
other_public_key = serialization.load_pem_public_key(
    public_key_bytes,
    backend=default_backend()
)

# Compute shared secret
shared_secret = private_key.exchange(other_public_key)

# Use shared secret as a symmetric encryption key
shared_secret_bytes = str(shared_secret).encode('utf-8')

# Use SHA-256 to generate a 32-byte key
key = hashlib.sha256(shared_secret_bytes).digest()

# URL-safe base64-encode the key
key_b64 = base64.urlsafe_b64encode(key)

# Initialize the Fernet object with the encoded key
fernet = Fernet(key_b64)

# Encrypt a file
def encrypt_file(file_name):
    with open(file_name, "rb") as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(file_name, "wb") as file:
        file.write(encrypted_data)

# Decrypt a file
def decrypt_file(file_name):
    with open(file_name, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(file_name, "wb") as file:
        file.write(decrypted_data)

# Test the file encryption and decryption functions
file_name = "example.txt"
with open(file_name, "wb") as file:
    file.write(b"Hello, world!")
print("Original file contents:")
with open(file_name, "rb") as file:
    print(file.read())
encrypt_file(file_name)
print("Encrypted file contents:")
with open(file_name, "rb") as file:
    print(file.read())
decrypt_file(file_name)
print("Decrypted file contents:")
with open(file_name, "rb") as file:
    print(file.read())
