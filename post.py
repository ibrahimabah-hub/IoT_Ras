import requests
import secrets
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

server_address = 'http://192.168.1.254:5000'


def generate_key(message):
  # Generate a symmetric key (AES) for data encryption
  salt_aes = secrets.token_bytes(16)  # Securely generate a random salt for AES
  password_aes = b'Silver'  # Secret AES password

  kdf_aes = PBKDF2HMAC(
      algorithm=hashes.SHA256(),
      iterations=100000,
      salt=salt_aes,
      length=32  # Specify the key length for AES
  )

  key_aes = base64.urlsafe_b64encode(kdf_aes.derive(password_aes))

  # Use classical symmetric encryption (AES) to encrypt the message
  cipher_suite_aes = Fernet(key_aes)
  cipher_text_aes = cipher_suite_aes.encrypt(message)

  return cipher_text_aes, key_aes


# Step 1: Get the public key from the Flask server
response = requests.get(f'{server_address}/get_public_key')
public_key_pem = response.json()['public_key']
public_key_rsa = serialization.load_pem_public_key(public_key_pem.encode())

# Step 2: Generate a symmetric key (AES) for data encryption
key_aes = Fernet.generate_key()

# Use RSA to encrypt the symmetric key
encrypted_key_rsa = public_key_rsa.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

# Step 4: Use the symmetric key (AES) to encrypt the message
cipher_suite_aes = Fernet(key_aes)
message = b"TempPassword"
cipher_text_aes = cipher_suite_aes.encrypt(message)

# Step 5: Send the encrypted key and ciphertext to the Flask server
data = {
    'Aes_key': encrypted_key_rsa.hex(),
    'Ciphertext': cipher_text_aes.hex()
}
response = requests.post(f'{server_address}/', json=data)

# Print the response from the server
print(response.text)