from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
import secrets
import base64

private_key_rsa = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key_rsa = private_key_rsa.public_key()


def generate_key(message):
  # Generate a symmetric key (AES) for data encryption
  salt_aes = secrets.token_bytes(16)  # Securely generate a random salt for AES
  password_aes = b'Secret_AES_Password'  # Secret AES password

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


# Encrypt the symmetric key with the public key
def pub_encrypt(message):
  encrypted_key_rsa = public_key_rsa.encrypt(
      message,
      asymmetric_padding.OAEP(
          mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None))

  return encrypted_key_rsa


def decrypt(encrypted_key_rsa, cipher_text_aes):
  # Decrypt the symmetric key with the private key (RSA)
  decrypted_key_rsa = private_key_rsa.decrypt(
      encrypted_key_rsa,
      asymmetric_padding.OAEP(
          mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None))

  # Use the decrypted symmetric key to decrypt the message
  decipher_suite_aes = Fernet(decrypted_key_rsa)
  decipher_text_aes = decipher_suite_aes.decrypt(cipher_text_aes)

  return decipher_text_aes


original_message = b"hello"
print("Original Message:", original_message.decode())
cipher_text_aes, key_aes = generate_key(original_message)
encrypted_key_rsa = pub_encrypt(key_aes)
print("Encrypted Message:", cipher_text_aes)
decipher_text_aes = decrypt(encrypted_key_rsa, cipher_text_aes)
print("Decrypted Message:", decipher_text_aes.decode())
