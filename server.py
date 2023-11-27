from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

private_key_rsa = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key = private_key_rsa.public_key()

public_key_pem = public_key.public_bytes(
  encoding=serialization.Encoding.PEM,
  format=serialization.PublicFormat.SubjectPublicKeyInfo
)

password = "TempPassword"

def decrypt(encrypted_key_rsa, cipher_text_aes):
    # Decrypt the symmetric key with the private key (RSA)
    decrypted_key_rsa = private_key_rsa.decrypt(
        encrypted_key_rsa,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Use the decrypted symmetric key to decrypt the message
    decipher_suite_aes = Fernet(decrypted_key_rsa)
    decipher_text_aes = decipher_suite_aes.decrypt(cipher_text_aes)

    return decipher_text_aes

@app.route('/', methods=['POST'])
def receive_data():
    data = request.get_json()
    if 'Aes_key' in data and 'Ciphertext' in data:
        Aes_key_b = bytes.fromhex(data['Aes_key'])
        Ciphertext_b = bytes.fromhex(data['Ciphertext'])
        
        aes_key = aes_key_b.decode('utf-8')
        ciphertext = Ciphertext_b.decode('utf-8')

        decipher_text_aes = decrypt(aes_key, ciphertext)

        if decipher_text_aes.decode() == password:
            print("Success")
            return "Success", 200
        else:
            return "Failure", 400
    else:
        return "Invalid data format", 400

@app.route('/get_public_key', methods=['GET'])
def get_public_key():
  return jsonify({'public_key': public_key_pem.decode()})

if __name__ == '__main__':
    # Run the Flask app on port 5000
    app.run(host='0.0.0.0', port=5000)
