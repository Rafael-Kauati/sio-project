import os
import hashlib
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Função para gerar uma chave AES e criptografar o arquivo
def encrypt_file_with_aes(file_data):
    aes_key = os.urandom(32)  # 256-bit AES key
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Padding para múltiplos de 16 bytes
    padding_length = 16 - len(file_data) % 16
    file_data += bytes([padding_length] * padding_length)

    encrypted_file_data = encryptor.update(file_data) + encryptor.finalize()
    return encrypted_file_data, aes_key, iv

# Simulando a criptografia do arquivo
file_path = './file.txt'
with open(file_path, 'rb') as f:
    file_data = f.read()

# Gera o hash SHA256 do arquivo para usá-lo como file_handle
# Gera o hash SHA256 do arquivo original, antes da criptografia

# Criptografa o arquivo

encrypted_file_data, aes_key, iv = encrypt_file_with_aes(file_data)
print(f"\n Encrypted file key : {aes_key.hex()}")
file_handle = hashlib.sha256(encrypted_file_data).hexdigest()

# Envia o arquivo criptografado, a chave de criptografia e o file_handle para o servidor
response = requests.post(
    'http://localhost:5000/add_document',
    files={'file': encrypted_file_data},  # Envia o arquivo criptografado
    data={
        'session_key': 'key',
        'file_name': 'test',
        'file_encryption_key': aes_key.hex(),  # Chave AES convertida para hexadecimal
        'file_handle': file_handle  # Passa o hash do arquivo original como file_handle
    }
)

print(response.json())
