import base64
import json
import os
import requests
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import logging
def encrypt_with_chacha20(key, nonce, plaintext):
    """
    Criptografa os dados usando o algoritmo ChaCha20.
    """
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()

    # Certifica-se de que o texto está no formato correto
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')  # Converte para bytes se for string

    return encryptor.update(plaintext)



def encrypt_with_public_key(public_key_pem, data):
    # Carregar a chave pública a partir da string PEM
    public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())

    # Encripta os dados usando a chave pública
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data


def encrypt_session_key(session_key, public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    encrypted_key = public_key.encrypt(
        session_key.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode()



def decrypt_with_chacha20(key, nonce, ciphertext):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)

def decrypt_with_public_key(public_key_path, encrypted_data):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
    decrypted_data = public_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data