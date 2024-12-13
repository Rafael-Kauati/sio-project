# utils.py
import os
from datetime import datetime, timedelta, timezone

import cryptography
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
# Função para carregar a chave privada a partir de um arquivo PEM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives.serialization import load_der_public_key
def encrypt_with_chacha20(key, nonce, plaintext):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext.encode('utf-8'))

def encrypt_with_private_key(private_key_path, data):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
    encrypted_data = private_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

def load_ec_master_key(private_key_path="./master_key.pem"):
    abs_path = os.path.abspath(private_key_path)
    print(f"Tentando carregar a chave de: {abs_path}")  # Verifica se o caminho está correto

    try:
        with open(abs_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        return private_key
    except FileNotFoundError:
        print("Erro: Arquivo não encontrado.")
        raise ValueError("Chave privada não encontrada.")
    except Exception as e:
        print(f"Erro ao carregar a chave: {e}")
        raise ValueError("Erro ao carregar a chave privada.")



def load_ec_public_key(public_key_path="./master_key.pem.pub"):
    # Carrega a chave pública EC de um arquivo PEM
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    print(f"\n === master public key : {public_key}")
    return public_key

def decrypt_file_key_with_ec_master(encrypted_file_key, iv, tag, ephemeral_public_key, private_key_path="master_key.pem"):
    # Carrega a chave privada da master key
    private_key = load_ec_master_key(private_key_path)

    # Carrega a chave pública efêmera a partir do DER
    ephemeral_public_key_obj = load_der_public_key(ephemeral_public_key)

    # Gera a chave compartilhada usando a troca de chaves ECDH com a chave pública efêmera
    shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key_obj)
    print(f"Chave compartilhada: {shared_key}")

    # Deriva a chave AES a partir da chave compartilhada usando HKDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"file encryption",
    ).derive(shared_key)

    print(f"AES Key derivada: {aes_key.hex()}")

    # Cria o objeto Cipher com AES-GCM e o IV fornecido
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()

    # Descriptografa a chave do arquivo
    try:
        decrypted_file_key = decryptor.update(encrypted_file_key) + decryptor.finalize()
        return decrypted_file_key
    except InvalidTag as e:
        print(f"Erro de tag inválida: {e}")
        raise ValueError("Falha na descriptografia da chave do arquivo devido a um tag inválido.") from e
    except Exception as e:
        print(f"Erro desconhecido: {e}")
        raise ValueError("Falha na descriptografia da chave do arquivo.") from e



def encrypt_file_key_with_ec_master(file_key, public_key):
    # Gera uma chave efêmera para ECDH
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)

    # Deriva uma chave AES a partir do segredo compartilhado usando HKDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"file encryption",
    ).derive(shared_key)

    # Criptografa a `file_key` usando AES-GCM com o segredo derivado
    iv = os.urandom(12)  # IV de 12 bytes para AES-GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()

    # Certifique-se de que `file_key` está em bytes
    if isinstance(file_key, str):
        file_key = file_key.encode()  # Converte para bytes se for uma string

    encrypted_file_key = encryptor.update(file_key) + encryptor.finalize()

    # Retorna a chave criptografada, a chave pública efêmera, IV e tag
    return encrypted_file_key, ephemeral_private_key.public_key(), iv, encryptor.tag

def load_ec_private_key(private_key_path="./master_key.pem"):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return private_key

def decrypt_with_chacha20(key, nonce, ciphertext):
        """Descriptografar dados usando ChaCha20."""
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext)


def decrypt_session_key(encrypted_session_key, private_key_path="private_key.pem"):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None
        )

    try:
        decrypted_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError(f"Erro ao descriptografar a chave de sessão: {e}")

    return decrypted_key.decode()

def decrypt_with_private_key(private_key_path, encrypted_data):
        """Descriptografar dados usando a chave privada."""
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )
        return private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

def is_session_valid(session):
    expiration_time = timedelta(seconds=30*60) # 15 minutes

    now = datetime.now(timezone.utc)

    if session.created_at.tzinfo is None:
        session_created_at = session.created_at.replace(tzinfo=timezone.utc)
    else:
        session_created_at = session.created_at

    return now - session_created_at < expiration_time


def encrypt_file_key_with_master_key():
    return None