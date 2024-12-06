import base64
import binascii
import hashlib
import os
import random
import string
import sys
import argparse
import logging
import json
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from utils import *
logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def save(state):
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    if not os.path.exists(state_dir):
      logger.debug('Creating state folder')
      os.mkdir(state_dir)

    with open(state_file, 'w') as f:
        f.write(json.dumps(state, indent=4))


def generate_chacha20_key_and_nonce():
    # Generate a 256-bit (32-byte) ChaCha20 key
    key = os.urandom(32)

    # Generate a 96-bit (12-byte) nonce
    nonce = os.urandom(16)

    return key, nonce




def list_organizations():
    url = f"http://{state['REP_ADDRESS']}/organizations"
    '''nonce = str(uuid.uuid4())  # Exemplo de nonce único
    headers = {

        "X-Nonce": nonce
    }'''
    response = requests.get(url)
    #print(response.content)
    if response.status_code == 200:
        #logger.info("Organizations listed successfully.")
        return response.json()
    else:
        logger.error(f"Failed to list organizations: {response.status_code}")


import json
import os
import requests
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import logging

# Set up logging
logger = logging.getLogger(__name__)




def create_organization(data):
    try:
        # Generate ChaCha20 key and nonce
        key = os.urandom(32)
        nonce = os.urandom(16)

        # Load the JSON content of the public key file
        with open(data['public_key_file'], 'r') as pub_key_file:
            key_data = json.load(pub_key_file)  # Parse JSON content
            public_key_content = key_data.get("public_key")  # Extract the public key

        if not public_key_content:
            raise ValueError("The public key is missing in the provided file.")

        # Prepare the payload
        payload = {
            "name": data['name'],
            "subject": {
                "username": data['username'],
                "full_name": data['full_name'],
                "email": data['email']
            },
            "public_key": public_key_content  # Include the public key in the payload
        }
        encrypted_payload = encrypt_with_chacha20(key, nonce, json.dumps(payload))

        # Encrypt ChaCha20 key and nonce with the representative's public key
        public_key_path = state['REP_PUB_KEY']
        encrypted_key = encrypt_with_public_key(public_key_path, key)
        encrypted_nonce = encrypt_with_public_key(public_key_path, nonce)

        # Prepare the JSON for the headers
        encryption_header = {
            "key": encrypted_key.hex(),
            "nonce": encrypted_nonce.hex()
        }
        headers = {
            "X-Encrypted-Key-Info": json.dumps(encryption_header)  # Send JSON as a string in the header
        }

        # Send the request
        url = f"http://{state['REP_ADDRESS']}/organizations"
        response = requests.post(url, json={"encrypted_payload": encrypted_payload.hex()}, headers=headers)

        # Check response status
        if response.status_code == 201:
            logger.info("Organization created successfully.")
            return {"status": "success", "message": "Organization created successfully."}
        else:
            logger.error(f"Failed to create organization: {response.status_code} - {response.text}")
            return {"status": "error", "message": response.text}

    except FileNotFoundError:
        logger.error("Public key file not found.")
        return {"status": "error", "message": "Public key file not found."}
    except ValueError as ve:
        logger.error(f"Error processing public key: {str(ve)}")
        return {"status": "error", "message": str(ve)}
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return {"status": "error", "message": str(e)}


from cryptography.hazmat.primitives.serialization import load_pem_private_key
def create_session(data, session_file):
    """
    Cria uma sessão e criptografa a chave de sessão com uma chave pública RSA.
    """
    import json
    import requests

    with open(data['credentials_file'], 'r') as cred_file:
        credentials = json.load(cred_file)  # Parse JSON content
        private_key_pem = credentials.get("private_key")  # Extract the private key

        if not private_key_pem:
            raise ValueError("Private key is missing in the credentials file.")

        # Load the private key
        private_key = load_pem_private_key(
            private_key_pem.encode(),
            password=None,  # No password encryption for the key in this example
            backend=default_backend()
        )

    # Generate a random nonce
    nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    #print(nonce)
    # Sign the nonce with the private key
    signature = private_key.sign(
        nonce.encode(),  # Encode the nonce as bytes
        ec.ECDSA(hashes.SHA256())  # Use ECDSA with SHA256 for signing
    )

    # Print the signed nonce in a readable format (e.g., hex)
    signed_nonce = signature.hex()
    #print(f"\nSigned nonce: {signed_nonce}")

    # Prepare the payload
    payload = {
        "username": data['username'],
        "organization_name": data['organization'],
        "password": data['password'],
        "credentials": credentials,
        "nonce": nonce,
        "signed_nonce": signed_nonce
    }

    # Envia o payload para criar uma sessão
    url = f"http://{state['REP_ADDRESS']}/sessions"


    key = os.urandom(32)
    nonce = os.urandom(16)

    encrypted_payload = encrypt_with_chacha20(key, nonce, json.dumps(payload))

    # Encrypt ChaCha20 key and nonce with the public key
    public_key_path = state['REP_PUB_KEY']
    encrypted_key = encrypt_with_public_key(public_key_path, key)
    encrypted_nonce = encrypt_with_public_key(public_key_path, nonce)

    # Prepare the JSON for the headers


    encryption_header = {
        "key": encrypted_key.hex(),
        "nonce": encrypted_nonce.hex()
    }
    headers = {
        #"X-Nonce": encrypted_nonce_header.hex(),
        "X-Encrypted-Key-Info": json.dumps(encryption_header)  # Send JSON as a string in the header
    }

    response = requests.post(url, json={"encrypted_payload": encrypted_payload.hex()}, headers=headers)

    if response.status_code == 201:
        # Obtém a resposta e criptografa a session_key
        response_data = response.json()
        #session_key = response_data["session_context"]["session_token"]

        ### Nao encryptar aq :

        '''
        # Usa o caminho para a chave pública
        public_key_path = "../public_key.pem"
        encrypted_session_key = encrypt_session_key(session_key, public_key_path)

        # Substitui a chave de sessão pela versão criptografada
        response_data["session_context"]["session_key"] = encrypted_session_key'''

        # Salva a resposta atualizada no arquivo de sessão
        with open(session_file, 'w') as file:
            json.dump(response_data, file, indent=4)
        return 0
    else:
        # Caso falhe na criação da sessão
        print(f"Failed to create session: {response.json()}{response.status_code}")
        return 1


def download_file(filename):
    url = f"http://{state['REP_ADDRESS']}/download/{filename}"
    response = requests.get(url)
    if response.status_code == 200:
        with open(filename, 'wb') as f:
            f.write(response.content)
        logger.info(f"File '{filename}' downloaded successfully.")
    else:
        logger.error(f"Failed to download file '{filename}': {response.status_code}")


def add_subject(data, session_file):
    url = f"http://{state['REP_ADDRESS']}/add_subject"

    # Carrega o arquivo de sessão para obter a session_key
    with open(session_file, 'r') as session_file_handle:
        session_data = json.load(session_file_handle)
        session_key = session_data["session_context"]["session_token"].encode('utf-8')  # Garantir que está como bytes

    # Carrega as credenciais do arquivo
    with open(data['credentials_file'], 'r') as cred_file:
        credentials = json.load(cred_file)

    # Gerar chave e nonce ChaCha20
    chacha_key = os.urandom(32)  # 32 bytes para a chave
    chacha_nonce = os.urandom(16)  # 16 bytes para o nonce

    # Criptografar o payload com ChaCha20
    payload = {
        "username": data['username'],
        "name": data['name'],
        "email": data['email'],
        "public_key": credentials.get("public_key"),
        #"credentials": credentials
    }
    payload_json = json.dumps(payload)  # Serializa e converte para bytes
    encrypted_payload = encrypt_with_chacha20(chacha_key, chacha_nonce, payload_json)

    # Criptografar o session_key com ChaCha20
    encrypted_session_key = encrypt_with_chacha20(chacha_key, chacha_nonce, session_key)

    # Criptografar a chave e o nonce do ChaCha20 com a chave pública
    public_key_path = state['REP_PUB_KEY']
    encrypted_key = encrypt_with_public_key(public_key_path, chacha_key)
    encrypted_nonce = encrypt_with_public_key(public_key_path, chacha_nonce)

    # Gerar um nonce único para o cabeçalho
    nonce_header = session_data["session_context"]["nonce"].encode('utf-8')

    # Define os cabeçalhos para incluir a session_key e o nonce
    headers = {
        "X-Session-Key": binascii.hexlify(encrypted_session_key).decode(),
        "X-Nonce": nonce_header,
        "X-Encrypted-Key": binascii.hexlify(encrypted_key).decode(),
        "X-Encrypted-Nonce": binascii.hexlify(encrypted_nonce).decode(),
    }

    # Faz a requisição POST com os cabeçalhos e o payload criptografado
    response = requests.post(url, data=binascii.hexlify(encrypted_payload), headers=headers)

    # Atualiza o nonce no arquivo de sessão com o new_nonce retornado
    response_data = response.json()
    print(response_data)
    new_nonce = response_data.get("new_nonce")

    if new_nonce:
        session_data["session_context"]["nonce"] = new_nonce
        with open(session_file, 'w') as session_file_handle:
            json.dump(session_data, session_file_handle, indent=4)
    if response.status_code != 201:
        return 1

    return 0



def get_document_metadata(session_file, document_name):
    # URL do endpoint para obter metadados do documento
    url = f"http://{state['REP_ADDRESS']}/document/metadata"
    true_doc_name = document_name
    # Abrir o arquivo de sessão para ler o session_key
    with open(session_file, 'r') as session_file:
        session_data = json.load(session_file)
        session_key = session_data["session_context"]["session_token"]
    key = os.urandom(32)
    nonce = os.urandom(16)


    # Encrypt ChaCha20 key and nonce with the public key
    public_key_path = state['REP_PUB_KEY']
    encrypted_key = encrypt_with_public_key(public_key_path, key)
    encrypted_nonce = encrypt_with_public_key(public_key_path, nonce)
    encryption_header = {
        "key": encrypted_key.hex(),
        "nonce": encrypted_nonce.hex()
    }
    # Prepare the JSON for the headers
    '''nonce_header = str(uuid.uuid4())
    encrypted_nonce_header = encrypt_with_chacha20(key, nonce, nonce_header)'''
    session_key = encrypt_with_chacha20(key, nonce, session_key)

    headers = {
        "X-Session-Key": binascii.hexlify(session_key).decode(),
        #"X-Nonce": encrypted_nonce_header.hex(),
        "X-Encrypted-Key-Info": json.dumps(encryption_header)
    }
    document_name = encrypt_with_chacha20(key, nonce,
             document_name)
    #print(binascii.hexlify(document_name).decode())
    params = {'document_name': binascii.hexlify(document_name).decode()}

    # Enviar requisição GET para o endpoint de metadados do documento
    response = requests.get(url, headers=headers, params=params)

    # Checar se a resposta foi bem-sucedida
    if response.status_code == 200:
        response_data = response.json()

        # Acessar os metadados corretos
        metadata = response_data.get("metadata", {})

        # Extrair `file_key` e `encryption_vars`
        encryption_data = {
            "file_key": metadata.get("file_key"),
            "encryption_vars": metadata.get("encryption_vars"),
        }

        # Nome do arquivo de saída
        output_file = f"{true_doc_name}_encryption_data.json"

        # Salvar os dados de criptografia no arquivo JSON
        with open(output_file, 'w') as file:
            json.dump(encryption_data, file, indent=4)

        print(f"Encryption data salvo em: {output_file}")
        return metadata
    else:
        print(f"Erro ao obter metadados: {response.status_code} - {response.text}")



import requests


def download_document(file_handle, file=None):
    """
    Faz o download de um documento criptografado e imprime o conteúdo como string.
    Se o arquivo estiver criptografado, exibe os dados binários como string.

    :param file_handle: Identificador do arquivo no servidor.
    :param file: Caminho opcional para salvar o arquivo baixado.
    :return: JSON com metadados ou None.
    """

    key = os.urandom(32)
    nonce = os.urandom(16)
    public_key_path = state['REP_PUB_KEY']
    encrypted_key = encrypt_with_public_key(public_key_path, key)
    encrypted_nonce = encrypt_with_public_key(public_key_path, nonce)
    #nonce_header = session_data["session_context"]["nonce"].encode('utf-8')  # Exemplo de nonce único
    #encrypted_nonce_header = encrypt_with_chacha20(key, nonce, nonce_header)
    encrypted_fh = encrypt_with_chacha20(key, nonce, file_handle)
    url = f"http://{state['REP_ADDRESS']}/download/{encrypted_fh.hex()}"

    encryption_header = {
        "key": encrypted_key.hex(),
        "nonce": encrypted_nonce.hex()
    }
    headers = {
        #"X-Nonce": encrypted_nonce_header.hex(),
        "X-Encrypted-Key-Info": json.dumps(encryption_header)
    }
    response = requests.get(url, headers=headers)

    # Verifica se o download foi bem-sucedido
    if response.status_code != 200:
        print(f"Erro ao baixar o arquivo: {response.status_code}")
        return None

    # Tenta interpretar a resposta como JSON
    try:
        # Retorna JSON se a resposta contiver metadados
        return response.json()
    except requests.exceptions.JSONDecodeError:
        # Se falhar, assume que é um arquivo binário
        pass

    # Salva o conteúdo do arquivo em disco, se necessário
    if file:
        with open(file, 'wb') as f:
            f.write(response.content)
        print(f"Arquivo salvo como: {file}")

    # Tenta converter o conteúdo binário em string
    try:
        content_as_string = response.content.decode('utf-8')  # Supondo que o conteúdo é texto UTF-8
        print("\nConteúdo do arquivo como string:")
        print(content_as_string)
    except UnicodeDecodeError:
        # Se não puder ser decodificado, exibe a representação hexadecimal
        print("\nConteúdo não é texto legível. Mostrando como hexadecimal:")
        print(response.content.hex())

    return 0


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json

def decrypt_file(encrypted_file, encryption_metadata_file):
    """
    Descriptografa um arquivo criptografado usando os metadados fornecidos.

    :param encrypted_file: Caminho para o arquivo criptografado.
    :param encryption_metadata_file: Caminho para o arquivo JSON contendo os metadados de criptografia.
    :return: O caminho do arquivo descriptografado.
    """
    try:
        # Ler o arquivo de metadados
        with open(encryption_metadata_file, 'r') as meta_file:
            metadata = json.load(meta_file)

        # Obter a chave e os parâmetros do algoritmo dos metadados
        file_key = bytes.fromhex(metadata.get("file_key"))
        encryption_vars = json.loads(metadata.get("encryption_vars"))
        alg = encryption_vars.get("alg")

        if not file_key or not alg:
            raise ValueError("Metadados incompletos: 'file_key' ou 'alg' ausentes.")

        # Configurar o algoritmo de descriptografia com base em `alg`
        if alg == "ChaCha20":
            nonce = bytes.fromhex(encryption_vars.get("nonce"))
            if not nonce:
                raise ValueError("Metadados incompletos: 'nonce' ausente para ChaCha20.")
            algorithm = algorithms.ChaCha20(file_key, nonce)
            cipher = Cipher(algorithm, mode=None)

        elif alg == "AES-GCM":
            nonce = bytes.fromhex(encryption_vars.get("nonce"))
            tag = bytes.fromhex(encryption_vars.get("tag"))
            if not nonce or not tag:
                raise ValueError("Metadados incompletos: 'nonce' ou 'tag' ausentes para AES-GCM.")
            algorithm = algorithms.AES(file_key)
            cipher = Cipher(algorithm, mode=modes.GCM(nonce, tag))

        elif alg == "AES-CBC":
            iv = bytes.fromhex(encryption_vars.get("iv"))
            if not iv:
                raise ValueError("Metadados incompletos: 'iv' ausente para AES-CBC.")
            algorithm = algorithms.AES(file_key)
            cipher = Cipher(algorithm, mode=modes.CBC(iv))

        else:
            raise ValueError(f"Algoritmo de criptografia '{alg}' não suportado.")

        # Criar o decodificador
        decryptor = cipher.decryptor()

        # Ler o conteúdo do arquivo criptografado
        with open(encrypted_file, 'rb') as enc_file:
            encrypted_data = enc_file.read()

        # Descriptografar os dados
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        print(decrypted_data.decode("utf-8"))
        # Definir o caminho de saída para o arquivo descriptografado
        output_file = f"{os.path.splitext(encrypted_file)[0]}_decrypted"
        with open(output_file, 'wb') as out_file:
            out_file.write(decrypted_data)

        print(f"Arquivo descriptografado salvo em: {output_file}")
        return output_file

    except Exception as e:
        print(f"Erro durante a descriptografia: {e}")
        raise




def encrypt_file_with_chacha20(file_data):
    chacha_key = os.urandom(32)  # 256-bit ChaCha20 key
    nonce = os.urandom(16)  # 128-bit nonce
    cipher = Cipher(algorithms.ChaCha20(chacha_key, nonce), mode=None)
    encryptor = cipher.encryptor()

    encrypted_file_data = encryptor.update(file_data) + encryptor.finalize()
    return encrypted_file_data, chacha_key, nonce


def upload_document(data):
    url = f"http://{state['REP_ADDRESS']}/add_document"

    # Carrega o arquivo de sessão para obter a session_key
    with open(data['session_file'], 'r') as session_file:
        session_data = json.load(session_file)
        session_key = session_data["session_context"]["session_token"]

    # Carrega e criptografa o arquivo
    with open(data['file'], 'rb') as file:
        file_data = file.read()

    # Usa ChaCha20 para criptografar
    encrypted_file_data, chacha_key, nonce = encrypt_file_with_chacha20(file_data)
    file_handle = hashlib.sha256(encrypted_file_data).hexdigest()

    # Cria o dicionário para 'encryption_vars'
    encryption_vars = {
        'nonce': nonce.hex(),
        'alg': "ChaCha20"
    }

    # Define os cabeçalhos para enviar a session_key
    nonce = session_data["session_context"]["nonce"].encode('utf-8')
    headers = {
        "X-Session-Key": session_key,
        "X-Nonce": nonce
    }

    # Faz a requisição POST para enviar o documento criptografado
    response = requests.post(
        url,
        files={'file': encrypted_file_data},
        data={
            'file_name': data['document_name'],  # Nome do documento
            'file_handle': file_handle,
            'file_encryption_key': chacha_key.hex(),
            'encryption_vars': json.dumps(encryption_vars)  # Converte para JSON string
        },
        headers=headers  # Inclui os cabeçalhos com a session_key
    )

    if response.status_code == 201 or response.status_code == 200:
        # Atualiza o nonce no arquivo de sessão com o new_nonce retornado
        response_data = response.json()
        #print(response_data)

        new_nonce = response_data.get("new_nonce")

        if new_nonce:
            session_data["session_context"]["nonce"] = new_nonce
            with open(data['session_file'], 'w') as session_file_handle:
                json.dump(session_data, session_file_handle, indent=4)
    else:
        print(response.json())
        return 1

    return 0


def get_documents(data):
    # Carrega o arquivo de sessão para obter a session_key
    with open(data['session_file'], 'r') as session_file:
        session_data = json.load(session_file)
        session_key = session_data["session_context"]["session_token"]
        # Gera a chave e o nonce para ChaCha20
    key = os.urandom(32)
    nonce = os.urandom(16)
    # Configura os parâmetros da URL com os argumentos opcionais
    params = {}
    if data["username"]:
        params["username"] = encrypt_with_chacha20(key, nonce, data["username"].encode('utf-8')).hex()
    if data["date"]:
        params["date"] = encrypt_with_chacha20(key, nonce, data["date"].encode('utf-8')).hex()

    #print(params)
    url = f"http://{state['REP_ADDRESS']}/sessions/documents"



    # Criptografa os parâmetros e a session_key
    encrypted_params = encrypt_with_chacha20(key, nonce, json.dumps(params).encode('utf-8'))
    encrypted_session_key = encrypt_with_chacha20(key, nonce, session_key.encode('utf-8'))

    # Criptografa a chave e o nonce com a chave pública do servidor
    encrypted_key = encrypt_with_public_key(state['REP_PUB_KEY'], key)
    encrypted_nonce = encrypt_with_public_key(state['REP_PUB_KEY'], nonce)
    encryption_header = {
        "key": encrypted_key.hex(),
        "nonce": encrypted_nonce.hex()
    }

    # Configura os cabeçalhos
    headers = {
        "X-Session-Key": encrypted_session_key.hex(),
        "X-Encrypted-Key-Info": json.dumps(encryption_header)
    }

    # Envia os parâmetros criptografados como dados no corpo da requisição
    response = requests.get(url, headers=headers, data=params)
    #print(response.json())
    # Retorna a resposta em formato JSON
    return response.json()




def delete_document(session_file, document_name):
    # Carrega o arquivo de sessão para obter o session_key
    with open(session_file, 'r') as session_file_handle:
        session_data = json.load(session_file_handle)
        session_key = session_data["session_context"]["session_token"]

    # URL do endpoint para deletar o documento


    key = os.urandom(32)
    nonce = os.urandom(16)

    nonce_header = session_data["session_context"]["nonce"].encode('utf-8')
    encrypted_nonce_header = encrypt_with_chacha20(key, nonce, nonce_header)
    encrypted_session_key = encrypt_with_chacha20(key, nonce, session_key)

    public_key_path = state['REP_PUB_KEY']
    encrypted_key = encrypt_with_public_key(public_key_path, key)
    encrypted_nonce = encrypt_with_public_key(public_key_path, nonce)

    enc_doc_name = encrypt_with_chacha20(key, nonce, document_name)

    encryption_header = {
        "key": encrypted_key.hex(),
        "nonce": encrypted_nonce.hex()
    }
    headers = {
        "X-Nonce": encrypted_nonce_header.hex(),
        "X-Session-Key": binascii.hexlify(encrypted_session_key).decode(),
        "X-Encrypted-Key-Info": json.dumps(encryption_header)  # Send JSON as a string in the header
    }

    url = f"http://{state['REP_ADDRESS']}/delete_document/{enc_doc_name.hex()}"

    # Enviar requisição DELETE para o endpoint de deletar o documento
    response = requests.delete(url, headers=headers)

    response_data = response.json()
    print(response_data)
    new_nonce = response_data.get("new_nonce")

    if new_nonce:
        session_data["session_context"]["nonce"] = new_nonce
        with open(session_file, 'w') as session_file_handle:
            json.dump(session_data, session_file_handle, indent=4)

    return response




def list_subjects(session_file, username=None):
    """
    Modifica a session_key para incluir um nonce antes de criptografá-la.
    """
    # Carregar os dados do arquivo da sessão
    with open(session_file, 'r') as file:
        session_data = json.load(file)
        session_key = session_data["session_context"]["session_token"]


    # Definir a URL do servidor
    url = f"http://{state['REP_ADDRESS']}/sessions/subjects"

    key = os.urandom(32)
    nonce = os.urandom(16)

    public_key_path = state['REP_PUB_KEY']
    encrypted_key = encrypt_with_public_key(public_key_path, key)
    encrypted_nonce = encrypt_with_public_key(public_key_path, nonce)

    # Prepare the JSON for the headers
    #nonce_header = str(uuid.uuid4())
    #encrypted_nonce_header = encrypt_with_chacha20(key, nonce, nonce_header)
    encrypted_session_key = encrypt_with_chacha20(key, nonce, session_key)

    encryption_header = {
        "key": encrypted_key.hex(),
        "nonce": encrypted_nonce.hex()
    }
    headers = {
        #"X-Nonce": encrypted_nonce_header.hex(),
        "X-Session-Key": binascii.hexlify(encrypted_session_key).decode(),
        "X-Encrypted-Key-Info": json.dumps(encryption_header)  # Send JSON as a string in the header
    }

    # Enviar a requisição GET com a session_key e nonce no cabeçalho
    response = requests.get(url, headers=headers)

    # Retornar a resposta em formato JSON
    return response.json()


def gen_subject_file(password, credentials_file):
    # Derive a seed from the password
    salt = os.urandom(16)  # Random salt for key derivation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Length of the derived seed
        salt=salt,
        iterations=100_000,
    )
    seed = kdf.derive(password.encode())  # Generate seed from password

    # Use the seed to generate an ECC private key deterministically
    private_key = ec.derive_private_key(int.from_bytes(seed, byteorder="big"), ec.SECP256R1())
    public_key = private_key.public_key()

    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode('utf-8')

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')

    # Save the keys and salt in a JSON file
    credentials_data = {
        "public_key": public_pem,
        "private_key": private_pem,
        "salt": salt.hex(),  # Save salt for future regeneration of keys
    }

    with open(credentials_file, "w") as cred_file:
        json.dump(credentials_data, cred_file, indent=4)

    print("Keys generated and saved in JSON format.")
def load_state():
    state = {}
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    logger.debug('State folder: ' + state_dir)
    logger.debug('State file: ' + state_file)

    if os.path.exists(state_file):
        logger.debug('Loading state')
        with open(state_file,'r') as f:
            state = json.loads(f.read())

    if state is None:
        state = {}

    return state

def parse_env(state):
    if 'REP_ADDRESS' in os.environ:
        state['REP_ADDRESS'] = os.getenv('REP_ADDRESS')
        logger.info('Setting REP_ADDRESS from Environment to: ' )
        #print('Setting REP_ADDRESS from Environment to: ' + state['REP_ADDRESS'])



    if 'REP_PUB_KEY' in os.environ:
        rep_pub_key = os.getenv('REP_PUB_KEY')
        logger.info('Loading REP_PUB_KEY from env variable: ' )
        #print('Loading REP_PUB_KEY from env variable: ' )
        if os.path.exists(rep_pub_key):
            with open(rep_pub_key, 'r') as f:
                state['REP_PUB_KEY'] = f.read()
                logger.debug('Loaded REP_PUB_KEY from Environment')

    return state


def parse_args(state):
    parser = argparse.ArgumentParser()

    # Define o argumento principal 'command' e os argumentos opcionais
    parser.add_argument("command", choices=["rep_list_orgs",
                                            "rep_create_org", "rep_create_session",
                                            "download_file", "rep_get_doc_metadata",
                                            "rep_list_docs",
                                            "rep_add_subject", "rep_list_subjects",  # Added missing comma
                                            "rep_add_doc", "rep_get_file","rep_delete_doc",
                                            "rep_subject_credentials", "rep_decrypt_file",
                                            "rep_list_roles", "rep_add_role", "rep_assume_role","rep_drop_role",
                                            "rep_add_permission", "rep_remove_permission",
                                            "rep_suspend_role","rep_reactivate_role"], help="Command to execute")
    parser.add_argument("-k", '--key', nargs=1, help="Path to the key file")
    parser.add_argument("-r", '--repo', nargs=1, help="Address:Port of the repository")
    parser.add_argument("-v", '--verbose', help="Increase verbosity", action="store_true")


    # Parse os argumentos até o comando (ignora os argumentos específicos do comando)
    args, unknown_args = parser.parse_known_args()

    if args.key:
        if not os.path.exists(args.key[0]) or not os.path.isfile(args.key[0]):
            logger.error(f'Key file not found or invalid: {args.key[0]}')
            sys.exit(-1)

        with open(args.key[0], 'r') as f:
            state['REP_PUB_KEY'] = f.read()
            logger.info('Overriding REP_PUB_KEY from command line')

    if args.repo:
        state['REP_ADDRESS'] = args.repo[0]
        logger.info('Overriding REP_ADDRESS from command line')

    # Configura o nível de verbosidade
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.info('Setting log level to DEBUG')

    # Sub-parser para argumentos específicos do comando
    command_parser = argparse.ArgumentParser()

    if args.command =="rep_list_roles":
        command_parser.add_argument("session_file", help="Path to session file")

    if args.command =="rep_add_role":
        command_parser.add_argument("session_file", help="Path to session file")
        command_parser.add_argument("role", help="new role to be craeted")


    if args.command =="rep_assume_role":
        command_parser.add_argument("session_file", help="Path to session file")
        command_parser.add_argument("role", help="role to be assumed")


    if args.command =="rep_drop_role":
        command_parser.add_argument("session_file", help="Path to session file")
        command_parser.add_argument("role", help="role to be released")

    if args.command =="rep_suspend_role":
        command_parser.add_argument("session_file", help="Path to session file")
        command_parser.add_argument("role", help="role to be suspended")

    if args.command =="rep_reactivate_role":
        command_parser.add_argument("session_file", help="Path to session file")
        command_parser.add_argument("role", help="role to be reactivated")



    if args.command =="rep_add_permission":
        command_parser.add_argument("session_file", help="Path to session file")
        command_parser.add_argument("role", help="role to be released")
        command_parser.add_argument("permission_username", help="role to be released")

    if args.command =="rep_remove_permission":
        command_parser.add_argument("session_file", help="Path to session file")
        command_parser.add_argument("role", help="role to be released")
        command_parser.add_argument("permission_username", help="role to be released")

    if args.command == "rep_subject_credentials":
        command_parser.add_argument("password", help="Password to generate the key")
        command_parser.add_argument("credentials_file", help="file to store the key")

    elif args.command == "rep_decrypt_file":
        command_parser.add_argument("encrypted_file", help="FIle to be decrypted")
        command_parser.add_argument("encryption_metadata_file", help="Data used to decrypt file")

    if args.command == "rep_create_org":
        command_parser.add_argument("organization", help="Organization ID")
        command_parser.add_argument("username", help="Username for the organization admin")
        command_parser.add_argument("name", help="Name of the organization")
        command_parser.add_argument("email", help="Email of the organization")
        command_parser.add_argument("public_key_file", help="Path to the public key file for the organization")

    if args.command == "rep_create_session":

        command_parser.add_argument("organization", help="Organization name")

        command_parser.add_argument("username", help="Username for the session")

        command_parser.add_argument("password", help="Password for the session")

        #command_parser.add_argument("key", help="key for the session")

        command_parser.add_argument("credentials_file", help="Path to the credentials file")

        command_parser.add_argument("session_file", help="Path to save the session file")




    elif args.command == "rep_get_doc_metadata":
        command_parser.add_argument("session_file", help="Path to session file")
        command_parser.add_argument("document_name", help="Document name")

    elif args.command == "rep_add_doc":
        command_parser.add_argument("session_file", help="Path to session file")
        command_parser.add_argument("document_name", help="Document name")
        command_parser.add_argument("file", help="Path to file encrypted file")

    elif args.command == "rep_list_docs":
        command_parser.add_argument("session_file", help="Path to session file")
        command_parser.add_argument("-s", "--username", help="Username filter (optional)")
        command_parser.add_argument(
            "-d", "--date",
            help="Date filter with type (format: 'nt YYYY-MM-DD' for new, 'ot YYYY-MM-DD' for old, 'et YYYY-MM-DD' for exact)"
        )

    elif args.command == "rep_delete_doc":
        command_parser.add_argument("session_file", help="Path to session file")
        command_parser.add_argument("document_name", help="Document name")

    if args.command == "rep_add_subject":
        command_parser.add_argument("session_file", help="Path to session file")
        command_parser.add_argument("username", help="Username for the organization admin")
        command_parser.add_argument("name", help="Name of the organization")
        command_parser.add_argument("email", help="Email of the organization")
        #command_parser.add_argument("key", help="key of the subject")
        command_parser.add_argument("credentials_file", help="Path to the credentials file")

    if args.command == "rep_get_file":
        command_parser.add_argument("file_handle", help="File Handle to download the file")
        command_parser.add_argument(
            "-f", "--file",
            help="File to save the document (optional)",
            default=None
        )


    elif args.command == "rep_list_subjects":
        command_parser.add_argument("session_file", help="Path to session file")
        command_parser.add_argument("-s", "--username", help="Username filter (optional)")


    # Analisa os argumentos específicos do comando usando unknown_args

    command_args = command_parser.parse_args(unknown_args)

    # Retorna o estado, os argumentos principais e os argumentos do comando específico
    return state, args, command_args


state = load_state()
state = parse_env(state)
state, args, command_args = parse_args(state)

if 'REP_ADDRESS' not in state:
  logger.error("Must define Repository Address")
  sys.exit(-1)

if 'REP_PUB_KEY' not in state:
  logger.error("Must set the Repository Public Key")
  sys.exit(-1)

if args.command == "rep_add_permission":
    session_file = command_args.session_file
    with open(session_file, 'r') as file:
        session_data = json.load(file)
        session_key = session_data["session_context"]["session_token"]
    role = command_args.role
    username_or_permission = command_args.permission_username

    if username_or_permission.isupper():
        print(f"Requesting adding permission {username_or_permission} to {role}")
        url = f"http://{state['REP_ADDRESS']}//organization/roles/add_permission"
        key = os.urandom(32)
        nonce = os.urandom(16)

        public_key_path = state['REP_PUB_KEY']
        encrypted_key = encrypt_with_public_key(public_key_path, key)
        encrypted_nonce = encrypt_with_public_key(public_key_path, nonce)

        encrypted_session_key = encrypt_with_chacha20(key, nonce, session_key)
        encrypted_role = encrypt_with_chacha20(key, nonce, role)
        encrypted_permission = encrypt_with_chacha20(key, nonce, username_or_permission)

        encryption_header = {
            "key": encrypted_key.hex(),
            "nonce": encrypted_nonce.hex()
        }
        headers = {
            # "X-Nonce": encrypted_nonce_header.hex(),
            "X-Session-Key": binascii.hexlify(encrypted_session_key).decode(),
            "role": binascii.hexlify(encrypted_role).decode(),
            "permission": binascii.hexlify(encrypted_permission).decode(),
            "X-Encrypted-Key-Info": json.dumps(encryption_header)  # Send JSON as a string in the header
        }

        response = requests.post(url, headers=headers)

        print(response.json())
    else:
        print(f"Requesting giving access of role {role} to {username_or_permission}")
        url = f"http://{state['REP_ADDRESS']}//organization/roles/add_access"
        key = os.urandom(32)
        nonce = os.urandom(16)

        public_key_path = state['REP_PUB_KEY']
        encrypted_key = encrypt_with_public_key(public_key_path, key)
        encrypted_nonce = encrypt_with_public_key(public_key_path, nonce)

        encrypted_session_key = encrypt_with_chacha20(key, nonce, session_key)
        encrypted_role = encrypt_with_chacha20(key, nonce, role)
        encrypted_username = encrypt_with_chacha20(key, nonce, username_or_permission)

        encryption_header = {
            "key": encrypted_key.hex(),
            "nonce": encrypted_nonce.hex()
        }
        headers = {
            # "X-Nonce": encrypted_nonce_header.hex(),
            "X-Session-Key": binascii.hexlify(encrypted_session_key).decode(),
            "role": binascii.hexlify(encrypted_role).decode(),
            "username": binascii.hexlify(encrypted_username).decode(),
            "X-Encrypted-Key-Info": json.dumps(encryption_header)  # Send JSON as a string in the header
        }

        response = requests.post(url, headers=headers)

        print(response.json())




if args.command == "rep_remove_permission":
    session_file = command_args.session_file
    with open(session_file, 'r') as file:
        session_data = json.load(file)
        session_key = session_data["session_context"]["session_token"]
    role = command_args.role
    username_or_permission = command_args.permission_username
    if username_or_permission.isupper():
        print(f"Requesting removinh permission {username_or_permission} to {role}")
        url = f"http://{state['REP_ADDRESS']}//organization/roles/remove_permission"
        key = os.urandom(32)
        nonce = os.urandom(16)

        public_key_path = state['REP_PUB_KEY']
        encrypted_key = encrypt_with_public_key(public_key_path, key)
        encrypted_nonce = encrypt_with_public_key(public_key_path, nonce)

        encrypted_session_key = encrypt_with_chacha20(key, nonce, session_key)
        encrypted_role = encrypt_with_chacha20(key, nonce, role)
        encrypted_permission = encrypt_with_chacha20(key, nonce, username_or_permission)

        encryption_header = {
            "key": encrypted_key.hex(),
            "nonce": encrypted_nonce.hex()
        }
        headers = {
            # "X-Nonce": encrypted_nonce_header.hex(),
            "X-Session-Key": binascii.hexlify(encrypted_session_key).decode(),
            "role": binascii.hexlify(encrypted_role).decode(),
            "permission": binascii.hexlify(encrypted_permission).decode(),
            "X-Encrypted-Key-Info": json.dumps(encryption_header)  # Send JSON as a string in the header
        }

        response = requests.post(url, headers=headers)

        print(response.json())
    else:
        print(f"Requesting removing access of role {role} to {username_or_permission}")
        url = f"http://{state['REP_ADDRESS']}//organization/roles/remove_access"
        key = os.urandom(32)
        nonce = os.urandom(16)

        public_key_path = state['REP_PUB_KEY']
        encrypted_key = encrypt_with_public_key(public_key_path, key)
        encrypted_nonce = encrypt_with_public_key(public_key_path, nonce)

        encrypted_session_key = encrypt_with_chacha20(key, nonce, session_key)
        encrypted_role = encrypt_with_chacha20(key, nonce, role)
        encrypted_username = encrypt_with_chacha20(key, nonce, username_or_permission)

        encryption_header = {
            "key": encrypted_key.hex(),
            "nonce": encrypted_nonce.hex()
        }
        headers = {
            # "X-Nonce": encrypted_nonce_header.hex(),
            "X-Session-Key": binascii.hexlify(encrypted_session_key).decode(),
            "role": binascii.hexlify(encrypted_role).decode(),
            "username": binascii.hexlify(encrypted_username).decode(),
            "X-Encrypted-Key-Info": json.dumps(encryption_header)  # Send JSON as a string in the header
        }

        response = requests.post(url, headers=headers)

        print(response.json())

if args.command == "rep_suspend_role":
    session_file = command_args.session_file
    role = command_args.role
    with open(session_file, 'r') as file:
        session_data = json.load(file)
        session_key = session_data["session_context"]["session_token"]

        # Definir a URL do servidor
        url = f"http://{state['REP_ADDRESS']}//organization/roles/suspend_role"

        key = os.urandom(32)
        nonce = os.urandom(16)

        public_key_path = state['REP_PUB_KEY']
        encrypted_key = encrypt_with_public_key(public_key_path, key)
        encrypted_nonce = encrypt_with_public_key(public_key_path, nonce)

        # Prepare the JSON for the headers
        # nonce_header = str(uuid.uuid4())
        # encrypted_nonce_header = encrypt_with_chacha20(key, nonce, nonce_header)
        encrypted_session_key = encrypt_with_chacha20(key, nonce, session_key)
        encrypted_role = encrypt_with_chacha20(key, nonce, role)

        encryption_header = {
            "key": encrypted_key.hex(),
            "nonce": encrypted_nonce.hex()
        }
        headers = {
            # "X-Nonce": encrypted_nonce_header.hex(),
            "X-Session-Key": binascii.hexlify(encrypted_session_key).decode(),
            "role": binascii.hexlify(encrypted_role).decode(),
            "X-Encrypted-Key-Info": json.dumps(encryption_header)  # Send JSON as a string in the header
        }

        # Enviar a requisição GET com a session_key e nonce no cabeçalho
        response = requests.post(url, headers=headers)

        # Retornar a resposta em formato JSON
        print(response.json())

if args.command == "rep_reactivate_role":
    session_file = command_args.session_file
    role = command_args.role
    with open(session_file, 'r') as file:
        session_data = json.load(file)
        session_key = session_data["session_context"]["session_token"]

        # Definir a URL do servidor
        url = f"http://{state['REP_ADDRESS']}//organization/roles/reactivate_role"

        key = os.urandom(32)
        nonce = os.urandom(16)

        public_key_path = state['REP_PUB_KEY']
        encrypted_key = encrypt_with_public_key(public_key_path, key)
        encrypted_nonce = encrypt_with_public_key(public_key_path, nonce)

        # Prepare the JSON for the headers
        # nonce_header = str(uuid.uuid4())
        # encrypted_nonce_header = encrypt_with_chacha20(key, nonce, nonce_header)
        encrypted_session_key = encrypt_with_chacha20(key, nonce, session_key)
        encrypted_role = encrypt_with_chacha20(key, nonce, role)

        encryption_header = {
            "key": encrypted_key.hex(),
            "nonce": encrypted_nonce.hex()
        }
        headers = {
            # "X-Nonce": encrypted_nonce_header.hex(),
            "X-Session-Key": binascii.hexlify(encrypted_session_key).decode(),
            "role": binascii.hexlify(encrypted_role).decode(),
            "X-Encrypted-Key-Info": json.dumps(encryption_header)  # Send JSON as a string in the header
        }

        # Enviar a requisição GET com a session_key e nonce no cabeçalho
        response = requests.post(url, headers=headers)

        # Retornar a resposta em formato JSON
        print(response.json())

if args.command == "rep_assume_role":
    session_file = command_args.session_file
    role = command_args.role
    with open(session_file, 'r') as file:
        session_data = json.load(file)
        session_key = session_data["session_context"]["session_token"]

    # Definir a URL do servidor
    url = f"http://{state['REP_ADDRESS']}//sessions/assume_role"

    key = os.urandom(32)
    nonce = os.urandom(16)

    public_key_path = state['REP_PUB_KEY']
    encrypted_key = encrypt_with_public_key(public_key_path, key)
    encrypted_nonce = encrypt_with_public_key(public_key_path, nonce)

    # Prepare the JSON for the headers
    # nonce_header = str(uuid.uuid4())
    # encrypted_nonce_header = encrypt_with_chacha20(key, nonce, nonce_header)
    encrypted_session_key = encrypt_with_chacha20(key, nonce, session_key)
    encrypted_role =  encrypt_with_chacha20(key, nonce, role)


    encryption_header = {
        "key": encrypted_key.hex(),
        "nonce": encrypted_nonce.hex()
    }
    headers = {
        # "X-Nonce": encrypted_nonce_header.hex(),
        "X-Session-Key": binascii.hexlify(encrypted_session_key).decode(),
        "role": binascii.hexlify(encrypted_role).decode(),
        "X-Encrypted-Key-Info": json.dumps(encryption_header)  # Send JSON as a string in the header
    }

    # Enviar a requisição GET com a session_key e nonce no cabeçalho
    response = requests.post(url, headers=headers)

    # Retornar a resposta em formato JSON
    print(response.json())

if args.command == "rep_drop_role":
    session_file = command_args.session_file
    role = command_args.role
    with open(session_file, 'r') as file:
        session_data = json.load(file)
        session_key = session_data["session_context"]["session_token"]

    # Definir a URL do servidor
    url = f"http://{state['REP_ADDRESS']}//sessions/release_role"

    key = os.urandom(32)
    nonce = os.urandom(16)

    public_key_path = state['REP_PUB_KEY']
    encrypted_key = encrypt_with_public_key(public_key_path, key)
    encrypted_nonce = encrypt_with_public_key(public_key_path, nonce)

    # Prepare the JSON for the headers
    # nonce_header = str(uuid.uuid4())
    # encrypted_nonce_header = encrypt_with_chacha20(key, nonce, nonce_header)
    encrypted_session_key = encrypt_with_chacha20(key, nonce, session_key)
    encrypted_role =  encrypt_with_chacha20(key, nonce, role)


    encryption_header = {
        "key": encrypted_key.hex(),
        "nonce": encrypted_nonce.hex()
    }
    headers = {
        # "X-Nonce": encrypted_nonce_header.hex(),
        "X-Session-Key": binascii.hexlify(encrypted_session_key).decode(),
        "role": binascii.hexlify(encrypted_role).decode(),
        "X-Encrypted-Key-Info": json.dumps(encryption_header)  # Send JSON as a string in the header
    }

    # Enviar a requisição GET com a session_key e nonce no cabeçalho
    response = requests.post(url, headers=headers)

    # Retornar a resposta em formato JSON
    print(response.json())


def add_new_role(session_file, new_role):
    # Carregar os dados do arquivo da sessão
    with open(session_file, 'r') as file:
        session_data = json.load(file)
        session_key = session_data["session_context"]["session_token"]

    # Definir a URL do servidor
    url = f"http://{state['REP_ADDRESS']}//sessions/roles/add"

    key = os.urandom(32)
    nonce = os.urandom(16)

    public_key_path = state['REP_PUB_KEY']
    encrypted_key = encrypt_with_public_key(public_key_path, key)
    encrypted_nonce = encrypt_with_public_key(public_key_path, nonce)

    # Prepare the JSON for the headers
    # nonce_header = str(uuid.uuid4())
    # encrypted_nonce_header = encrypt_with_chacha20(key, nonce, nonce_header)
    encrypted_session_key = encrypt_with_chacha20(key, nonce, session_key)
    encrypted_role =  encrypt_with_chacha20(key, nonce, new_role)


    encryption_header = {
        "key": encrypted_key.hex(),
        "nonce": encrypted_nonce.hex()
    }
    headers = {
        # "X-Nonce": encrypted_nonce_header.hex(),
        "X-Session-Key": binascii.hexlify(encrypted_session_key).decode(),
        "new_role": binascii.hexlify(encrypted_role).decode(),
        "X-Encrypted-Key-Info": json.dumps(encryption_header)  # Send JSON as a string in the header
    }

    # Enviar a requisição GET com a session_key e nonce no cabeçalho
    response = requests.post(url, headers=headers)

    # Retornar a resposta em formato JSON
    return response.json()


if args.command == "rep_add_role":
    session_file = command_args.session_file
    new_role = command_args.role
    print(add_new_role(session_file, new_role))

def list_roles_by_session(session_file):
    # Carregar os dados do arquivo da sessão
    with open(session_file, 'r') as file:
        session_data = json.load(file)
        session_key = session_data["session_context"]["session_token"]

    # Definir a URL do servidor
    url = f"http://{state['REP_ADDRESS']}//sessions/roles"

    key = os.urandom(32)
    nonce = os.urandom(16)

    public_key_path = state['REP_PUB_KEY']
    encrypted_key = encrypt_with_public_key(public_key_path, key)
    encrypted_nonce = encrypt_with_public_key(public_key_path, nonce)

    # Prepare the JSON for the headers
    # nonce_header = str(uuid.uuid4())
    # encrypted_nonce_header = encrypt_with_chacha20(key, nonce, nonce_header)
    encrypted_session_key = encrypt_with_chacha20(key, nonce, session_key)

    encryption_header = {
        "key": encrypted_key.hex(),
        "nonce": encrypted_nonce.hex()
    }
    headers = {
        # "X-Nonce": encrypted_nonce_header.hex(),
        "X-Session-Key": binascii.hexlify(encrypted_session_key).decode(),
        "X-Encrypted-Key-Info": json.dumps(encryption_header)  # Send JSON as a string in the header
    }

    # Enviar a requisição GET com a session_key e nonce no cabeçalho
    response = requests.get(url, headers=headers)

    # Retornar a resposta em formato JSON
    return response.json()

if args.command =="rep_list_roles":
    session_file = command_args.session_file
    print(list_roles_by_session(session_file))

# Handle the command execution
if args.command == "rep_list_orgs":
    print(list_organizations())

elif args.command == "rep_add_doc":
    data = {
        "session_file": command_args.session_file,
        "document_name": command_args.document_name,
        "file": command_args.file,
    }
    print(upload_document(data))

elif args.command == "rep_subject_credentials":
    password = command_args.password
    crendentials_file = command_args.credentials_file
    print(gen_subject_file(password, crendentials_file))

elif args.command == "rep_decrypt_file":
    encrypted_file = command_args.encrypted_file
    encryption_metadata_file = command_args.encryption_metadata_file
    decrypt_file(encrypted_file, encryption_metadata_file)

elif args.command == "rep_list_docs":
    data = {
        "session_file": command_args.session_file,
        "username": command_args.username,
        "date": command_args.date,
        #"date": command_args.date,
    }
    print(get_documents(data))

elif args.command == "rep_create_org":
    data = {
        "name": command_args.organization,
        "username": command_args.username,
        "full_name": command_args.name,
        "email": command_args.email,
        "public_key_file": command_args.public_key_file
    }
    print(create_organization(data))

if args.command == "rep_add_subject":
    data = {
        #"session_file": command_args.session_file,
        "username": command_args.username,
        "name": command_args.name,
        "email": command_args.email,
        #"key": command_args.key,
        "credentials_file": command_args.credentials_file
    }
    print(add_subject(data, command_args.session_file))

elif args.command == "rep_list_subjects":
    session_file = command_args.session_file
    username = command_args.username
    print(list_subjects(session_file))

elif args.command == "rep_get_file":
    file_handle = command_args.file_handle
    output_file = command_args.file
    print(download_document(file_handle, output_file))

if args.command == "rep_create_session":
    data = {
        "organization": command_args.organization,
        "username": command_args.username,
        "password": command_args.password,
        #"key": command_args.key,
        "credentials_file": command_args.credentials_file
    }
    print(create_session(data, command_args.session_file))

elif args.command == "rep_get_doc_metadata":

    print(get_document_metadata(command_args.session_file, command_args.document_name))

elif args.command == "rep_delete_doc":

    print(delete_document(command_args.session_file, command_args.document_name))


save(state)
