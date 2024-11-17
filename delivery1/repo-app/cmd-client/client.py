import base64
import hashlib
import os
import sys
import argparse
import logging
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

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

def list_organizations():
    url = f"http://{state['REP_ADDRESS']}/organizations"
    response = requests.get(url)
    print(response.content)
    if response.status_code == 200:
        logger.info("Organizations listed successfully.")
        return response.json()
    else:
        logger.error(f"Failed to list organizations: {response.status_code}")


def create_organization(data):
    try:
        # Carregar o arquivo de chave pública
        with open(data['public_key_file'], 'r') as key_file:
            public_key_data = json.load(key_file)

        # Obter a chave pública do conteúdo carregado
        public_key = public_key_data.get("public_key")
        if not public_key:
            raise ValueError("Public key not found in the provided file.")

        # Montar o payload da requisição
        payload = {
            "name": data['name'],
            "subject": {
                "username": data['username'],
                "full_name": data['full_name'],
                "email": data['email'],
                "public_key": public_key
            }
        }

        # Enviar a requisição para criar a organização
        url = f"http://{state['REP_ADDRESS']}/organizations"
        response = requests.post(url, json=payload)

        # Verificar o status da resposta
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



def create_session(data, session_file):
    """
    Cria uma sessão e criptografa a chave de sessão com uma chave pública RSA.
    """
    import json
    import requests

    # Lê as credenciais do arquivo especificado
    with open(data['credentials_file'], 'r') as cred_file:
        credentials = json.load(cred_file)

    payload = {
        "username": data['username'],
        "organization_name": data['organization'],
        "password": data['password'],
        "credentials": credentials
    }

    # Envia o payload para criar uma sessão
    url = f"http://{state['REP_ADDRESS']}/sessions"
    response = requests.post(url, json=payload)

    if response.status_code == 201:
        # Obtém a resposta e criptografa a session_key
        response_data = response.json()
        session_key = response_data["session_context"]["session_key"]

        # Usa o caminho para a chave pública
        public_key_path = "../public_key.pem"
        encrypted_session_key = encrypt_session_key(session_key, public_key_path)

        # Substitui a chave de sessão pela versão criptografada
        response_data["session_context"]["session_key"] = encrypted_session_key

        # Salva a resposta atualizada no arquivo de sessão
        with open(session_file, 'w') as file:
            json.dump(response_data, file, indent=4)
        return 0
    else:
        # Caso falhe na criação da sessão
        print(f"Failed to create session: {response.status_code}")
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
    with open(session_file, 'r') as session_file:
        session_data = json.load(session_file)
        session_key = session_data["session_context"]["session_key"]

    with open(data['credentials_file'], 'r') as cred_file:
        credentials = json.load(cred_file)

        # Obter a chave pública do conteúdo carregado
        public_key = credentials.get("public_key")
        if not public_key:
            raise ValueError("Public key not found in the provided file.")

    # Payload agora não inclui mais a session_key, pois ela será enviada no cabeçalho
    payload = {
        "username": data['username'],
        "name": data['name'],
        "email": data['email'],
        "public_key": public_key,
        "credentials": credentials
    }

    # Define os cabeçalhos para incluir a session_key
    headers = {
        "X-Session-Key": session_key
    }

    # Faz a requisição POST com os cabeçalhos e o payload
    response = requests.post(url, json=payload, headers=headers)
    return response


def get_document_metadata(session_file, document_name):
    # URL do endpoint para obter metadados do documento
    url = f"http://{state['REP_ADDRESS']}/document/metadata"

    # Abrir o arquivo de sessão para ler o session_key
    with open(session_file, 'r') as session_file:
        session_data = json.load(session_file)
        session_key = session_data["session_context"]["session_key"]

    # Definir cabeçalhos e parâmetros
    headers = {'session_key': session_key}  # Envia session_key no cabeçalho
    params = {'document_name': document_name}

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
        output_file = f"{document_name}_encryption_data.json"

        # Salvar os dados de criptografia no arquivo JSON
        with open(output_file, 'w') as file:
            json.dump(encryption_data, file, indent=4)

        print(f"Encryption data salvo em: {output_file}")
        return metadata
    else:
        print(f"Erro ao obter metadados: {response.status_code} - {response.text}")
        response.raise_for_status()


import requests


def download_document(file_handle, file=None):
    """
    Faz o download de um documento criptografado e imprime o conteúdo como string.
    Se o arquivo estiver criptografado, exibe os dados binários como string.

    :param file_handle: Identificador do arquivo no servidor.
    :param file: Caminho opcional para salvar o arquivo baixado.
    :return: JSON com metadados ou None.
    """
    url = f"http://{state['REP_ADDRESS']}/download/{file_handle}"
    response = requests.get(url)

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

    return None


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
        session_key = session_data["session_context"]["session_key"]

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
    headers = {
        "X-Session-Key": session_key
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

    return response


def get_documents(data):
    # Carrega o arquivo de sessão para obter a session_key
    with open(data['session_file'], 'r') as session_file:
        session_data = json.load(session_file)
        session_key = session_data["session_context"]["session_key"]

    # Configura os parâmetros da URL com os argumentos opcionais
    params = {}
    if data["username"]:
        params["username"] = data["username"]
    if data["date"]:
        date_parts = data["date"].split(' ')
        if len(date_parts) == 2:
            filter_type, date_str = date_parts
            params["date"] = date_str
            params["filter_type"] = filter_type
        else:
            print("Formato de data incorreto. Use <filter_type> <date> (por exemplo, 'nt 2023-01-01').")
            return

    # Configura a URL do servidor
    url = f"http://{state['REP_ADDRESS']}/sessions/documents"

    # Define os cabeçalhos para incluir a session_key
    headers = {
        "X-Session-Key": session_key
    }

    # Faz a requisição GET com os parâmetros e os cabeçalhos
    response = requests.get(url, headers=headers, params=params)

    # Retorna a resposta em formato JSON
    return response.json()

    # Faz a requisição GET para o endpoint usando session_key
    url = f"http://{state['REP_ADDRESS']}/sessions/{session_key}/documents"
    response = requests.get(url, params=params)

    if response.status_code == 200:
        logger.info("Documents retrieved successfully.")
        return response.json()
    else:
        logger.error(f"Failed to retrieve documents: {response.status_code}")
        return None

def delete_document(session_file, document_name):
    # Carrega o arquivo de sessão para obter o session_key
    with open(session_file, 'r') as session_file:
        session_data = json.load(session_file)
        session_key = session_data["session_context"]["session_key"]

    # URL do endpoint para deletar o documento
    url = f"http://{state['REP_ADDRESS']}/delete_document/{document_name}"

    # Definir cabeçalhos com o session_key
    headers = {'session_key': session_key}  # Envia session_key no cabeçalho

    # Enviar requisição DELETE para o endpoint de deletar o documento
    response = requests.delete(url, headers=headers)

    return response.json()

def list_subjects(session_file, username=None):
    # Carregar os dados do arquivo da sessão
    with open(session_file, 'r') as file:
        session_data = json.load(file)
        session_key = session_data["session_context"]["session_key"]

    # Definir a URL do servidor
    url = f"http://{state['REP_ADDRESS']}/sessions/subjects"

    # Definir os cabeçalhos para incluir a session_key
    headers = {
        "X-Session-Key": session_key
    }

    # Enviar a requisição GET com a session_key no cabeçalho
    response = requests.get(url, headers=headers)

    # Retornar a resposta em formato JSON
    return response.json()

def gen_subject_file(password, credentials_file):
    # Generate RSA private/public key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize the public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')  # Decode to string for JSON storage

    # Encrypt the private key
    salt = os.urandom(16)  # Random salt for key derivation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # AES encryption of the private key
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    encrypted_private_key = encryptor.update(private_pem) + encryptor.finalize()

    # Save the public key in JSON format and encrypted private key in the same file
    credentials_data = {
        "public_key": public_pem,
        "salt": salt.hex(),
        "iv": iv.hex(),
        "encrypted_private_key": encrypted_private_key.hex()
    }

    with open(f"{credentials_file}", "w") as cred_file:
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
        logger.debug('Setting REP_ADDRESS from Environment to: ' + state['REP_ADDRESS'])
    else:
        state['REP_ADDRESS'] = "localhost:5000"
        logger.debug('Setting REP_ADDRESS as : ' + state['REP_ADDRESS'])


    if 'REP_PUB_KEY' in os.environ:
        rep_pub_key = os.getenv('REP_PUB_KEY')
        logger.debug('Loading REP_PUB_KEY fron: ' + state['REP_PUB_KEY'])
        if os.path.exists(rep_pub_key):
            with open(rep_pub_key, 'r') as f:
                state['REP_PUB_KEY'] = f.read()
                logger.debug('Loaded REP_PUB_KEY from Environment')
    else:
        state['REP_PUB_KEY'] = "../public_key.pem"
        logger.debug('Loading REP_PUB_KEY fron: ' + state['REP_PUB_KEY'])
        if os.path.exists(state['REP_PUB_KEY']):
            with open(state['REP_PUB_KEY'], 'r') as f:
                state['REP_PUB_KEY'] = f.read()
                logger.debug('Loaded REP_PUB_KEY from file')
    return state


def parse_args(state):
    parser = argparse.ArgumentParser()

    # Define o argumento principal 'command' e os argumentos opcionais
    parser.add_argument("command", choices=["list_organizations",
                                            "rep_create_org", "rep_create_session",
                                            "download_file", "rep_get_doc_metadata",
                                            "rep_list_docs",
                                            "rep_add_subject", "rep_list_subjects",  # Added missing comma
                                            "rep_add_doc", "rep_get_file","rep_delete_doc",
                                            "rep_subject_credentials", "rep_decrypt_file"], help="Command to execute")
    parser.add_argument("-k", '--key', nargs=1, help="Path to the key file")
    parser.add_argument("-r", '--repo', nargs=1, help="Address:Port of the repository")
    parser.add_argument("-v", '--verbose', help="Increase verbosity", action="store_true")


    # Parse os argumentos até o comando (ignora os argumentos específicos do comando)
    args, unknown_args = parser.parse_known_args()

    # Configura o nível de verbosidade
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.info('Setting log level to DEBUG')

    # Sub-parser para argumentos específicos do comando
    command_parser = argparse.ArgumentParser()


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
        command_parser.add_argument("-f", "--file", help="File to save the document (optional)")


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

# Handle the command execution
if args.command == "list_organizations":
    list_organizations()

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
    create_organization(data)

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
