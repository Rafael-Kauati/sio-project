import hashlib
import os
import sys
import argparse
import logging
import json
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

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
    # Formatar o corpo da requisição conforme o exemplo dado
    with open(data['public_key_file'], 'r') as key_file:
        public_key = key_file.read()

    payload = {
        "name": data['name'],
        "subject": {
            "username": data['username'],
            "full_name": data['full_name'],
            "email": data['email'],
            "public_key": public_key
        }
    }

    url = f"http://{state['REP_ADDRESS']}/organizations"
    response = requests.post(url, json=payload)
    if response.status_code == 201:
        logger.info("Organization created successfully.")
        return 0
    else:
        logger.error(f"Failed to create organization: {response.status_code}")


def create_session(data, session_file):
    # Formata a carga da requisição conforme o formato especificado
    with open(data['credentials_file'], 'r') as cred_file:
        credentials = json.load(cred_file)

    payload = {
        "username": data['username'],
        "organization_name": data['organization'],
        "identifier": "orgsession",
        "session_key": data['key'],  # Atualize conforme necessário
        "password": data['password'],
        "credentials": credentials
    }

    url = f"http://{state['REP_ADDRESS']}/sessions"
    response = requests.post(url, json=payload)

    if response.status_code == 201:
        # Salva a resposta no arquivo de sessão
        with open(session_file, 'w') as file:
            json.dump(response.json(), file, indent=4)
        return 0
    else:
        #logger.error(f"Failed to create session: {response.status_code}")
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

def add_subject(data):
    url = f"http://{state['REP_ADDRESS']}/add_subject"
    response = requests.post(url, json=data)
    if response.status_code == 201:
        logger.info("Subject added successfully.")
        return response.json()
    else:
        logger.error(f"Failed to add subject: {response.status_code}")

def add_document(data, file_path):
    url = f"http://{state['REP_ADDRESS']}/add_document"
    with open(file_path, 'rb') as file:
        files = {
            'file': file,
            'session_key': (None, data['session_key']),
            'document_name': (None, data['document_name'])
        }
        response = requests.post(url, files=files)
    if response.status_code == 201:
        logger.info("Document added successfully.")
        return response.json()
    else:
        logger.error(f"Failed to add document: {response.status_code}")

def get_document_metadata(session_file, document_name):
    # URL do endpoint para obter metadados do documento
    url = f"http://{state['REP_ADDRESS']}/document/metadata"

    # Abrir o arquivo de sessão para ler o session_key
    with open(session_file, 'r') as session_file:
        session_data = json.load(session_file)
        session_key = session_data["session_context"]["session_key"]

    # Definir cabeçalhos e parâmetros
    headers = {'session_key': session_key}
    params = {'document_name': document_name}

    # Enviar requisição GET para o endpoint de metadados do documento
    response = requests.get(url, headers=headers, params=params)

    # Retornar a resposta
    return response.json()

def download_document(session_key, document_name):
    url = f"http://{state['REP_ADDRESS']}/download_document/{session_key}/{document_name}"
    response = requests.get(url)
    if response.status_code == 200:
        with open(document_name, 'wb') as f:
            f.write(response.content)
        logger.info(f"Document '{document_name}' downloaded successfully.")
    else:
        logger.error(f"Failed to download document '{document_name}': {response.status_code}")

def delete_document(session_key, document_name):
    url = f"http://{state['REP_ADDRESS']}/delete_document/{session_key}/{document_name}"
    response = requests.delete(url)
    if response.status_code == 200:
        logger.info(f"Document '{document_name}' deleted successfully.")
    else:
        logger.error(f"Failed to delete document '{document_name}': {response.status_code}")

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

def upload_document(data):
    # Carrega o arquivo de sessão para obter a session_key
    with open(data['session_file'], 'r') as session_file:
        session_data = json.load(session_file)
        session_key = session_data["session_context"]["session_key"]

    # Carrega e criptografa o arquivo
    with open(data['file'], 'rb') as file:
        file_data = file.read()

    encrypted_file_data, aes_key, iv = encrypt_file_with_aes(file_data)
    file_handle = hashlib.sha256(encrypted_file_data).hexdigest()

    # Faz a requisição para enviar o documento criptografado
    response = requests.post(
        f"http://{state['REP_ADDRESS']}/add_document",
        files={'file': encrypted_file_data},
        data={
            'session_key': session_key,  # Utiliza a session_key extraída
            'file_name': data['document_name'],  # Nome do documento
            'file_encryption_key': aes_key.hex(),
            'file_handle': file_handle
        }
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

    # Faz a requisição GET para o endpoint usando session_key
    url = f"http://{state['REP_ADDRESS']}/sessions/{session_key}/documents"
    response = requests.get(url, params=params)

    if response.status_code == 200:
        logger.info("Documents retrieved successfully.")
        return response.json()
    else:
        logger.error(f"Failed to retrieve documents: {response.status_code}")
        return None



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
                                            "rep_list_docs","add_subject", "rep_add_doc"], help="Command to execute")
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

        command_parser.add_argument("key", help="key for the session")

        command_parser.add_argument("credentials_file", help="Path to the credentials file")

        command_parser.add_argument("session_file", help="Path to save the session file")

    elif args.command == "download_file":
        command_parser.add_argument("filename", help="File to download")

    elif args.command == "add_subject":
        command_parser.add_argument("session_key", help="Session key for the subject")
        command_parser.add_argument("subject_data", help="Subject data to add")

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
    # Analisa os argumentos específicos do comando usando unknown_args
    command_args = command_parser.parse_args(unknown_args)

    # Retorna o estado, os argumentos principais e os argumentos do comando específico
    return state, args, command_args



def save(state):
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    if not os.path.exists(state_dir):
      logger.debug('Creating state folder')
      os.mkdir(state_dir)

    with open(state_file, 'w') as f:
        f.write(json.dumps(state, indent=4))





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


if args.command == "rep_create_session":
    data = {
        "organization": command_args.organization,
        "username": command_args.username,
        "password": command_args.password,
        "key": command_args.key,
        "credentials_file": command_args.credentials_file
    }
    print(create_session(data, command_args.session_file))

elif args.command == "rep_get_doc_metadata":

    print(get_document_metadata(command_args.session_file, command_args.document_name))


elif args.command == "add_subject":
    data = {
        "session_key": command_args.session_key,
        "subject_data": command_args.subject_data
    }
    add_subject(data)

save(state)
