import os
import sys
import argparse
import logging
import json
import requests

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

def get_document_metadata(session_key, document_name):
    url = f"http://{state['REP_ADDRESS']}/document/metadata"
    headers = {'session_key': session_key}
    params = {'document_name': document_name}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        logger.info("Document metadata retrieved successfully.")
        return response.json()
    else:
        logger.error(f"Failed to get document metadata: {response.status_code}")

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
    parser.add_argument("command", choices=["list_organizations", "create_organization", "create_session", "download_file", "add_subject"], help="Command to execute")
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

    if args.command == "create_organization":
        command_parser.add_argument("organization", help="Organization ID")
        command_parser.add_argument("username", help="Username for the organization admin")
        command_parser.add_argument("name", help="Name of the organization")
        command_parser.add_argument("email", help="Email of the organization")
        command_parser.add_argument("public_key_file", help="Path to the public key file for the organization")

    if args.command == "create_session":

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

    # Adiciona outros comandos conforme necessário

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

elif args.command == "create_organization":
    data = {
        "name": command_args.organization,
        "username": command_args.username,
        "full_name": command_args.name,
        "email": command_args.email,
        "public_key_file": command_args.public_key_file
    }
    create_organization(data)


if args.command == "create_session":
    data = {
        "organization": command_args.organization,
        "username": command_args.username,
        "password": command_args.password,
        "key": command_args.key,
        "credentials_file": command_args.credentials_file
    }
    print(create_session(data, command_args.session_file))

elif args.command == "download_file":
    download_file(command_args.filename)

elif args.command == "add_subject":
    data = {
        "session_key": command_args.session_key,
        "subject_data": command_args.subject_data
    }
    add_subject(data)

save(state)
