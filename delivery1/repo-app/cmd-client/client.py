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
    url = f"http://{state['REP_ADDRESS']}/organizations" #mudar isto para o caminho da api
    response = requests.get(url)
    if response.status_code == 200:
        logger.info("Organizations listed successfully.")
        return response.json()
    else:
        logger.error(f"Failed to list organizations: {response.status_code}")

def create_organization(data):
    url = f"http://{state['REP_ADDRESS']}/organizations"
    response = requests.post(url, json=data)
    if response.status_code == 200:
        logger.info("Organization created successfully.")
        return response.json()
    else:
        logger.error(f"Failed to create organization: {response.status_code}")

def create_session(data):
    url = f"http://{state['REP_ADDRESS']}/sessions"
    response = requests.post(url, json=data)
    if response.status_code == 200:
        logger.info("Session created successfully.")
        return response.json()
    else:
        logger.error(f"Failed to create session: {response.status_code}")

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

    # Add a 'command' argument to identify which action to perform
    parser.add_argument("command", help="Command to execute (e.g., list_organizations, create_organization, etc.)")

    # Define other generic arguments
    parser.add_argument("-k", '--key', nargs=1, help="Path to the key file")
    parser.add_argument("-r", '--repo', nargs=1, help="Address:Port of the repository")
    parser.add_argument("-v", '--verbose', help="Increase verbosity", action="store_true")

    args = parser.parse_args()

    # Set verbosity level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.info('Setting log level to DEBUG')

    # Command-specific argument parsing
    command_parser = argparse.ArgumentParser()

    if args.command == "create_organization":
        command_parser.add_argument("name", help="Name of the organization")
        command_parser.add_argument("email", help="Email of the organization")
        command_parser.add_argument("public_key_file", help="Path to the public key file for the organization")

    elif args.command == "create_session":
        command_parser.add_argument("username", help="Username for the session")
        command_parser.add_argument("password", help="Password for the session")
        command_parser.add_argument("credentials_file", help="Path to the credentials file")

    elif args.command == "download_file":
        command_parser.add_argument("filename", help="File to download")

    elif args.command == "add_subject":
        command_parser.add_argument("session_key", help="Session key for the subject")
        command_parser.add_argument("subject_data", help="Subject data to add")

    # Add other commands here as needed

    # Parse the arguments for the selected command
    command_args = command_parser.parse_args(sys.argv[2:])

    # Return the parsed state and arguments
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
        "name": command_args.name,
        "email": command_args.email,
        "public_key_file": command_args.public_key_file
    }
    create_organization(data)

elif args.command == "create_session":
    data = {
        "username": command_args.username,
        "password": command_args.password,
        "credentials_file": command_args.credentials_file
    }
    create_session(data)

elif args.command == "download_file":
    download_file(command_args.filename)

elif args.command == "add_subject":
    data = {
        "session_key": command_args.session_key,
        "subject_data": command_args.subject_data
    }
    add_subject(data)

""" Do something """
req = requests.get(f'http://{state['REP_ADDRESS']}/organizations')
print(req.json)
save(state)
