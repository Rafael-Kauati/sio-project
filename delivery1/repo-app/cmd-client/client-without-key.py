import os
import sys
import argparse
import logging
import json
import requests

logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def load_state():
    state = {}
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    logger.debug('State folder: ' + state_dir)
    logger.debug('State file: ' + state_file)

    if os.path.exists(state_file):
        logger.debug('Loading state')
        with open(state_file, 'r') as f:
            state = json.loads(f.read())

    if state is None:
        state = {}

    return state

def parse_env(state):
    if 'REP_ADDRESS' in os.environ:
        state['REP_ADDRESS'] = os.getenv('REP_ADDRESS')
        logger.debug('Setting REP_ADDRESS from Environment to: ' + state['REP_ADDRESS'])

    # Comentado: carregamento da chave pública
    # if 'REP_PUB_KEY' in os.environ:
    #     rep_pub_key = os.getenv('REP_PUB_KEY')
    #     logger.debug('Loading REP_PUB_KEY from: ' + rep_pub_key)
    #     if os.path.exists(rep_pub_key):
    #         with open(rep_pub_key, 'r') as f:
    #             state['REP_PUB_KEY'] = f.read()
    #             logger.debug('Loaded REP_PUB_KEY from Environment')

    return state

def parse_args(state):
    parser = argparse.ArgumentParser()

    # Apenas argumento para o repositório
    parser.add_argument("-r", '--repo', nargs=1, help="Address:Port of the repository")
    parser.add_argument("-v", '--verbose', help="Increase verbosity", action="store_true")

    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.info('Setting log level to DEBUG')

    # Comentado: carregamento da chave pública via argumento
    # if args.key:
    #     if not os.path.exists(args.key[0]) or not os.path.isfile(args.key[0]):
    #         logger.error(f'Key file not found or invalid: {args.key[0]}')
    #         sys.exit(-1)
    #
    #     with open(args.key[0], 'r') as f:
    #         state['REP_PUB_KEY'] = f.read()
    #         logger.info('Overriding REP_PUB_KEY from command line')

    if args.repo:
        state['REP_ADDRESS'] = args.repo[0]
        logger.info('Overriding REP_ADDRESS from command line')

    return state

def save(state):
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    if not os.path.exists(state_dir):
        logger.debug('Creating state folder')
        os.mkdir(state_dir)

    with open(state_file, 'w') as f:
        f.write(json.dumps(state, indent=4))

# Carrega o estado, configurações de ambiente e argumentos
state = load_state()
state = parse_env(state)
state = parse_args(state)

# Remove a verificação da chave pública
if 'REP_ADDRESS' not in state:
    logger.error("Must define Repository Address")
    sys.exit(-1)

# Realiza a requisição ao endereço do repositório
try:
    req = requests.get(f'http://{state["REP_ADDRESS"]}/organizations')
    print(req.json())
except requests.exceptions.RequestException as e:
    logger.error(f"Failed to connect to the repository: {e}")

# Salva o estado
save(state)
