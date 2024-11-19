import base64
import binascii
import hashlib
import io
import json
import logging
import os

from flask import Blueprint, jsonify, request, current_app, send_from_directory, send_file, abort
from api.controllers import OrganizationController, SessionController, DocumentController
from api import logger, Document
from api.utils import decrypt_file_key_with_ec_master, load_ec_master_key, load_ec_private_key
from . import app
from .utils import *
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


main_bp = Blueprint('main', __name__)


#######################################################################
#################### Anonymous API ####################################
#######################################################################
@main_bp.route('/organizations', methods=['POST'])
def create_organization_route():
    logger.info("Request to create organization received.")
    response = OrganizationController.create_organization()
    logger.info("Organization created successfully.")
    return response


@main_bp.route('/organizations', methods=['GET'])
def list_organizations_route():
    logger.info("Request to list organizations received.")
    response = OrganizationController.list_organizations()
    logger.info("Organizations listed successfully.")
    return response


# Endpoint for creating a session
@main_bp.route('/sessions', methods=['POST'])
def create_session_route():
    logger.info("Request to create session received.")
    response = SessionController.create_session()
    logger.info("Session created successfully.")
    return response


@main_bp.route('/download/<file_handle>', methods=['GET'])
def download_file(file_handle):
    # Chama o método do controlador
    nonce = request.headers.get("X-Nonce")

    response, status_code = DocumentController.download_document(file_handle, nonce)

    # Caso o método retorne a chave do arquivo, faz o envio do arquivo também
    if status_code == 200:
        file_data = response.get('file_data')  # Dados do arquivo
        file_key = response.get('file_key')    # Chave do arquivo
        file_name = response.get('file_name')  # Nome do arquivo

        # Salva o arquivo como resposta para o cliente
        return send_file(
            io.BytesIO(file_data),    # Usar io.BytesIO para enviar os dados binários
            as_attachment=True,       # Força o download do arquivo
            download_name=file_name,  # Nome do arquivo
            mimetype='application/octet-stream'  # Tipo MIME genérico
        )

    # Se o código de status não for 200, retorna o erro
    return jsonify(response), status_code




#######################################################################
#################### Authenticated API ################################
#######################################################################
@main_bp.route('/sessions/assume_role', methods=['POST'])
def assume_role_route():
    logger.info("Request to assume role received.")
    return SessionController.assume_role()


@main_bp.route('/sessions/release_role', methods=['POST'])
def release_role_route():
    logger.info("Request to release role received.")
    return SessionController.release_role()


@main_bp.route('/sessions/<string:session_key>/roles', methods=['GET'])
def list_session_roles_route(session_key):
    logger.info(f"Request to list roles for session: {session_key}")
    return SessionController.list_session_roles(session_key)


@main_bp.route('/sessions/subjects', methods=['GET'])
def get_subjects_by_session_key_route():
    # Obtém a session_key e o nonce dos cabeçalhos da requisição
    session_key = request.headers.get('X-Session-Key')
    nonce = request.headers.get('X-Nonce')

    if not session_key or not nonce:
        # Retorna um erro se os cabeçalhos não estiverem presentes
        return jsonify({"error": "Missing 'X-Session-Key' or 'X-Nonce' header"}), 400

    logger.info(f"Request to get subjects by session key: {session_key} and nonce: {nonce}")

    # Chama o controlador para processar a lógica
    return SessionController.get_subjects_by_session_key(session_key, nonce)



@main_bp.route('/organization/<string:session_key>/org/roles', methods=['GET'])
def get_roles_by_session_key_route(session_key):
    logger.info(f"Request to get roles by session key: {session_key}")
    return SessionController.get_roles_by_session_key(session_key)


@main_bp.route('/sessions/documents', methods=['GET'])
def get_documents_by_session_key_route():
    # Obtém a session_key dos cabeçalhos
    session_key = request.headers.get('X-Session-Key')

    # Obtém os parâmetros da URL
    username = request.args.get('username')
    date_str = request.args.get('date')
    filter_type = request.args.get('filter_type', 'all')

    logger.info(
        f"Request to get documents by session key: {session_key} with filters - username: {username}, date: {date_str}, filter_type: {filter_type}")

    documents = DocumentController.get_documents_by_session_key(session_key, username, date_str, filter_type)
    return jsonify(documents), 200


#######################################################################
#################### Authorized API ###################################
#######################################################################
@main_bp.route('/add_subject', methods=['POST'])
def add_subject_route():
    try:
        # Obtém os cabeçalhos criptografados
        encrypted_session_key = request.headers.get("X-Session-Key")
        encrypted_key = request.headers.get("X-Encrypted-Key")
        encrypted_nonce = request.headers.get("X-Encrypted-Nonce")
        nonce_header = request.headers.get("X-Nonce")

        if not all([encrypted_session_key, encrypted_key, encrypted_nonce, nonce_header]):
            logger.warning("Missing required headers for adding subject.")
            return jsonify({"error": "Todos os cabeçalhos são obrigatórios"}), 400

        # Obtém o payload criptografado
        encrypted_payload = request.get_data()

        # Descriptografar chave e nonce ChaCha20 com a chave privada
        private_key_path = "private_key.pem"  # Caminho para a chave privada
        chacha_key = decrypt_with_private_key(private_key_path, binascii.unhexlify(encrypted_key))
        chacha_nonce = decrypt_with_private_key(private_key_path, binascii.unhexlify(encrypted_nonce))

        # Descriptografar session_key e payload com ChaCha20
        session_key = decrypt_with_chacha20(chacha_key, chacha_nonce, binascii.unhexlify(encrypted_session_key)).decode('utf-8')
        payload_json = decrypt_with_chacha20(chacha_key, chacha_nonce, binascii.unhexlify(encrypted_payload)).decode('utf-8')
        data = json.loads(payload_json)

        # Extrai os campos do payload descriptografado
        username = data.get("username")
        name = data.get("name")
        email = data.get("email")

        if not all([session_key, username, name, email]):
            logger.warning("Missing required fields for adding subject.")
            return jsonify(
                {"error": "Todos os campos são obrigatórios: session_key, username, name, email"}), 400

        # Chama o controlador para adicionar o sujeito
        logger.info(f"Adding subject to organization with session key: {session_key}")
        result, status_code = SessionController.add_subject_to_organization(
            session_key, nonce_header, username, name, email
        )
        return jsonify(result), status_code
    except Exception as e:
        logger.error(f"Erro ao processar a requisição: {str(e)}")
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500




@main_bp.route('/add_document', methods=['POST'])
def add_document_route():
    # Recebe os dados da requisição
    session_key = request.headers.get("X-Session-Key")  # Obtém session_key do cabeçalho
    nonce = request.headers.get("X-Nonce")  # Obtém session_key do cabeçalho
    file_name = request.form.get("file_name")
    file = request.files.get("file")
    file_encryption_key = request.form['file_encryption_key']
    file_handle = request.form.get('file_handle')
    encryption_vars = request.form.get('encryption_vars')  # Recebe o JSON de encryption_vars

    # Validação de campos obrigatórios
    if not all([session_key, file_name, file, file_encryption_key, file_handle, encryption_vars]):
        logger.warning("Missing required fields for adding document.")
        return jsonify({
            "error": "Todos os campos são obrigatórios: session_key, document_name, arquivo, file_encryption_key, file_handle e encryption_vars"}), 400

    # Gera o hash do arquivo e valida se corresponde ao file_handle recebido
    file.seek(0)
    file_content = file.read()
    file_hash = hashlib.sha256(file_content).hexdigest()
    if file_handle != file_hash:
        logger.warning("file_handle não corresponde ao hash do arquivo enviado.")
        return jsonify({
            "error": "O file_handle enviado não corresponde ao hash do arquivo."}), 400

    # Chama o controller para fazer o processamento e salvar o documento
    logger.info(f"Adding document to organization with session key: {session_key} and document name: {file_name}")
    result = SessionController.upload_document_to_organization(
        session_key, nonce,file_name, file, file_handle, file_encryption_key, encryption_vars
    )

    # Retorna o resultado conforme o sucesso ou falha
    return jsonify(result)





@main_bp.route('/document/metadata', methods=['GET'])
def get_document_metadata_route():
    # Recebe a session_key do cabeçalho HTTP
    session_key = request.headers.get('X-Session-Key')  # Obtém session_key dos cabeçalhos
    nonce = request.headers.get("X-Nonce")
    document_name = request.args.get('document_name')  # Obtém o document_name dos parâmetros de consulta

    if not document_name:
        logger.warning("Document name parameter missing for metadata request.")
        return jsonify({"error": "O parâmetro 'document_name' é obrigatório"}), 400

    if not session_key:
        logger.warning("Session key missing for metadata request.")
        return jsonify({"error": "O cabeçalho 'session_key' é obrigatório"}), 400

    logger.info(f"Requesting document metadata for session key: {session_key} and document name: {document_name}")
    result = SessionController.get_document_metadata(session_key, nonce,document_name)
    return result






@main_bp.route('/delete_document/<string:document_name>', methods=['DELETE'])
def delete_document_route(document_name):
    # Recebe a session_key do cabeçalho HTTP
    session_key = request.headers.get('X-Session-Key')
    nonce = request.headers.get("X-Nonce")

    if not session_key:
        logger.warning("Session key missing for delete request.")
        return jsonify({"error": "O cabeçalho 'session_key' é obrigatório"}), 400

    logger.info(f"Request to delete document: {document_name} in session: {session_key}")
    result = SessionController.delete_document_from_organization(session_key,nonce, document_name)
    return result

