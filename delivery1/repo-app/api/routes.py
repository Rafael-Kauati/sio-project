from flask import Blueprint, jsonify, request, current_app, send_from_directory
from api.controllers import OrganizationController, SessionController, DocumentController
from werkzeug.utils import secure_filename
import os

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

main_bp = Blueprint('main', __name__)

#######################################################################
#################### Anonymous API ####################################
#######################################################################
@main_bp.route('/organizations', methods=['POST'])
def create_organization_route():
    return OrganizationController.create_organization()

@main_bp.route('/organizations', methods=['GET'])
def list_organizations_route():
    return OrganizationController.list_organizations()

# Endpoint de criação de sessão
@main_bp.route('/sessions', methods=['POST'])
def create_session_route():
    return SessionController.create_session()

# Endpoint para download de arquivo
@main_bp.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    try:
        return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404

#######################################################################
#################### Authenticated API ################################
#######################################################################
@main_bp.route('/sessions/assume_role', methods=['POST'])
def assume_role_route():
    return SessionController.assume_role()

@main_bp.route('/sessions/release_role', methods=['POST'])
def release_role_route():
    return SessionController.release_role()

# Endpoint para listar as roles da sessão
@main_bp.route('/sessions/<string:session_key>/roles', methods=['GET'])
def list_session_roles_route(session_key):
    return SessionController.list_session_roles(session_key)

@main_bp.route('/sessions/<string:session_key>/subjects', methods=['GET'])
def get_subjects_by_session_key_route(session_key):
    return SessionController.get_subjects_by_session_key(session_key)

@main_bp.route('/organization/<string:session_key>/org/roles', methods=['GET'])
def get_roles_by_session_key_route(session_key):
    return SessionController.get_roles_by_session_key(session_key)

@main_bp.route('/sessions/<string:session_key>/documents', methods=['GET'])
def get_documents_by_session_key_route(session_key):
    # Obtém parâmetros da consulta
    username = request.args.get('username')
    date_str = request.args.get('date')
    filter_type = request.args.get('filter_type', 'all')  # 'all', 'more_recent', 'older', etc.

    # Chama o controlador para obter documentos
    documents = DocumentController.get_documents_by_session_key(session_key, username, date_str, filter_type)
    return jsonify(documents), 200




#######################################################################
#################### Authorized API ###################################
#######################################################################

@main_bp.route('/add_subject', methods=['POST'])
def add_subject_route():
    data = request.json
    session_key = data.get("session_key")
    username = data.get("username")
    name = data.get("name")
    email = data.get("email")
    public_key = data.get("public_key")

    if not all([session_key, username, name, email, public_key]):
        return jsonify({"error": "Todos os campos são obrigatórios: session_key, username, name, email, public_key"}), 400

    result = SessionController.add_subject_to_organization(session_key, username, name, email, public_key)
    return jsonify(result), 201 if "id" in result else 400

@main_bp.route('/add_document', methods=['POST'])
def add_document_route():
    session_key = request.form.get("session_key")
    document_name = request.form.get("document_name")
    file = request.files.get("file")

    if not all([session_key, document_name, file]):
        return jsonify({"error": "Todos os campos são obrigatórios: session_key, document_name, e o arquivo"}), 400

    # Chama o controller para salvar o documento
    result = SessionController.upload_document_to_organization(session_key, document_name, file)
    return jsonify(result), 201 if "id" in result else 400

@main_bp.route('/document/metadata', methods=['GET'])
def get_document_metadata_route():
    session_key = request.headers.get('session_key')
    document_name = request.args.get('document_name')
    
    if not document_name:
        return jsonify({"error": "O parâmetro 'document_name' é obrigatório"}), 400

    # Chama a função do controlador para buscar os metadados e o conteúdo do documento
    result = SessionController.get_document_metadata(session_key, document_name)

    return jsonify(result)


@main_bp.route('/download_document/<session_key>/<document_name>', methods=['GET'])
def download_document_route(session_key, document_name):
    result = SessionController.download_document(session_key, document_name)
    if result is None:
        return jsonify({"error": "Document not found in organization"}), 404  # Documento não encontrado ou erro na sessão
    return result

@main_bp.route('/delete_document/<session_key>/<string:document_name>', methods=['DELETE'])
def delete_document_route(session_key, document_name):
    if not session_key:
        return jsonify({"error": "Session key is required"}), 400

    result = SessionController.delete_document_from_organization(session_key, document_name)
    return jsonify(result), 200 if result['success'] else 400
