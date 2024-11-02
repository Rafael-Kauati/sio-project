from flask import Blueprint, jsonify, request, current_app, send_from_directory
from api.controllers import OrganizationController, SessionController, DocumentController
from werkzeug.utils import secure_filename
import os

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

main_bp = Blueprint('main', __name__)

# Endpoints de organizações
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

# Endpoints de role
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



# Endpoint de upload de arquivo
@main_bp.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'message': 'File uploaded successfully', 'filename': filename}), 201
    else:
        return jsonify({'error': 'File type not allowed'}), 400

# Endpoint para download de arquivo
@main_bp.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    try:
        return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404

###    Authorized API

# Endpoint de deleção de documento
@main_bp.route('/documents/<string:file_handle>', methods=['DELETE'])
def delete_document_route(file_handle):
    return DocumentController.delete_document(file_handle)

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