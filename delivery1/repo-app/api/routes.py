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

# Endpoint de deleção de documento
@main_bp.route('/documents/<string:file_handle>', methods=['DELETE'])
def delete_document_route(file_handle):
    return DocumentController.delete_document(file_handle)
