from flask import Blueprint, jsonify, request
from app.controllers import OrganizationController, SessionController, DocumentController

main_bp = Blueprint('main', __name__)

@main_bp.route('/organizations', methods=['POST'])
def create_organization_route():
    return OrganizationController.create_organization()

@main_bp.route('/organizations', methods=['GET'])
def list_organizations_route():
    return OrganizationController.list_organizations()

@main_bp.route('/sessions', methods=['POST'])
def create_session_route():
    return SessionController.create_session()

@main_bp.route('/documents', methods=['POST'])
def upload_document_route():
    return DocumentController.upload_document()

@main_bp.route('/documents/<string:file_handle>', methods=['GET'])
def download_file_route(file_handle):
    return DocumentController.download_document(file_handle)

@main_bp.route('/documents/<string:file_handle>', methods=['DELETE'])
def delete_document_route(file_handle):
    return DocumentController.delete_document(file_handle)