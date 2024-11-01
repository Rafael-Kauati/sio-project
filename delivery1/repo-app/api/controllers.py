from flask import jsonify, request
from api.models import db, Document, Organization, Session, Subject

from flask import jsonify, request, send_file, abort
from api.models import db, Document
import os

class DocumentController:
    @staticmethod
    def upload_document():
        data = request.json
        document = Document(**data)
        db.session.add(document)
        db.session.commit()
        return jsonify({'message': 'Document uploaded successfully'}), 201

    @staticmethod
    def download_document(file_handle):
        # Busca o documento no banco de dados
        document = Document.query.filter_by(file_handle=file_handle).first_or_404()

        # Define o caminho do arquivo usando o `file_handle`
        file_path = f"/path/to/documents/{document.file_handle}"  # Substitua com o caminho real

        # Verifica se o arquivo existe no caminho especificado
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)  # Envia o arquivo como anexo
        else:
            abort(404, description="File not found.")  # Retorna erro 404 se o arquivo não for encontrado

    @staticmethod
    def delete_document(file_handle):
        document = Document.query.filter_by(file_handle=file_handle).first_or_404()
        db.session.delete(document)
        db.session.commit()
        return jsonify({'message': 'Document deleted successfully'}), 204


class OrganizationController:
    @staticmethod
    def create_organization():
        data = request.json
        org_name = data.get("name")
        subject_data = data.get("subject")

        if not org_name or not subject_data:
            return jsonify({'error': 'Organization name and subject data are required'}), 400
        
        # Extract subject data
        username = subject_data.get("username")
        full_name = subject_data.get("full_name")
        email = subject_data.get("email")
        public_key = subject_data.get("public_key")
        
        if not username or not full_name or not email or not public_key:
            return jsonify({'error': 'All subject fields are required'}), 400
        
        # Create organization
        organization = Organization(name=org_name)
        
        # Create subject
        subject = Subject(
            username=username,
            full_name=full_name,
            email=email,
            public_key=public_key
        )
        
        # Save both to the database
        try:
            db.session.add(organization)
            db.session.add(subject)
            db.session.commit()
            return jsonify({'message': 'Organization and subject created successfully'}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    @staticmethod
    def list_organizations():
        organizations = Organization.query.all()
        return jsonify([org.name for org in organizations]), 200

class SessionController:
    @staticmethod
    def create_session():
        data = request.json

        # Busca a organização pelo nome
        organization = Organization.query.filter_by(name=data.get("organization_name")).first()
        if not organization:
            abort(404, description="Organization not found")

        # Busca o subject pelo username
        subject = Subject.query.filter_by(username=data.get("username")).first()
        if not subject:
            abort(404, description="Subject not found")

        # Cria uma nova sessão
        session = Session(
            identifier=data.get("identifier"),
            keys=data.get("keys"),
            password=data.get("password"),
            credentials=data.get("credentials"),
            organization=organization,
            subject=subject
        )

        db.session.add(session)
        db.session.commit()

        # Retorna o contexto da sessão criada
        return jsonify({
            'message': 'Session created successfully',
            'session_context': {
                'session_id': session.id,  # Ou qualquer campo que represente a sessão
                'organization_name': organization.name,
                'subject_username': subject.username,
                'identifier': session.identifier,
                # Adicione mais campos conforme necessário
            }
        }), 201

