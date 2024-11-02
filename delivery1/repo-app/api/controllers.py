from flask import jsonify, request, send_file, abort
from api.models import db, Document, Organization, Session, Subject, Role
from sqlalchemy import text
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
    def get_session_by_key(session_key):
        return Session.query.filter_by(session_key=session_key).first()


    @staticmethod
    def assume_role():
        data = request.json
        session_key = data.get("session_key")
        role_name = data.get("role")

        # Busca a sessão pelo campo `keys`
        session = SessionController.get_session_by_key(session_key)
        if not session:
            return jsonify({"error": "Session not found"}), 404
        '''
       
        # Search for the specific role by name and organization of the session
        role = Role.query.filter_by(name=role_name, organization_id=session.organization_id).first()
        if not role:
            abort(404, description="Role not found in this organization")
        
        # Add the role to the session
        session.roles.append(role)
        db.session.commit()
        '''
        return jsonify({"message": f"Role '{role_name}' assumed successfully"}), 200

    @staticmethod
    def release_role():
        data = request.json
        session_key = data.get("session_key")
        role_name = data.get("role_name")

        # Valida a sessão e busca a instância da sessão
        session = SessionController.get_session_by_key(session_key)
        if not session:
            return jsonify({"error": "Session not found"}), 404
        return jsonify({"message": f"Role '{role_name}' released successfully"}), 200
        '''
        # Busca o role específico pelo nome e organização da sessão
        role = Role.query.filter_by(name=role_name, organization_id=session.organization_id).first()
        if not role:
            abort(404, description="Role not found in this organization")

        # Remove o role da sessão
        if role in session.roles:
            session.roles.remove(role)
            db.session.commit()
            return jsonify({"message": f"Role '{role_name}' released successfully"}), 200
        else:
            abort(400, description="Role not assigned to the session")
        '''
    
    @staticmethod
    def create_session():
        data = request.json
        session_key = data.get("session_key")
        role = data.get("role")

        # Busca a organização pelo nome
        organization_name = data.get("organization_name")
        organization = Organization.query.filter_by(name=organization_name).first()
        if not organization:
            return jsonify({"error": "Organization not found"}), 404

        # Busca o subject pelo username
        subject = Subject.query.filter_by(username=data.get("username")).first()
        if not subject:
            abort(404, description="Subject not found")

        # Cria uma nova sessão
        new_session = Session(
            identifier=data.get("identifier"),
            session_key=data.get("session_key"),
            password=data.get("password"),
            credentials=data.get("credentials"),
            organization_id=organization.id,  # Associa à organização encontrada
            subject=subject
        )

        db.session.add(new_session)
        db.session.commit()

        # Retorna o contexto da sessão criada
        return jsonify({
            'message': 'Session created successfully',
            'session_context': {
                'session_id': new_session.id,
                'organization_name': organization.name,
                'subject_username': subject.username,
                'session_key': new_session.session_key,
                'identifier': new_session.identifier,
                # Adicione mais campos conforme necessário
            }
        }), 201

