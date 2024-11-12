import base64
import hashlib

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import serialization
from flask import jsonify, request, send_file, abort
from api.models import db, Document, Organization, Session, Subject, Role
from sqlalchemy import text
import mimetypes
from datetime import datetime
from werkzeug.utils import secure_filename
from .utils import *
from . import app  
import os

def check_session(key):
    session = Session.query.filter_by(session_key=key).first()

    if not session or not is_session_valid(session):
        if session:
            db.session.delete(session)  # Exclui a sessão expirada
            db.session.commit()  # Commit para garantir a exclusão no banco
        return None

    # A sessão é válida, pode continuar com o processamento normal
    return session


class DocumentController:
    @staticmethod
    def get_documents_by_session_key(session_key, username=None, date_str=None, filter_type='all'):
        # Encontre a sessão com base na session_key
        session = Session.query.filter_by(session_key=session_key).first()
        if not session:
            return {"error": "Session not found"}, 404

        organization = session.organization

        # Crie a consulta para obter documentos
        query = Document.query.filter_by(organization_id=organization.id)

        if username:
            subject = Subject.query.filter_by(username=username).first()
            if subject:
                query = query.filter_by(creator=subject.username)  # Use o username em vez do id

        if date_str:
            # Converta a data de string para objeto datetime
            from datetime import datetime
            date_obj = datetime.strptime(date_str, '%d-%m-%Y')
            
            if filter_type == 'more_recent':
                query = query.filter(Document.create_date > date_obj)
            elif filter_type == 'older':
                query = query.filter(Document.create_date < date_obj)
            elif filter_type == 'equal':
                query = query.filter(Document.create_date == date_obj)

        documents = query.all()

        return [doc.to_dict() for doc in documents]  # Suponha que você tenha um método to_dict em Document
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
        document = Document.query.filter_by(file_handle=file_handle).first()
        print(f"\nfile fetched : {document.name}")
        if not document:
            return {'error': 'File not found in database'}, 404

        # Recupera a chave criptografada e os dados de criptografia
        print(f"Encrypted file key recuperado para descriptografia: {document.encrypted_file_key}")
        encrypted_file_key = document.encrypted_file_key
        iv = document.iv  # Certifique-se de que o iv está sendo obtido corretamente
        tag = document.tag  # Certifique-se de que o tag está sendo obtido corretamente
        ephemeral_public_key = document.ephemeral_public_key  # Obtém a chave pública efêmera armazenada
        print(f"IV recuperado: {iv}")
        print(f"Tag recuperado: {tag}")

        # Verifica se os dados de criptografia estão presentes
        if not encrypted_file_key or not iv or not tag or not ephemeral_public_key:
            return {'error': 'Cryptography data not found for this document'}, 404

        # Descriptografa a chave do arquivo usando a função de descriptografia
        decrypted_file_key = decrypt_file_key_with_ec_master(encrypted_file_key, iv, tag, ephemeral_public_key)

        # Define o caminho do arquivo usando o file_handle
        file_path = f"./api/uploads/{document.name}"

        # Verifica se o arquivo existe no caminho
        if not os.path.exists(file_path):
            return {'error': 'File not found on server'}, 404

        # Abre o arquivo em modo binário e o retorna na resposta
        with open(file_path, 'rb') as file:
            file_data = file.read()

        # Retorna tanto o conteúdo do arquivo quanto a chave desencriptada
        return {
            'file_key': decrypted_file_key.decode('utf-8'),
            'file_data': file_data,  # Dados binários do arquivo
            'file_name': document.name  # Nome do arquivo
        }, 200  # Retorna uma tupla com resposta e código de status

    '''
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
    '''

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

        # Extrair dados do sujeito
        username = subject_data.get("username")
        full_name = subject_data.get("full_name")
        email = subject_data.get("email")
        public_key = subject_data.get("public_key")

        if not username or not full_name or not email or not public_key:
            return jsonify({'error': 'All subject fields are required'}), 400

        # Validação da chave pública
        try:
            # Carregar a chave pública para verificar se é válida
            public_key_obj = serialization.load_pem_public_key(
                public_key.encode(),  # Converte a chave pública de string para bytes
                backend=None
            )
        except (ValueError, InvalidKey) as e:
            return jsonify({'error': 'Invalid public key format'}), 400

        # Criar organização
        organization = Organization(name=org_name)

        # Criar sujeito
        subject = Subject(
            username=username,
            full_name=full_name,
            email=email,
            public_key=public_key  # Armazena a chave pública
        )

        # Salvar ambas as entidades no banco de dados
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
    def delete_document_from_organization(session_key, document_name):
        # Obter a sessão associada à session key
        session = check_session(session_key)
        if session is None:
            return {"error": "Sessão inválida ou não encontrada"}, 404

        # Obter a organização associada à sessão
        organization = session.organization
        if not organization:
            return {"success": False, "message": "No organization associated with this session"}


        # Buscar o documento na base de dados
        document = db.session.query(Document).filter_by(
            organization_id=organization.id, document_handle=document_name
        ).first()

        print(f"Encrypted file key recuperado para descriptografia: {document.encrypted_file_key}")
        encrypted_file_key = document.encrypted_file_key
        iv = document.iv  # Certifique-se de que o iv está sendo obtido corretamente
        tag = document.tag  # Certifique-se de que o tag está sendo obtido corretamente
        ephemeral_public_key = document.ephemeral_public_key  # Obtém a chave pública efêmera armazenada
        print(f"IV recuperado: {iv}")
        print(f"Tag recuperado: {tag}")

        # Verifica se os dados de criptografia estão presentes
        if not encrypted_file_key or not iv or not tag or not ephemeral_public_key:
            return {'error': 'Cryptography data not found for this document'}, 404

        # Descriptografa a chave do arquivo usando a função de descriptografia
        decrypted_file_key = decrypt_file_key_with_ec_master(encrypted_file_key, iv, tag, ephemeral_public_key)

        if document:
            # Deletar o arquivo do sistema de arquivos
            try:
                file_path = f"./api/uploads/{document.name}"  # Usar o caminho do arquivo armazenado
                if os.path.exists(file_path):
                    os.remove(file_path)

                # Deletar o documento da base de dados
                db.session.delete(document)
                db.session.commit()
                return jsonify({"success": True, "message": "Document deleted successfully", "file_key":decrypted_file_key.hex(), "file_handle":document.file_handle}), 200
            except Exception as e:
                return {"success": False, "message": str(e)}, 404
        else:
            return {"success": False, "message": "Document not found"}, 400

    @staticmethod
    def download_document(session_key, document_name):
        # Verifica a sessão e a organização correspondente
        session = check_session(session_key)
        if session is None:
            return {"error": "Sessão inválida ou não encontrada"}, 404
        
        organization = session.organization

        # Busca o documento na organização especificada
        document = Document.query.filter_by(
            organization_id=organization.id, document_handle=document_name
        ).first()

        if not document:
            return None  # Documento não encontrado

        # Retorna o arquivo para download
        file_path = document.file_handle
        try:
            return send_file(file_path, as_attachment=True)
        except FileNotFoundError:
            return None  # Arquivo não encontrado
        except Exception as e:
            print(f"Erro ao enviar arquivo: {e}")
            return None

    @staticmethod
    def get_document_metadata(session_key, document_name):
        # Verifica a sessão e a organização correspondente
        session = check_session(session_key)
        if session is None:
            return jsonify({"error": "Sessão inválida ou não encontrada"}), 404

        organization = session.organization

        # Busca o documento na organização especificada
        document = Document.query.filter_by(
            organization_id=organization.id, document_handle=document_name
        ).first()

        if not document:
            return jsonify({"error": "Documento não encontrado na organização"}), 404

        # Lê o arquivo criptografado
        file_path = document.file_handle

        # Recupera a chave criptografada do arquivo
        encrypted_file_key = document.encrypted_file_key

        # Retornar metadados do documento e a chave criptografada
        metadata = {
            "document_id": document.id,
            "document_name": document.name,
            "create_date": document.create_date,
            "creator": document.creator,
            "organization_id": document.organization_id,
            "file_handle": document.file_handle,
            "file_key": encrypted_file_key.hex()  # Retorna a chave criptografada em formato hexadecimal
        }

        # Certifique-se de que todos os dados são serializáveis
        # Convertendo valores como datetime para string, por exemplo
        metadata["create_date"] = metadata["create_date"].isoformat() if isinstance(metadata["create_date"],
                                                                                    datetime) else metadata[
            "create_date"]

        # Retornar os metadados em JSON diretamente com jsonify
        return {"metadata": metadata}, 200

    @staticmethod
    def upload_document_to_organization(session_key, file_name, file, file_encryption_key, file_handle,
                                        private_key_path="master_key.pem.pub"):
        # Verifica a sessão e a organização correspondente
        session = check_session(session_key)
        if session is None:
            return {"error": "Sessão inválida ou não encontrada"}, 404

        organization = session.organization
        subject = session.subject

        # Salva o arquivo de forma segura
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_name)
        file.seek(0)  # Move o ponteiro de leitura do arquivo para o início antes de salvar
        file.save(filepath)

        # Carrega a chave pública para a criptografia da chave do arquivo
        public_key = load_ec_public_key(private_key_path)

        # Criptografa a chave do arquivo com a chave pública mestre
        encrypted_file_key, ephemeral_public_key, iv, tag = encrypt_file_key_with_ec_master(
            file_encryption_key, public_key
        )
        print(f"Encrypted file key durante criptografia: {encrypted_file_key}")
        print(f"IV gerado: {iv}")
        print(f"Tag gerado: {tag}")

        # Serializa a chave pública efêmera para armazenamento no banco de dados
        ephemeral_public_key_serialized = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Cria um novo documento, armazenando `iv`, `tag` e `ephemeral_public_key`
        new_document = Document(
            document_handle=file_name,
            name=file_name,
            create_date=datetime.now(),
            creator=subject.username,
            file_handle=file_handle,
            acl={},
            organization_id=organization.id,
            encrypted_file_key=encrypted_file_key,  # Salva a chave de criptografia criptografada
            iv=iv,  # Armazena o IV diretamente
            tag=tag,  # Armazena o TAG diretamente
            ephemeral_public_key=ephemeral_public_key_serialized  # Armazena a chave pública efêmera
        )

        # Adiciona e salva o documento no banco de dados
        db.session.add(new_document)
        db.session.commit()

        return {"message": "Documento adicionado com sucesso", "document_id": new_document.id}, 201

    @staticmethod
    def add_document_to_organization(session_key, document_name, file_handle):
        session = check_session(session_key)
        if session is None:
            return {"error": "Sessão inválida ou não encontrada"}, 404

        # Obtém a organização e o subject associados à sessão
        organization = session.organization
        subject = session.subject
        if not organization or not subject:
            return {"error": "Organização ou Subject associado à sessão não encontrado."}

        # Cria um novo Document associado à organização e ao subject como criador
        new_document = Document(
            document_handle=f"handle_{datetime.utcnow().timestamp()}",
            name=document_name,
            create_date=datetime.utcnow(),
            creator=subject.username,  # Nome do usuário associado ao Subject como criador
            file_handle=file_handle,
            acl={},  # ACL padrão ou configurável
            organization_id=organization.id
        )

        # Adiciona e confirma a transação
        try:
            db.session.add(new_document)
            db.session.commit()
            return {"id": new_document.id, "message": "Documento adicionado com sucesso."}
        except Exception as e:
            db.session.rollback()
            return {"error": f"Ocorreu um erro ao adicionar o documento: {str(e)}"}

    @staticmethod
    def add_subject_to_organization(session_key, username, name, email, public_key):
        session = check_session(session_key)
        if session is None:
            return {"error": "Sessão inválida ou não encontrada"}, 404

        organization = session.organization
        if not organization:
            return {"error": "Organização associada à sessão não encontrada."}

        # Verifique se o username já existe na organização
        existing_subject = Subject.query.filter_by(username=username).first()
        if existing_subject:
            return {"error": "Um usuário com esse username já existe."}

        # Crie um novo Subject e o associe à organização
        new_subject = Subject(
            username=username,
            full_name=name,
            email=email,
            public_key=public_key
        )

        # Adicione e confirme a transação
        try:
            db.session.add(new_subject)
            db.session.commit()
            return {"id": new_subject.id, "message": "Sujeito adicionado com sucesso."}
        except Exception as e:
            db.session.rollback()
            return {"error": f"Ocorreu um erro ao adicionar o sujeito: {str(e)}"}

    @staticmethod
    def get_roles_by_session_key(session_key):
        session = check_session(session_key)
        if session is None:
            return {"error": "Sessão inválida ou não encontrada"}, 404
        
        organization = session.organization  # Obtém a organização associada à sessão
        if not organization:
            return jsonify({"error": "Organization not found"}), 404
        
        # Obter todos os roles associados à organização
        roles = Role.query.filter_by(organization_id=organization.id).all()
        
        return jsonify([{
            'id': role.id, 
            'name': role.name, 
            'permissions': role.permissions
        } for role in roles]), 200

    @staticmethod
    def get_subjects_by_session_key(session_key):
        session = check_session(session_key)
        if session is None:
            return {"error": "Sessão inválida ou não encontrada"}, 404
        
        organization = session.organization  # Obtém a organização associada à sessão
        if not organization:
            return jsonify({"error": "Organization not found"}), 404
        
        # Obter todos os subjects associados à mesma organização através de suas sessões
        subjects = Subject.query.join(Session).filter(Session.organization_id == organization.id).all()
        
        return jsonify([{
            'id': subject.id, 
            'username': subject.username, 
            'full_name': subject.full_name, 
            'email': subject.email
        } for subject in subjects]), 200
    @staticmethod
    def list_session_roles(session_key):
        session = check_session(session_key)
        if session is None:
            return {"error": "Sessão inválida ou não encontrada"}, 404
        
        roles = [role.name for role in session.roles]
        return jsonify({"roles": roles}), 200

    
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

    @staticmethod
    def assume_role():
        data = request.json
        session_key = data.get("session_key")
        role_name = data.get("role")

        # Busca a sessão pelo campo `keys`
        session = check_session(session_key)
        if session is None:
            return {"error": "Sessão inválida ou não encontrada"}, 404
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