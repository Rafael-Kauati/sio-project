import base64
import binascii
import hashlib
import json
import random
import secrets
import string
import uuid

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from flask import jsonify, abort
from api.models import db, Document, Permission, RolePermission, AuthenticationID, Organization, Session, Subject, Role, \
    Nonce, subject_organization
from werkzeug.utils import secure_filename
from .utils import *
from . import app
import os
import jwt

from flask import request

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64


def check_session(session_key):
    try:
        # Decode and validate the JWT signature
        payload = jwt.decode(
            session_key,
            SessionController.SECRET_KEY,
            algorithms=["HS256"]
        )
    except jwt.ExpiredSignatureError:
        return None, "Session token has expired."
    except jwt.InvalidTokenError as e:
        return None, f"Invalid session token: {str(e)}"

    # Busca a sessão no banco usando a chave de sessão descriptografada
    session = Session.query.filter_by(session_key=session_key).first()
    if not session:
        return None  # Se não encontrar a sessão, retorna None
    is_valid = is_session_valid(session)
    if not is_valid:
        return None  # Se estiver expirada

    # A sessão foi encontrada e é válida
    return session

@staticmethod
def has_permission(session_key, username, permission_name):
    # Verificar a sessão
    session = check_session(session_key)
    if session is None:
        print("[DEBUG] Sessão inválida ou não encontrada.")
        return False

    # Obter a organização associada à sessão
    organization = session.organization
    if not organization:
        print("[DEBUG] Organização não encontrada para esta sessão.")
        return False

    # Buscar o subject pelo username
    subject = Subject.query.filter_by(username=username).first()
    if not subject:
        print(f"[DEBUG] Subject '{username}' não encontrado.")
        return False

    # Verificar se o subject pertence à organização
    if organization not in subject.organizations:
        print(f"[DEBUG] Subject '{username}' não pertence à organização '{organization.name}'.")
        return False

    # Buscar a permissão pelo nome
    permission = Permission.query.filter_by(name=permission_name).first()
    if not permission:
        print(f"[DEBUG] Permissão '{permission_name}' não encontrada.")
        return False

    # Iterar pelas roles associadas ao subject
    for role in subject.roles:
        print(f"[DEBUG] Verificando role '{role.name}' para o subject '{subject.username}'.")

        # Verificar se a role pertence à mesma organização
        if role.organization_id != organization.id:
            print(f"[DEBUG] Role '{role.name}' não pertence à organização '{organization.name}'. Ignorando.")
            continue

        # Verificar se a role está suspensa
        if role.is_suspended:
            print(f"[DEBUG] Role '{role.name}' está suspensa. Ignorando.")
            continue

        # Verificar se a role está assumida pelo usuário na sessão
        if role not in session.roles:
            print(f"[DEBUG] Role '{role.name}' não está assumida na sessão. Ignorando.")
            continue

        # Verificar se a role possui a permissão
        if any(rp.permission_id == permission.id for rp in role.permissions):
            print(f"[DEBUG] Permissão '{permission_name}' encontrada na role '{role.name}'.")
            return True
        else:
            print(f"[DEBUG] Permissão '{permission_name}' não encontrada na role '{role.name}'.")

    # Se nenhuma role passou nos critérios
    print(f"[DEBUG] Nenhuma role do subject '{subject.username}' atende a todos os critérios.")
    return False

class DocumentController:
    @staticmethod
    def get_documents_by_session_key(session_key, username=None, date_str=None, filter_type='all'):
        # Encontre a sessão com base na session_key
        session = check_session(session_key)
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
    def download_document(file_handle):
        '''existing_nonce = Nonce.query.filter_by(nonce=nonce).first()
        if existing_nonce:
            return jsonify({"error": "Nonce já utilizado. Replay detectado!"}), 400
        else:
            # Se o nonce não existe, insira-o na tabela
            new_nonce = Nonce(nonce=nonce)
            db.session.add(new_nonce)
            db.session.commit()'''
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
        print(f"\n file key recupada da encryptaçao : {decrypted_file_key}")
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
            # 'file_key': decrypted_file_key.decode('utf-8'),
            'file_data': file_data,  # Dados binários do arquivo
            'file_name': document.name  # Nome do arquivo
        }, 200  # Retorna uma tupla com resposta e código de status


class OrganizationController:
    @staticmethod
    def create_organization():
        try:
            # Extrair e descriptografar a chave ChaCha20 e o nonce do cabeçalho
            encrypted_key_info = request.headers.get("X-Encrypted-Key-Info")
            if not encrypted_key_info:
                return jsonify({"error": "Encrypted key info is missing"}), 400

            key_info = json.loads(encrypted_key_info)
            private_key_path = "private_key.pem"

            # Descriptografar a chave ChaCha20 e o nonce
            encrypted_key = binascii.unhexlify(key_info["key"])
            encrypted_nonce = binascii.unhexlify(key_info["nonce"])
            chacha_key = decrypt_with_private_key(private_key_path, encrypted_key)
            chacha_nonce = decrypt_with_private_key(private_key_path, encrypted_nonce)

            # Descriptografar o payload da requisição
            encrypted_payload = request.json.get("encrypted_payload")
            if not encrypted_payload:
                return jsonify({"error": "Encrypted payload is missing"}), 400
            encrypted_payload = binascii.unhexlify(encrypted_payload)
            decrypted_payload = decrypt_with_chacha20(chacha_key, chacha_nonce, encrypted_payload)
            payload_data = json.loads(decrypted_payload)

            # Extrair dados do payload
            org_name = payload_data.get("name")
            subject_data = payload_data.get("subject")
            public_key = payload_data.get("public_key")
            if not org_name or not subject_data or not public_key:
                return jsonify(
                    {'error': f'Organization name, subject and subject public data are required {payload_data}'}), 400

            # Extrair dados do sujeito
            username = subject_data.get("username")
            full_name = subject_data.get("full_name")
            email = subject_data.get("email")

            if not username or not full_name or not email:
                return jsonify({'error': 'All subject fields are required'}), 400

            # Criar instâncias
            organization = Organization(name=org_name)
            subject = Subject(
                username=username,
                full_name=full_name,
                email=email,
                public_key=public_key
            )

            # Criar a role "Manager" e associar permissões
            manager_role = Role(name="Manager", organization=organization)
            db.session.add(manager_role)

            # Associar todas as permissões existentes à role "Manager"
            permissions = Permission.query.all()  # Recupera todas as permissões da tabela 'permissions'
            for permission in permissions:
                role_permission = RolePermission(role=manager_role, permission=permission)
                db.session.add(role_permission)

            # Adicionar o sujeito à organização
            organization.subjects.append(subject)

            # Associar a role "Manager" apenas ao sujeito recém-criado
            subject.roles.append(manager_role)

            # Salvar entidades no banco de dados
            db.session.commit()

            return jsonify({
                               'message': 'Organization and subject created successfully, and role "Manager" created and associated'}), 201

        except binascii.Error:
            return jsonify({"error": "Invalid hexadecimal data in headers or payload"}), 400
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    @staticmethod
    def list_organizations():
        organizations = Organization.query.all()
        return jsonify([org.name for org in organizations]), 200


class SessionController:

    SECRET_KEY = "ultra_secret_repo_key"

    @staticmethod
    def get_session_by_key(session_key):
        return Session.query.filter_by(session_key=session_key).first()

    @staticmethod
    def delete_document_from_organization(session_key, nonce, document_name):
        # Obter a sessão associada à session key
        session = check_session(session_key)
        if session is None:
            return {"error": "Sessão inválida ou não encontrada"}, 404

        existing_nonce = Nonce.query.filter_by(nonce=nonce).first()
        if not existing_nonce:
            return jsonify({"error": "Nonce inválido ou não encontrado."}), 400

        if existing_nonce.used:
            return jsonify({"error": "Nonce já utilizado. Replay detectado!"}), 400

        # Marcar o nonce como usado
        existing_nonce.used = True
        db.session.commit()

        # Gerar um novo nonce exclusivo
        new_nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        while Nonce.query.filter_by(nonce=new_nonce).first():
            new_nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

        # Salvar o novo nonce
        new_nonce_entry = Nonce(nonce=new_nonce, used=False)
        db.session.add(new_nonce_entry)
        db.session.commit()

        # Obter a organização associada à sessão
        organization = session.organization
        if not organization:
            return {"success": False, "message": "No organization associated with this session",
                    "new_nonce": new_nonce}, 404

        # Obter o subject associado à sessão
        subject = session.subject
        if not subject:
            return {"success": False, "message": "No subject associated with this session", "new_nonce": new_nonce}, 404

        # Buscar o documento na base de dados
        document = db.session.query(Document).filter_by(
            organization_id=organization.id, name=document_name
        ).first()

        if not document:
            return {"success": False, "message": "Document not found",
                    "new_nonce": new_nonce}, 404

        # Verificar se os dados de criptografia estão presentes
        encrypted_file_key = document.encrypted_file_key
        iv = document.iv
        tag = document.tag
        ephemeral_public_key = document.ephemeral_public_key

        if not encrypted_file_key or not iv or not tag or not ephemeral_public_key:
            return {'error': 'Cryptography data not found for this document',
                    "new_nonce": new_nonce}, 404

        # Descriptografar a chave do arquivo
        try:
            decrypted_file_key = decrypt_file_key_with_ec_master(encrypted_file_key, iv, tag, ephemeral_public_key)
        except Exception as e:
            return {'error': f'Failed to decrypt file key: {str(e)}'}, 500

        # Limpar os dados do documento no banco de dados
        try:
            file_handle = document.file_handle
            document.file_handle = None
            document.encrypted_file_key = None
            encryption_metadata = document.encryption_vars
            document.encryption_vars = None
            document.deleter = subject.username  # Registrar o deleter
            db.session.commit()

            return {
                "success": True,
                "message": "Document content deleted successfully",
                "document name": document.name,
                "file_key": decrypted_file_key.hex(),
                "file_handle": file_handle,
                "encryption_metadata": encryption_metadata,
                "new_nonce": new_nonce
            }, 200
        except Exception as e:
            db.session.rollback()
            return {"success": False, "message": f"Failed to update document: {str(e)}"}, 500

    @staticmethod
    def get_document_metadata(session_key, document_name):
        # Verifica a sessão e a organização correspondente
        session = check_session(session_key)
        if session is None:
            return jsonify({"error": "Sessão inválida ou não encontrada"}), 404

        '''# Verifica se o nonce já foi usado para a sessão
        existing_nonce = Nonce.query.filter_by(nonce=nonce).first()
        if existing_nonce:
            return jsonify({"error": "Nonce já utilizado. Replay detectado!"}), 400
        else:
            # Se o nonce não existe, insira-o na tabela
            new_nonce = Nonce(nonce=nonce)
            db.session.add(new_nonce)
            db.session.commit()'''

        organization = session.organization

        # Busca o documento na organização especificada
        document = Document.query.filter_by(
            organization_id=organization.id, name=document_name
        ).first()

        if not document:
            return jsonify({"error": "Documento não encontrado na organização"}), 404

        # Lê o arquivo criptografado
        file_path = document.file_handle

        # Recupera a chave criptografada do arquivo
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

        decrypted_file_key = decrypt_file_key_with_ec_master(encrypted_file_key, iv, tag, ephemeral_public_key)
        print(f"\n file key recupada da encryptaçao : {decrypted_file_key}")

        # Retornar metadados do documento e a chave criptografada
        metadata = {
            "document_id": document.id,
            "document_name": document.name,
            "create_date": document.create_date,
            "creator": document.creator,
            "organization_id": document.organization_id,
            "file_handle": document.file_handle,
            "file_key": decrypted_file_key.decode('utf-8'),
            "encryption_vars": json.dumps(document.encryption_vars)
        }

        # Certifique-se de que todos os dados são serializáveis
        # Convertendo valores como datetime para string, por exemplo
        metadata["create_date"] = metadata["create_date"].isoformat() if isinstance(metadata["create_date"],
                                                                                    datetime) else metadata[
            "create_date"]

        # Retornar os metadados em JSON diretamente com jsonify
        return {"metadata": metadata}, 200

    @staticmethod
    def upload_document_to_organization(session_key, nonce, file_name, file, file_handle, file_encryption_key,
                                        encryption_vars,
                                        private_key_path="master_key.pem.pub"):
        # Verifica a sessão e a organização correspondente
        session = check_session(session_key)
        if session is None:
            return {"error": "Sessão inválida ou não encontrada"}, 404

        existing_nonce = Nonce.query.filter_by(nonce=nonce).first()
        if not existing_nonce:
            return jsonify({"error": "Nonce inválido ou não encontrado."}), 400

        if existing_nonce.used:
            return jsonify({"error": "Nonce já utilizado. Replay detectado!"}), 400

        # Marcar o nonce como usado
        existing_nonce.used = True
        db.session.commit()

        # Gerar um novo nonce exclusivo
        new_nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        while Nonce.query.filter_by(nonce=new_nonce).first():
            new_nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

        # Salvar o novo nonce
        new_nonce_entry = Nonce(nonce=new_nonce, used=False)
        db.session.add(new_nonce_entry)
        db.session.commit()

        organization = session.organization
        subject = session.subject

        # Salva o arquivo de forma segura
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_name)
        file.seek(0)  # Move o ponteiro de leitura do arquivo para o início antes de salvar
        file.save(filepath)
        print(f"Encrypting vars received: {json.loads(encryption_vars)}")

        # Carrega a chave pública para a criptografia da chave do arquivo
        public_key = load_ec_public_key(private_key_path)
        print(f" file key antes de encryptaçao: {file_encryption_key}")
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

        # Cria um novo documento, incluindo o campo `encryption_vars`
        new_document = Document(
            # document_handle=file_name,
            name=file_name,
            create_date=datetime.now(),
            creator=subject.username,
            file_handle=file_handle,
            acl={},
            organization_id=organization.id,
            encrypted_file_key=encrypted_file_key,  # Salva a chave de criptografia criptografada
            iv=iv,  # Armazena o IV diretamente
            tag=tag,  # Armazena o TAG diretamente
            ephemeral_public_key=ephemeral_public_key_serialized,  # Armazena a chave pública efêmera
            encryption_vars=json.loads(encryption_vars)  # Converte o JSON de string para dicionário e armazena
        )

        # Adiciona e salva o documento no banco de dados
        db.session.add(new_document)
        db.session.commit()

        return {"message": "Documento adicionado com sucesso",
                "document_id": new_document.id, "new_nonce": new_nonce}, 201

    @staticmethod
    def add_subject_to_organization(session_key, nonce, username, name, email, public_key):

        existing_nonce = Nonce.query.filter_by(nonce=nonce).first()
        if not existing_nonce:
            return jsonify({"error": "Nonce inválido ou não encontrado."}), 400

        if existing_nonce.used:
            return jsonify({"error": "Nonce já utilizado. Replay detectado!"}), 400

        # Marcar o nonce como usado
        existing_nonce.used = True
        db.session.commit()

        # Gerar um novo nonce exclusivo
        new_nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        while Nonce.query.filter_by(nonce=new_nonce).first():
            new_nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

        # Salvar o novo nonce
        new_nonce_entry = Nonce(nonce=new_nonce, used=False)
        db.session.add(new_nonce_entry)
        db.session.commit()

        session = check_session(session_key)
        if session is None:
            return {"error": "Sessão inválida ou não encontrada", "new_nonce": new_nonce}, 404

        # Verificar organização associada à sessão
        organization = session.organization
        if not organization:
            return {"error": "Organização associada à sessão não encontrada."
                , "new_nonce": new_nonce}, 404
        print(f"Username: {username}, Name: {name}, Email: {email}")
        # Verificar se o username já existe na organização
        existing_subject = db.session.query(Subject).join(subject_organization).filter(
            subject_organization.c.organization_id == organization.id,
            Subject.username == username
        ).first()
        if existing_subject:
            print(f"Existing subject: {existing_subject}")
            return {"error": "Um usuário com esse username já existe nesta organização."
                , "new_nonce": new_nonce}, 400

        # Criar novo Subject e associá-lo à organização
        new_subject = Subject(
            username=username,
            full_name=name,
            email=email,
            public_key=public_key
        )

        try:
            # Associar o novo Subject à organização usando a tabela de relacionamento
            organization.subjects.append(new_subject)

            # Persistir no banco de dados
            db.session.add(new_subject)
            db.session.commit()

            return {"id": new_subject.id, "message": "Sujeito adicionado com sucesso."
                , "new_nonce": new_nonce}, 201
        except Exception as e:
            db.session.rollback()
            return {"error": f"Ocorreu um erro ao adicionar o sujeito: {str(e)}"}, 500

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
        """
        Obtém os subjects associados à organização da sessão após validar o nonce.
        """
        # Valida a sessão
        session = check_session(session_key)
        if session is None:
            return jsonify({"error": "Sessão inválida ou não encontrada"}), 404

        # Verifica se o nonce já foi usado
        '''existing_nonce = Nonce.query.filter_by(nonce=nonce).first()
        if existing_nonce:
            return jsonify({"error": "Nonce já utilizado. Replay detectado!"}), 400
        else:
            # Insere o nonce na tabela
            new_nonce = Nonce(nonce=nonce)
            db.session.add(new_nonce)
            db.session.commit()'''

        # Obtém a organização associada à sessão
        organization = session.organization
        if not organization:
            return jsonify({"error": "Organização não encontrada"}), 404

        # Obtém todos os subjects associados à organização pela tabela de relacionamento
        subjects = organization.subjects

        # Retorna os subjects associados
        return jsonify([{
            'id': subject.id,
            'username': subject.username,
            'full_name': subject.full_name,
            'email': subject.email
        } for subject in subjects]), 200

    @staticmethod
    def list_session_roles(session_key):
        # Verificar a sessão e obter informações
        session = check_session(session_key)
        if session is None:
            return jsonify({"error": "Sessão inválida ou não encontrada"}), 404

        # Obter o subject associado à sessão
        subject = session.subject
        if not subject:
            return jsonify({"error": "Subject não encontrado para esta sessão"}), 404

        # Obter as roles associadas ao subject
        roles = subject.roles
        roles_data = [{"id": role.id, "name": role.name, "organization_id": role.organization_id} for role in roles]

        return jsonify({"roles": roles_data}), 200

    @staticmethod
    def create_session():
        data = request.json

        # Extract encrypted key info
        encrypted_key_info = request.headers.get("X-Encrypted-Key-Info")
        if not encrypted_key_info:
            return jsonify({"error": "Encrypted key info is missing"}), 400
        key_info = json.loads(encrypted_key_info)
        private_key_path = "private_key.pem"

        # Decrypt the ChaCha20 key and nonce
        encrypted_key = binascii.unhexlify(key_info["key"])
        encrypted_nonce = binascii.unhexlify(key_info["nonce"])
        chacha_key = decrypt_with_private_key(private_key_path, encrypted_key)
        chacha_nonce = decrypt_with_private_key(private_key_path, encrypted_nonce)

        # Decrypt the payload
        encrypted_payload = request.json.get("encrypted_payload")
        if not encrypted_payload:
            return jsonify({"error": "Encrypted payload is missing"}), 400
        encrypted_payload = binascii.unhexlify(encrypted_payload)
        decrypted_payload = decrypt_with_chacha20(chacha_key, chacha_nonce, encrypted_payload)
        data = json.loads(decrypted_payload)

        # Extract signed_nonce and nonce from the payload
        signed_nonce = binascii.unhexlify(data.get("signed_nonce", ""))
        nonce = data.get("nonce", "")
        if not signed_nonce or not nonce:
            return jsonify({"error": "Missing signed_nonce or nonce in the payload"}), 400

        # Fetch the subject by username
        subject = Subject.query.filter_by(username=data.get("username")).first()
        if not subject:
            return jsonify({"error": "Subject not found"}), 404

        # Verify the signature
        try:
            public_key_pem = subject.public_key.encode()
            public_key = load_pem_public_key(public_key_pem, backend=default_backend())

            # Verify the signature
            public_key.verify(
                signed_nonce,  # Signature
                nonce.encode(),  # Original data
                ec.ECDSA(hashes.SHA256())  # Same algorithm used to sign
            )
        except Exception as e:
            return jsonify({"error": f"Signature validation failed: {str(e)}"}), 400

        # Check if an AuthenticationID with the same nonce exists
        existing_auth_id = AuthenticationID.query.filter_by(nonce=nonce).join(Subject).filter(
            Subject.username == subject.username).first()
        if existing_auth_id:
            return jsonify({"error": "Nonce already exists for this user"}), 400

        new_auth_id = AuthenticationID(nonce=nonce, subject=subject)
        db.session.add(new_auth_id)
        db.session.commit()

        # Generate JWT as session_key
        created_at = datetime.now(timezone.utc)
        expiration_time = created_at + timedelta(minutes=15)  # Token valid for 15 minutes
        payload = {
            "session_id": new_auth_id.id,  # Unique session identifier
            "organization_name": data.get("organization_name"),  # Organization name
            "subject_username": subject.username,  # Username of the subject
            "iat": created_at,  # Issued at
            "exp": expiration_time,  # Expiration time
            "jti": str(uuid.uuid4()),  # Unique identifier for this token
        }

        session_key = jwt.encode(payload, SessionController.SECRET_KEY, algorithm="HS256")

        # Save the session to the database
        organization_name = data.get("organization_name")
        organization = Organization.query.filter_by(name=organization_name).first()
        if not organization:
            return jsonify({"error": "Organization not found"}), 404

        new_session = Session(
            session_key=session_key,  # Store the JWT here
            password=data.get("password"),
            credentials=data.get("credentials"),
            organization_id=organization.id,
            subject=subject,
            created_at=created_at  # Store the creation time for server-side expiration
        )

        db.session.add(new_session)
        db.session.commit()

        # Gerar um nonce exclusivo
        nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

        # Verificar se já existe um nonce idêntico
        while Nonce.query.filter_by(nonce=nonce).first():
            nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

        # Criar e salvar o nonce
        new_nonce = Nonce(nonce=nonce, used=False)
        db.session.add(new_nonce)
        db.session.commit()

        return jsonify({
            'message': 'Session created successfully',
            'session_context': {
                'session_id': new_session.id,
                'organization_name': organization.name,
                'subject_username': subject.username,
                'session_token': session_key,  # JWT returned to the client
                'nonce': nonce
            }
        }), 201

    @staticmethod
    def generate_session_key(length=32):
        characters = string.ascii_letters + string.digits  # Letras maiúsculas, minúsculas e números
        session_key = ''.join(secrets.choice(characters) for _ in range(length))
        return session_key

    @staticmethod
    def add_access_of_role_to_subject(session_key, role_name, username):
        # Verificar a sessão
        session = check_session(session_key)
        if session is None:
            return jsonify({"error": "Sessão inválida ou não encontrada"}), 404

        # Obter a organização associada à sessão
        organization = session.organization
        if not organization:
            return jsonify({"error": "Organização não encontrada para esta sessão"}), 404

        # Buscar a role na organização
        role = Role.query.filter_by(name=role_name, organization_id=organization.id).first()
        if not role:
            return jsonify({"error": f"Role '{role_name}' não encontrada na organização"}), 404

        # Buscar o subject pelo username
        subject = Subject.query.filter_by(username=username).first()
        if not subject:
            return jsonify({"error": f"Subject com username '{username}' não encontrado"}), 404

        # Verificar se o subject pertence à organização
        if organization not in subject.organizations:
            return jsonify({"error": f"Subject '{username}' não pertence à organização"}), 400

        # Verificar se a role já está acessível ao subject
        if role in subject.accessible_roles:
            return jsonify({"message": f"Role '{role_name}' já está acessível ao subject '{username}'"}), 200

        # Tornar a role acessível ao subject
        subject.accessible_roles.append(role)
        db.session.commit()

        return jsonify({"message": f"Role '{role_name}' tornou-se acessível ao subject '{username}' com sucesso!"}), 200

    @staticmethod
    def remove_access_of_role_to_subject(session_key, role_name, username):
        # Verificar a sessão
        session = check_session(session_key)
        if session is None:
            return jsonify({"error": "Sessão inválida ou não encontrada"}), 404

        # Obter a organização associada à sessão
        organization = session.organization
        if not organization:
            return jsonify({"error": "Organização não encontrada para esta sessão"}), 404

        # Buscar a role na organização
        role = Role.query.filter_by(name=role_name, organization_id=organization.id).first()
        if not role:
            return jsonify({"error": f"Role '{role_name}' não encontrada na organização"}), 404

        # Buscar o subject pelo username
        subject = Subject.query.filter_by(username=username).first()
        if not subject:
            return jsonify({"error": f"Subject com username '{username}' não encontrado"}), 404

        # Verificar se o subject pertence à organização
        if organization not in subject.organizations:
            return jsonify({"error": f"Subject '{username}' não pertence à organização"}), 400

        # Verificar se a role está acessível ao subject
        if role not in subject.accessible_roles:
            return jsonify({"error": f"Role '{role_name}' não está acessível ao subject '{username}'"}), 404

        # Remover o acesso da role ao subject
        subject.accessible_roles.remove(role)

        # Verificar se a role está diretamente associada ao subject e desassociar se necessário
        if role in subject.roles:
            subject.roles.remove(role)

        db.session.commit()

        return jsonify({"message": f"Acesso da role '{role_name}' removido do subject '{username}' com sucesso!"}), 200

    @staticmethod
    def add_permission_to_role(session_key, role_name, permission_name):
        # Verificar a sessão
        session = check_session(session_key)
        if session is None:
            return jsonify({"error": "Sessão inválida ou não encontrada"}), 404

        # Obter a organização associada à sessão
        organization = session.organization
        if not organization:
            return jsonify({"error": "Organização não encontrada para esta sessão"}), 404

        # Buscar a role na organização
        role = Role.query.filter_by(name=role_name, organization_id=organization.id).first()
        if not role:
            return jsonify({"error": f"Role '{role_name}' não encontrada na organização"}), 404

        # Buscar a permissão pela tabela de permissões
        permission = Permission.query.filter_by(name=permission_name).first()
        if not permission:
            return jsonify({"error": f"Permissão '{permission_name}' não encontrada"}), 404

        # Verificar se a permissão já está associada à role
        if any(rp.permission_id == permission.id for rp in role.permissions):
            return jsonify({"message": f"Permissão '{permission_name}' já está associada à role '{role_name}'"}), 200

        # Criar associação entre role e permission
        role_permission = RolePermission(role_id=role.id, permission_id=permission.id)
        db.session.add(role_permission)
        db.session.commit()
        response = f"Permissão '{permission_name}' associada à role '{role_name}' com sucesso!"
        print(response)
        return jsonify({"message": f"Permissão '{permission_name}' associada à role '{role_name}' com sucesso!"}), 200

    @staticmethod
    def remove_permission_from_role(session_key, role_name, permission_name):
        # Verificar a sessão
        session = check_session(session_key)
        if session is None:
            return jsonify({"error": "Sessão inválida ou não encontrada"}), 404

        # Obter a organização associada à sessão
        organization = session.organization
        if not organization:
            return jsonify({"error": "Organização não encontrada para esta sessão"}), 404

        # Buscar a role na organização
        role = Role.query.filter_by(name=role_name, organization_id=organization.id).first()
        if not role:
            return jsonify({"error": f"Role '{role_name}' não encontrada na organização"}), 404

        # Buscar a permissão pela tabela de permissões
        permission = Permission.query.filter_by(name=permission_name).first()
        if not permission:
            return jsonify({"error": f"Permissão '{permission_name}' não encontrada"}), 404

        # Verificar se a permissão está associada à role
        role_permission = RolePermission.query.filter_by(role_id=role.id, permission_id=permission.id).first()
        if not role_permission:
            return jsonify({"error": f"Permissão '{permission_name}' não está associada à role '{role_name}'"}), 404

        # Remover a permissão da role
        db.session.delete(role_permission)
        db.session.commit()

        return jsonify({"message": f"Permissão '{permission_name}' removida da role '{role_name}' com sucesso!"}), 200

    @staticmethod
    def suspend_role(session_key, role_name):
        # Verificar a sessão
        session = check_session(session_key)
        if session is None:
            return jsonify({"error": "Sessão inválida ou não encontrada"}), 404

        # Obter a organização associada à sessão
        organization = session.organization
        if not organization:
            return jsonify({"error": "Organização não encontrada para esta sessão"}), 404

        # Buscar a role na organização
        role = Role.query.filter_by(name=role_name, organization_id=organization.id).first()
        if not role:
            return jsonify({"error": f"Role '{role_name}' não encontrada na organização"}), 404

        # Verificar se a role já está suspensa
        if role.is_suspended:
            return jsonify({"message": f"Role '{role_name}' já está suspensa"}), 200

        # Suspender a role
        role.is_suspended = True
        db.session.commit()

        return jsonify({"message": f"Role '{role_name}' suspensa com sucesso!"}), 200

    @staticmethod
    def reactivate_role(session_key, role_name):
        # Verificar a sessão
        session = check_session(session_key)
        if session is None:
            return jsonify({"error": "Sessão inválida ou não encontrada"}), 404

        # Obter a organização associada à sessão
        organization = session.organization
        if not organization:
            return jsonify({"error": "Organização não encontrada para esta sessão"}), 404

        # Buscar a role na organização
        role = Role.query.filter_by(name=role_name, organization_id=organization.id).first()
        if not role:
            return jsonify({"error": f"Role '{role_name}' não encontrada na organização"}), 404

        # Verificar se a role já está ativa
        if not role.is_suspended:
            return jsonify({"message": f"Role '{role_name}' já está ativa"}), 200

        # Reativar a role
        role.is_suspended = False
        db.session.commit()

        return jsonify({"message": f"Role '{role_name}' reativada com sucesso!"}), 200

    @staticmethod
    def assume_role(session_key, role_name):
        # Verificar a sessão
        session = check_session(session_key)
        if session is None:
            return jsonify({"error": "Sessão inválida ou não encontrada"}), 404

        # Obter o subject associado à sessão
        subject = session.subject
        if not subject:
            return jsonify({"error": "Subject não encontrado para esta sessão"}), 404

        # Buscar a role na organização
        role = Role.query.filter_by(name=role_name, organization_id=session.organization_id).first()
        if not role:
            return jsonify({"error": f"Role '{role_name}' não encontrada na organização"}), 404

        # Verificar se a role está acessível para o subject
        if role not in subject.accessible_roles:
            return jsonify({"error": f"Role '{role_name}' não está acessível para o subject '{subject.username}'"}), 403

        # Verificar se a role já está associada ao subject
        if role in subject.roles:
            return jsonify({"message": f"Role '{role_name}' já está associada ao subject '{subject.username}'"}), 200

        # Associar a role ao subject
        subject.roles.append(role)
        db.session.commit()

        return jsonify({"message": f"Role '{role_name}' associada ao subject '{subject.username}' com sucesso!"}), 200

    @staticmethod
    def drop_role(session_key, role_name):
        # Verificar a sessão
        session = check_session(session_key)
        if session is None:
            return jsonify({"error": "Sessão inválida ou não encontrada"}), 404

        # Obter o subject associado à sessão
        subject = session.subject
        if not subject:
            return jsonify({"error": "Subject não encontrado para esta sessão"}), 404

        # Buscar a role pelo nome e organização
        role = Role.query.filter_by(name=role_name, organization_id=session.organization_id).first()
        if not role:
            return jsonify({"error": f"Role '{role_name}' não encontrada na organização"}), 404

        # Verificar se a role está associada ao subject
        if role not in subject.roles:
            return jsonify({"error": f"Role '{role_name}' não está associada ao subject '{subject.username}'"}), 400

        # Remover a associação entre a role e o subject
        subject.roles.remove(role)
        db.session.commit()

        return jsonify(
            {"message": f"Role '{role_name}' desassociada do subject '{subject.username}' com sucesso!"}), 200

    @staticmethod
    def add_role(session_key, new_role):
        # Verificar a sessão e obter as informações
        session = check_session(session_key)
        if session is None:
            return jsonify({"error": "Sessão inválida ou não encontrada"}), 404

        # Obter a organização associada à sessão
        organization = session.organization
        if not organization:
            return jsonify({"error": "Organização não encontrada"}), 404

        # Verificar se a role já existe na organização
        role = Role.query.filter_by(name=new_role, organization_id=organization.id).first()
        if role:
            return jsonify({"error": "Role já existe na organização"}), 400

        # Criar a nova role
        role = Role(name=new_role, organization_id=organization.id)

        # Adicionar a role à organização (sem associar a nenhum subject ainda)
        db.session.add(role)
        db.session.commit()

        return jsonify({"message": f"Role '{new_role}' criada com sucesso!"}), 200

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