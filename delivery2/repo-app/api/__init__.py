import logging

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from cryptography.hazmat.primitives.asymmetric import rsa
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from sqlalchemy import text


def generate_and_save_master_key(key_path="master_key.pem"):
    # Gera uma nova chave privada EC (usando a curva SECP256R1)
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Salva a chave privada em um arquivo .pem
    with open(key_path, "wb") as private_key_file:
        private_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Gera a chave pública associada
    public_key = private_key.public_key()

    # Salva a chave pública em um arquivo .pem
    with open(f"{key_path}.pub", "wb") as public_key_file:
        public_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    return private_key, public_key


def gen_anon_key():
    # Gera um par de chaves RSA
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Salva a chave privada em um arquivo
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Salva a chave pública em um arquivo
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:password@localhost:5432/repository'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Configura o Flask-Migrate com o aplicativo e o banco de dados

app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')

# Crie o diretório se ele não existir
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),  # Print to terminal
        logging.FileHandler("repository.log")  # Write to log file
    ]
)

logger = logging.getLogger(__name__)

# Test log entry
logger.info("Logging configuration test.")

# Import your models
from .models import Document, Organization, Session, Subject, Permission

## Gen pub key for anonymous API :
#gen_anon_key()
#generate_and_save_master_key()
# Create the tables in the database

with app.app_context():
    # Recria as tabelas (se necessário, habilite o drop_all para reinicializar completamente)
    # db.drop_all()
    db.create_all()

    # Verifica se a tabela 'organization' foi criada
    result = db.session.execute("SELECT * FROM information_schema.tables WHERE table_name = 'organization'")
    for row in result:
        print(row)

    # Cria permissões iniciais, caso ainda não existam
    permissions = [
        {"name": "DOC_READ", "description": "Permission to read document contents."},
        {"name": "DOC_WRITE", "description": "Permission to write document contents."},
        {"name": "DOC_DELETE", "description": "Permission to delete document contents."},
        {"name": "ROLE_ACL", "description": "Permission to modify the role's ACL."},
        {"name": "DOC_ACL", "description": "Permission to modify the document's ACL."},
        {"name": "SUBJECT_NEW", "description": "Permission to add a new subject."},
        {"name": "SUBJECT_DOWN", "description": "Permission to suspend a subject."},
        {"name": "SUBJECT_UP", "description": "Permission to reactivate a subject."},
        {"name": "DOC_NEW", "description": "Permission to add a new document."},
        {"name": "ROLE_NEW", "description": "Permission to create a new role."},
        {"name": "ROLE_DOWN", "description": "Permission to suspend a role."},
        {"name": "ROLE_UP", "description": "Permission to reactivate a role."},
        {"name": "ROLE_MOD", "description": "Permission to modify a role."}
    ]

    # Adiciona permissões apenas se elas não existirem
    for permission in permissions:
        existing_permission = db.session.query(db.exists().where(Permission.name == permission["name"])).scalar()
        if not existing_permission:
            new_permission = Permission(name=permission["name"], description=permission["description"])
            db.session.add(new_permission)

    # Salva as permissões no banco de dados
    db.session.commit()
    print("Permissões criadas ou já existentes no banco de dados.")

from .routes import main_bp
app.register_blueprint(main_bp)