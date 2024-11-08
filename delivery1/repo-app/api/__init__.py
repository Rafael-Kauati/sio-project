import logging

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def gen_key():
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
from .models import Document, Organization, Session, Subject

## Gen pub key for anonymous API :
gen_key()

# Create the tables in the database
with app.app_context():
    #db.drop_all()
    db.create_all()

    # Verify if the organization table exists
    result = db.session.execute("SELECT * FROM information_schema.tables WHERE table_name = 'organization'")
    for row in result:
        print(row)

from .routes import main_bp
app.register_blueprint(main_bp)
