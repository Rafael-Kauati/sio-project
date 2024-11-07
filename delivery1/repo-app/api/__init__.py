import logging

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os

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
