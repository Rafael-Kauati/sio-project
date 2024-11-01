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


# Import your models
from .models import Document, Organization, Session, Subject

# Create the tables in the database
with app.app_context():
    db.create_all()  # This will create all tables defined in your models

    # Verify if the organization table exists
    result = db.session.execute("SELECT * FROM information_schema.tables WHERE table_name = 'organization'")
    for row in result:
        print(row)

# Import your routes
from .routes import main_bp
app.register_blueprint(main_bp)
