from flask_sqlalchemy import SQLAlchemy
from api import app, db


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_handle = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(128), nullable=False)
    create_date = db.Column(db.DateTime, nullable=False)
    creator = db.Column(db.String(128), nullable=False)
    file_handle = db.Column(db.String(128), unique=True, nullable=False)
    acl = db.Column(db.JSON, nullable=False)
    deleter = db.Column(db.String(128), nullable=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)

class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    documents = db.relationship('Document', backref='organization')

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    identifier = db.Column(db.String(128), unique=True, nullable=False)
    keys = db.Column(db.JSON, nullable=False)
    password = db.Column(db.String(128), nullable=False)  # Adicionando o campo password
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    credentials = db.Column(db.JSON, nullable=False)  # Credenciais associadas
    organization = db.relationship('Organization', backref='sessions')
    subject = db.relationship('Subject', backref='sessions')


class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), unique=True, nullable=False)
    full_name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.String(512), nullable=False)
