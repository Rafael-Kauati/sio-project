from flask_sqlalchemy import SQLAlchemy
from api import app, db

# Define the association table for Session and Role
session_roles = db.Table('session_roles',
    db.Column('session_id', db.Integer, db.ForeignKey('session.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True)
)

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
    roles = db.relationship('Role', back_populates='organization', cascade="all, delete-orphan")

class Session(db.Model):
    __tablename__ = "session"
    id = db.Column(db.Integer, primary_key=True)
    identifier = db.Column(db.String(128), unique=True, nullable=False)
    session_key = db.Column(db.String(428), nullable=False)
    password = db.Column(db.String(128), nullable=False)  # Adicionando o campo password
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    credentials = db.Column(db.JSON, nullable=False)  # Credenciais associadas
    organization = db.relationship('Organization', backref='sessions')
    subject = db.relationship('Subject', backref='sessions')
    roles = db.relationship('Role', secondary=session_roles, backref='sessions')  # Use the defined session_roles table

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), unique=True, nullable=False)
    full_name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.String(512), nullable=False)

class Role(db.Model):
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    permissions = db.Column(db.JSON, nullable=True)

    organization = db.relationship("Organization", back_populates="roles")

    def __repr__(self):
        return f"<Role(name='{self.name}', organization_id='{self.organization_id}')>"