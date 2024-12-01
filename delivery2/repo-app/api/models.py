
from flask_sqlalchemy import SQLAlchemy
from api import app, db
from datetime import datetime, timezone

session_roles = db.Table('session_roles',
    db.Column('session_id', db.Integer, db.ForeignKey('session.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True)
)

subject_roles = db.Table('subject_roles',
    db.Column('subject_id', db.Integer, db.ForeignKey('subject.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True)
)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    #document_handle = db.Column(db.String(64), unique=True, nullable=True)
    name = db.Column(db.String(128), nullable=False)
    create_date = db.Column(db.DateTime, nullable=False)
    creator = db.Column(db.String(128), nullable=False)
    file_handle = db.Column(db.String(1000), unique=False, nullable=True)
    acl = db.Column(db.JSON, nullable=False)
    encrypted_file_key = db.Column(db.LargeBinary, nullable=True)  # Chave de criptografia do arquivo
    iv = db.Column(db.LargeBinary, nullable=False)  # Armazena o IV usado na criptografia
    tag = db.Column(db.LargeBinary, nullable=False)  # Armazena o TAG usado na criptografia
    ephemeral_public_key = db.Column(db.LargeBinary, nullable=False)  # Nova coluna para chave pública efêmera
    deleter = db.Column(db.String(128), nullable=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    encryption_vars = db.Column(db.JSON, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "organization_id": self.organization_id
        }


subject_organization = db.Table(
    'subject_organization',
    db.Column('subject_id', db.Integer, db.ForeignKey('subject.id'), primary_key=True),
    db.Column('organization_id', db.Integer, db.ForeignKey('organization.id'), primary_key=True)
)

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), unique=True, nullable=False)
    full_name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.String(1200), nullable=True)

    roles = db.relationship('Role', secondary=subject_roles, back_populates='subjects')
    organizations = db.relationship('Organization', secondary=subject_organization, back_populates='subjects')
    authentication_ids = db.relationship('AuthenticationID', back_populates='subject', cascade="all, delete-orphan")

class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    documents = db.relationship('Document', backref='organization')
    roles = db.relationship('Role', back_populates='organization', cascade="all, delete-orphan")

    # Relação com Subject via tabela associativa
    subjects = db.relationship('Subject', secondary=subject_organization, back_populates='organizations')


class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    permissions = db.relationship('RolePermission', back_populates='role', cascade='all, delete')
    subjects = db.relationship('Subject', secondary=subject_roles, back_populates='roles')
    organization = db.relationship("Organization", back_populates="roles")

    def __repr__(self):
        return f"<Role(name='{self.name}', organization_id='{self.organization_id}')>"




class RolePermission(db.Model):
    __tablename__ = 'role_permissions'

    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), primary_key=True)
    permission_id = db.Column(db.Integer, db.ForeignKey('permissions.id'), primary_key=True)
    role = db.relationship('Role', back_populates='permissions')
    permission = db.relationship('Permission', back_populates='roles')

    def __repr__(self):
        return f"<RolePermission(role_id={self.role_id}, permission_id={self.permission_id})>"



class Permission(db.Model):
    __tablename__ = 'permissions'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    description = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f"<Permission(id={self.id}, name={self.name})>"

Permission.roles = db.relationship('RolePermission', back_populates='permission', cascade='all, delete')

class Session(db.Model):
    __tablename__ = "session"
    id = db.Column(db.Integer, primary_key=True)
    #identifier = db.Column(db.String(128), unique=True, nullable=False)
    session_key = db.Column(db.String(1000), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    password = db.Column(db.String(128), nullable=False)  # Adicionando o campo password
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    credentials = db.Column(db.JSON, nullable=False)  # Credenciais associadas
    organization = db.relationship('Organization', backref='sessions')
    subject = db.relationship('Subject', backref='sessions')
    roles = db.relationship('Role', secondary=session_roles, backref='sessions')








class Nonce(db.Model):
    __tablename__ = "nonces"
    id = db.Column(db.Integer, primary_key=True)
    nonce = db.Column(db.String(128), unique=True, nullable=False)  # Nonce deve ser único
    used = db.Column(db.Boolean, default=False, nullable=False)  # Novo campo
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

class AuthenticationID(db.Model):
    __tablename__ = "authentication_id"
    id = db.Column(db.Integer, primary_key=True)
    nonce = db.Column(db.String(128), unique=True, nullable=False)  # Nonce must be unique
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Foreign key to reference Subject
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)

    # Relationship back to Subject
    subject = db.relationship('Subject', back_populates='authentication_ids')