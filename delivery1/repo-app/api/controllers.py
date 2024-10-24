from flask import Flask, request, jsonify
from models import db, Document, Organization, Session, Subject

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///repository.db'
db.init_app(app)

class SubjectController:
    @app.route('/subjects', methods=['POST'])
    def create_subject():
        data = request.json
        subject = Subject(**data)
        db.session.add(subject)
        db.session.commit()
        return jsonify({'message': 'Subject created successfully'}), 201

    @app.route('/subjects', methods=['GET'])
    def list_subjects():
        subjects = Subject.query.all()
        return jsonify([{'username': sub.username, 'full_name': sub.full_name} for sub in subjects]), 200
    
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
        document = Document.query.filter_by(file_handle=file_handle).first_or_404()
        return jsonify({
            'file_handle': document.file_handle,
            'alg': document.alg,
            'key': document.key
        })

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
        organization = Organization(**data)
        db.session.add(organization)
        db.session.commit()
        return jsonify({'message': 'Organization created successfully'}), 201

    @staticmethod
    def list_organizations():
        organizations = Organization.query.all()
        return jsonify([org.name for org in organizations]), 200

class SessionController:
    @staticmethod
    def create_session():
        data = request.json
        session = Session(**data)
        db.session.add(session)
        db.session.commit()
        return jsonify({'message': 'Session created successfully'}), 201