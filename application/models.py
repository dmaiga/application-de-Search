from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Enum
from datetime import datetime
from flask_bcrypt import Bcrypt
import uuid


db = SQLAlchemy()
bcrypt = Bcrypt() 

class Role(Enum):
    ADMIN = 'admin'
    USER = 'user'

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)  
    last_name = db.Column(db.String(100), nullable=False)  
    username = db.Column(db.String(100), unique=True, nullable=False)  
    email = db.Column(db.String(150), unique=True, nullable=False)  
    password = db.Column(db.Text, nullable=False)  
    job_title = db.Column(db.String(100), nullable=True)  
    department = db.Column(db.String(100), nullable=True)  
    phone = db.Column(db.String(20), nullable=True)  
    work_location = db.Column(db.String(200), nullable=True)  
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  
    role = db.Column(Enum('admin', 'user', name='role'), default='user')  # Rôle (par défaut 'user')

    def hash_password(self):
        """Hash le mot de passe avant de le stocker dans la base de données."""
        self.password = bcrypt.generate_password_hash(self.password).decode('utf-8')

    def check_password(self, password):
        """Vérifie si le mot de passe fourni correspond au mot de passe hashé."""
        return bcrypt.check_password_hash(self.password, password)

    def __repr__(self):
        return f"Username: {self.username}, Role: {self.role}"

    def get_id(self):
        """Retourne l'ID de l'utilisateur (requis par Flask-Login)."""
        return self.id


class Document(db.Model):
    doc_id = db.Column(db.String(36), primary_key=True)
    doc_name = db.Column(db.String(255), nullable=False)
    doc_type = db.Column(db.String(100), nullable=False)
    doc_content = db.Column(db.Text, nullable=False)
    doc_format = db.Column(db.String(10), nullable=False)
    doc_insert_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    doc_updated_date = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_hash = db.Column(db.String(64), unique=True, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id', name="fk_document_user"), nullable=False)

    # Relation avec l'utilisateur
    user = db.relationship('User', backref=db.backref('documents', lazy=True))