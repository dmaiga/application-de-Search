from config import DB_URI,ELASTICSEARCH_URL, ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD,SECRET_KEY
from flask import Flask, request, jsonify,url_for,redirect
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from uuid import UUID
from flask_jwt_extended import JWTManager, create_access_token,jwt_required, get_jwt_identity
from models import db, User, Document
import datetime
import uuid
import os 
from werkzeug.utils import secure_filename 
from elasticsearch import Elasticsearch
from utils import extract_text_from_file




def create_app():
    app= Flask(__name__, template_folder='templates', static_folder='static', static_url_path='/')
    app.config["SQLALCHEMY_DATABASE_URI"] = DB_URI
    app.secret_key= SECRET_KEY

     # Initialisation de la base de données
    db.init_app(app)
    bcrypt= Bcrypt(app)

    # Connexion à Elasticsearch
    es = Elasticsearch(
    ELASTICSEARCH_URL,
    basic_auth=(ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD)
        )
    
    # Configuration de Flask-Login
    login_manager= LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth'
    
    from models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    @login_manager.unauthorized_handler
    def unauthorized_callback():
        return redirect( url_for('auth'))

    
    # Enregistrement des routes
    from routes import register_routes
    register_routes(app,db,bcrypt,es)
    
    # Upload and index_file route
    from routes import register_document_routes
    register_document_routes(app, db,es,UUID)

    # gestion des users
    from routes import profiles_user
    profiles_user(app,db,bcrypt)

    # Configuration de Flask-Migrate
    migrate = Migrate(app,db)    
    return app



