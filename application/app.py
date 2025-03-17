from config import DB_URI,ELASTICSEARCH_URL, ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD,SECRET_KEY
from flask import Flask, request, jsonify,url_for,redirect
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from uuid import UUID

from models import db, User, Document
import datetime
import uuid
import os 
from werkzeug.utils import secure_filename 
from elasticsearch import Elasticsearch
from utils import extract_text_from_file




def create_app():
    """
    Fonction principale pour créer et configurer l'application Flask.
    """

    app= Flask(__name__, template_folder='templates', static_folder='static', static_url_path='/')
    app.config["SQLALCHEMY_DATABASE_URI"] = DB_URI  # Configuration de l'URI de la base de données
    app.secret_key = SECRET_KEY  # Clé secrète pour la session Flask

    # Initialisation de la base de données
    db.init_app(app)
    bcrypt= Bcrypt(app) # Initialisation de Bcrypt pour le hachage des mots de pass

    # Connexion à Elasticsearch
    es = Elasticsearch(
    ELASTICSEARCH_URL,
    basic_auth=(ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD)
        )
    
    # Configuration de Flask-Login pour la gestion des utilisateurs
    login_manager= LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth' # Vue de connexion par défaut
    
    from models import User
    @login_manager.user_loader
    def load_user(user_id):
        """
        Charge l'utilisateur à partir de l'ID stocké dans la session.
        """
        return User.query.get(int(user_id))
    
    @login_manager.unauthorized_handler
    def unauthorized_callback():
        """
            Redirige les utilisateurs non authentifiés vers la page de connexion.
        """
        return redirect( url_for('auth'))

    
    # Enregistrement des routes  principales
    from routes import register_routes
    register_routes(app,db,bcrypt,es)
    
    # Enregistrement des routes pour la gestion des documents
    from routes import register_document_routes
    register_document_routes(app, db,es,UUID)

    # Enregistrement des routes pour la gestion des profils utilisateurs
    from routes import profiles_user
    profiles_user(app,db,bcrypt)

    # Configuration de Flask-Migrate pour la gestion des migrations de la base de données

    migrate = Migrate(app,db)    
    return app



