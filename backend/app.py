from config import DB_URI,ELASTICSEARCH_URL, ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD,SECRET_KEY
from flask import Flask, request, jsonify,url_for,redirect
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_bcrypt import Bcrypt

from flask_jwt_extended import JWTManager, create_access_token,jwt_required, get_jwt_identity
from models import db, User, Document
import datetime
import uuid
import os 
from werkzeug.utils import secure_filename 
from elasticsearch import Elasticsearch
from utils import extract_text_from_file




def create_app():
    app= Flask(__name__, template_folder='templates')
    app.config["SQLALCHEMY_DATABASE_URI"] = DB_URI
    app.secret_key= SECRET_KEY

     # Initialisation de la base de données
    db.init_app(app)
    bcrypt= Bcrypt(app)

    # Configuration de Flask-Login
    login_manager= LoginManager()
    login_manager.init_app(app)
    
    from models import User
    @login_manager.user_loader
    def load_user(id):
        return User.query.get(id)
    
    @login_manager.unauthorized_handler
    def unauthorized_callback():
        return redirect( url_for('index'))

    
    # Enregistrement des routes
    from routes import register_routes
    register_routes(app,db,bcrypt)
    

    # Configuration de Flask-Migrate
    migrate = Migrate(app,db)    
    return app




"""
app = Flask(__name__)

# Configurer la base de données
app.config["SQLALCHEMY_DATABASE_URI"] = DB_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Configurer JWT
app.config["JWT_SECRET_KEY"] = "super-secret-key"  #####
jwt = JWTManager(app)

db.init_app(app)

# Route d'inscription
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if not data.get("username") or not data.get("password") or not data.get("email"):
        return jsonify({"error": "Champs obligatoires manquants"}), 400

    # Vérifier si l'utilisateur existe déjà
    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"error": "Utilisateur déjà existant"}), 400

    # Créer l'utilisateur
    new_user = User(
        username=data["username"],
        email=data["email"],
        password=data["password"],
        role=data.get("role", "user")  
    )
    new_user.hash_password()
    
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Utilisateur créé avec succès"}), 201

# Route de connexion
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data["username"]).first()

    if not user or not user.check_password(data["password"]):
        return jsonify({"error": "Identifiants invalides"}), 401

    # Générer un token JWT
    access_token = create_access_token(identity=user.username, expires_delta=datetime.timedelta(days=1))
    return jsonify({"access_token": access_token}), 200



@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Bienvenue {current_user}, cette route est protégée."}), 200

@app.route('/users', methods=['GET'])
@jwt_required()  # Seuls les utilisateurs authentifiés peuvent voir la liste
def get_users():
    users = User.query.all()
    users_list = [{"id": user.id, "username": user.username, "email": user.email, "role": user.role} for user in users]
    return jsonify({"users": users_list}), 200

## route pour l'uploads
UPLOAD_FOLDER = "uploads/"
ALLOWED_EXTENSIONS = {"pdf", "docx"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Connexion à Elasticsearch
es = Elasticsearch(
    ELASTICSEARCH_URL,
    basic_auth=(ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD)
)

# Vérifier si le dossier uploads/ existe, sinon le créer
if not os.path.exists(app.config["UPLOAD_FOLDER"]):
    os.makedirs(app.config["UPLOAD_FOLDER"])

# Vérifier si l’extension du fichier est autorisée
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# Route pour uploader un fichier et l'indexer
@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "Aucun fichier fourni"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Nom de fichier invalide"}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_extension = filename.rsplit(".", 1)[1].lower()
        doc_id = str(uuid.uuid4())
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], f"{doc_id}.{file_extension}")
        
        file.save(filepath)  # Sauvegarde du fichier

        # Extraction du texte
        extracted_text = extract_text_from_file(filepath, file_extension)

        # Enregistrer dans PostgreSQL
        new_doc = Document(
            doc_id=doc_id,
            doc_name=filename,
            doc_type="Autre",
            doc_format=file_extension,
            file_path=filepath
        )
        db.session.add(new_doc)
        db.session.commit()

        # Indexer dans Elasticsearch
        es.index(index="documents", id=doc_id, body={
            "doc_name": filename,
            "doc_type": "Autre",
            "doc_content": extracted_text,
            "file_path": filepath
        })

        return jsonify({"message": "Fichier uploadé et indexé", "doc_id": doc_id}), 201

    return jsonify({"error": "Format de fichier non autorisé"}), 400








if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
"""
