from flask import render_template, request, redirect,url_for,flash
from flask_login import login_user,logout_user,current_user,login_required
from models import User,Role, Document
import os
 
from datetime import datetime
import uuid
from werkzeug.utils import secure_filename 
from utils import extract_text_from_file,generate_file_hash

def register_routes(app, db,bcrypt):

    @app.route('/')
    def index():
        return render_template('index.html')
        
        
    @app.route('/signup',methods=['GET','POST'])
    def signup():
        if request.method == 'GET':
            return render_template('signup.html')
        elif request.method == 'POST':
            try :                
                username = request.form.get('username')
                password= request.form.get('password')
                email= request.form.get('email')
                hash_password = bcrypt.generate_password_hash(password).decode('utf-8')
                
                first_user = User.query.first()
                if first_user is None:  
                    role = Role.ADMIN
                else:
                    role = Role.USER
    
                user = User(username=username, password=hash_password, email=email, role=role)
                db.session.add(user)
                db.session.commit()
                user = User.query.all()
                return redirect( url_for('index') )
            
            except Exception as e:
                db.session.rollback()
                flash(f'Erreur lors de l\'inscription: {e}', 'error')
                return render_template('signup.html')

    @app.route('/login',methods=['GET','POST'])
    def login():
        if request.method == 'GET':
            return render_template('login.html')
        elif request.method == 'POST':
            username = request.form.get('username')
            password= request.form.get('password')
            
            user= User.query.filter(User.username == username).first()

            if user and bcrypt.check_password_hash(user.password, password):
               login_user(user)
               flash('Connexion réussie.', 'success')
               return redirect(url_for('index'))  
            else:
                flash('Nom d\'utilisateur ou mot de passe incorrect.', 'error')
                return render_template('login.html', error='Invalid credentials')


            

    @app.route('/logout')
    def logout():
        logout_user()
        return redirect( url_for('index') )
    
    @app.route('/secret')
    @login_required
    def secret():
        return 'My secret message'
    




def register_document_routes(app,db,es):
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limite à 16MB
    # Connexion à Elasticsearch

    # Liste dynamique des types de documents (exemple, peut être stockée en base de données)
    DOCUMENT_TYPES = ["CV", "Fiche de poste", "Évaluation annuelle","Autre"]

    @app.route('/upload', methods=['GET', 'POST'])
    @login_required
    def upload_file():
        if request.method == 'GET':
            return render_template('upload.html', document_types=DOCUMENT_TYPES)

        try:
            # Récupération des données du formulaire
            doc_id = request.form.get('doc_id') 
            doc_name = request.form.get('doc_name')
            doc_type = request.form.get('doc_type')
            doc_file = request.files.get('doc_file')

            if not doc_name or not doc_type or not doc_file:
                flash("Tous les champs sont requis.", "danger")
                return redirect(url_for('upload_file'))

            if doc_type not in DOCUMENT_TYPES:
                flash("Type de document invalide.", "danger")
                return redirect(url_for('upload_file'))

            # Vérification de l'extension du fichier
            allowed_extensions = {'.pdf', '.docx'}
            file_extension = os.path.splitext(doc_file.filename)[-1].lower()

            if file_extension not in allowed_extensions:
                flash("Seuls les fichiers PDF et DOCX sont acceptés.", "danger")
                return redirect(url_for('upload_file'))

            # Enregistrer le fichier sur le disque
            upload_folder = os.path.join(app.root_path, 'uploads')
            os.makedirs(upload_folder, exist_ok=True)

            # Générer un ID unique si c'est un nouveau document
            if not doc_id:
                doc_id = str(uuid.uuid4())

            filename = f"{doc_id}_{secure_filename(doc_file.filename)}"
            file_path = os.path.join(upload_folder, filename)
            doc_file.save(file_path)

            # Extraction du texte du fichier
            doc_content = extract_text_from_file(file_path)

            if not doc_content or doc_content.strip() == "":
                flash("Le fichier semble vide ou illisible.", "warning")

            # Générer un hash du fichier pour détecter les doublons
            file_hash = generate_file_hash(file_path)

            # Vérifier si un document avec le même hash existe déjà
            existing_doc = Document.query.filter_by(file_hash=file_hash).first()

            if existing_doc:
                # Supprimer l'ancien fichier du disque
                if os.path.exists(existing_doc.file_path):
                    os.remove(existing_doc.file_path)

                # Mettre à jour le document existant
                existing_doc.doc_name = doc_name
                existing_doc.doc_type = doc_type
                existing_doc.doc_content = doc_content
                existing_doc.doc_format = file_extension.lstrip('.')
                existing_doc.file_path = file_path
                existing_doc.doc_updated_date = datetime.utcnow()

                db.session.commit()

                # Mettre à jour Elasticsearch
                try:
                    es.update(
                        index="documents",
                        id=existing_doc.doc_id,
                        body={
                            "doc": {
                                "doc_name": doc_name,
                                "doc_type": doc_type,
                                "doc_content": doc_content,
                                "file_path": file_path
                            }
                        }
                    )
                except Exception as es_error:
                    db.session.rollback()
                    flash(f"Erreur lors de la mise à jour dans Elasticsearch : {str(es_error)}", "danger")
                    return redirect(url_for('upload_file'))

                flash("Le document a été mis à jour avec succès.", "success")
                return redirect(url_for('documents'))

            # Si aucun doublon n'est détecté, créer un nouveau document
            new_doc = Document(
                doc_id=doc_id,
                doc_name=doc_name,
                doc_type=doc_type,
                doc_content=doc_content,
                doc_format=file_extension.lstrip('.'),
                file_path=file_path,
                user_id=current_user.id,
                doc_insert_date=datetime.utcnow(),
                doc_updated_date=datetime.utcnow(),
                file_hash=file_hash
            )
            db.session.add(new_doc)
            db.session.commit()

            # Indexer dans Elasticsearch
            try:
                es.index(index="documents", id=doc_id, body={
                    "doc_name": doc_name,
                    "doc_type": doc_type,
                    "doc_content": doc_content,
                    "file_path": file_path
                })
            except Exception as es_error:
                db.session.rollback()
                flash(f"Erreur lors de l'indexation dans Elasticsearch : {str(es_error)}", "danger")
                return redirect(url_for('upload_file'))

            flash("Document uploadé avec succès.", "success")
            return redirect(url_for('documents'))

        except Exception as e:
            db.session.rollback()
            flash(f"Erreur lors de l'upload : {str(e)}", "danger")
            return redirect(url_for('upload_file'))