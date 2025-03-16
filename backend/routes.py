from flask import render_template, request, redirect,url_for,flash,send_file,jsonify
from flask_login import login_user,logout_user,current_user,login_required
from models import User,Role, Document
import os
 
from datetime import datetime
import uuid
from werkzeug.utils import secure_filename 
from utils import extract_text_from_file,generate_file_hash,is_email_valid


"""
    Module de gestion des routes pour une application Flask

    Ce module définit les routes suivantes :
    - `/index` : Page d'accueil protégée par authentification
    - `/` : Page d'authentification
    - `/documents` : Page listant les documents avec pagination
    - `/search` : Recherche avancée de documents avec Elasticsearch

"""
def register_routes(app, db,bcrypt,es):
    """
        Enregistre les routes de l'application Flask.

        :param app: Instance de l'application Flask
        :param db: Instance de la base de données SQLAlchemy
        :param bcrypt: Instance de l'utilitaire de chiffrement Bcrypt
        :param es: Instance du client Elasticsearch
   
    """

    @app.route('/index')
    @login_required # Nécessite une authentification pour accéder à cette page
    def index():
        """Affiche la page d'accueil après connexion."""

        return render_template('index.html')
    
    @app.route('/', methods=['GET'])
    def auth():
        """Affiche la page d'authentification."""
        return render_template('auth.html')    
    
    @app.route('/documents')
    @login_required
    def documents():
        """
            Affiche une liste paginée des documents disponibles.

            :query_param page: Numéro de la page demandée (par défaut 1)
            :return: Template HTML avec la liste paginée des documents
       
         """
        page = request.args.get('page', 1, type=int)
        per_page = 5  # Nombre de documents par page
        all_documents = Document.query.paginate(page=page, per_page=per_page)
        return render_template('documents.html', documents=all_documents)

    @app.route('/search', methods=['GET'])
    @login_required
    def search_documents():
        """
            Effectue une recherche avancée de documents en utilisant Elasticsearch.

            :query_param query: Terme de recherche dans le contenu des documents
            :query_param doc_type: Filtre optionnel par type de document
            :query_param page: Numéro de page pour la pagination (par défaut 1)
            :query_param doc_format: Filtre optionnel par format de document
            :return: Template HTML affichant les résultats de la recherche
      
        """
        try:
            # Extraction des paramètres de requête
            query = request.args.get('query', '').strip()
            doc_type = request.args.get('doc_type', '').strip()
            page = request.args.get('page', 1, type=int)
            per_page = 10   # Nombre de résultats par page
            doc_format = request.args.get('doc_format', '').strip() 

            # Construction de la requête pour Elasticsearch

            search_body = {
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"doc_content": query}}  # Recherche sur le contenu des documents
                        ]
                    }
                },
                "highlight": {
                    "fields": {
                        "doc_content": {
                            "number_of_fragments": 5,  # Nombre maximum de fragments retournés
                            "fragment_size": 150       # Taille maximale de chaque fragment
                        }
                    }
                },
                "from": (page - 1) * per_page,
                "size": per_page
            }

            # Ajout d'un filtre sur le format du document si spécifié
            if doc_format:
                search_body["query"]["bool"].setdefault("filter", []).append({"term": {"doc_format.keyword": doc_format}})


            # Exécution de la recherche dans Elasticsearch
            response = es.search(index="documents", body=search_body)

            # Traitement des résultats
            results = []
            for hit in response['hits']['hits']:
                result = {
                    "doc_id": hit["_id"],
                    "doc_name": hit["_source"]["doc_name"],
                    "doc_type": hit["_source"]["doc_type"],
                    "highlight": hit.get("highlight", {}).get("doc_content", ["Aucun aperçu disponible"]),
                    "file_path": hit["_source"]["file_path"]
                }
                results.append(result)

            # Calcul du nombre total de pages
            total_results = response['hits']['total']['value']  # Nombre total de résultats
            total_pages = (total_results + per_page - 1) // per_page  # Calcul du nombre total de pages

            #  # Affichage des résultats dans un template
            return render_template('search_results.html', results=results, query=query, doc_type=doc_type, page=page, total_pages=total_pages)

        except Exception as e:
            flash(f"Erreur lors de la recherche : {str(e)}", "danger")
            return redirect(url_for('documents'))

"""
    Module de gestion des documents :

    Routes :
       - /upload : Téléchargement de fichiers
       - /download/<doc_id> : Téléchargement d'un document
       - /delete_documents : Suppression de plusieurs documents
       - /delete/<doc_id> : Suppression d'un document spécifique
       - /view_document/<doc_id> : Affichage d'un document
"""


def register_document_routes(app,db,es,UUID):
    """
        Enregistre les routes liées à la gestion des documents dans l'application Flask.

        :param app: Instance de l'application Flask.
        :param db: Instance de la base de données SQLAlchemy.
        :param es: Instance d'Elasticsearch pour l'indexation des documents.
        :param UUID: Fonction pour la validation des UUID.
   
     """
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limite à 16MB
    

    #  Liste des types de documents acceptés 
    DOCUMENT_TYPES = [
    "CV", 
    "fiche de poste", 
    "évaluation annuelle", 
    "proposition commerciale", 
    "contrat client", 
    "rapport de réunion", 
    "devis", 
    "plan de projet", 
    "documentation technique", 
    "compte rendu d'activité", 
    "factures", 
    "autre"
]


    @app.route('/upload', methods=['GET', 'POST'])
    @login_required
    def upload_file():
        """
            Gère l'upload de fichiers par les utilisateurs.
        """
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

            #Vérification de l'extension du fichier
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

             # Extraction du texte du document pour indexation
            doc_content = extract_text_from_file(file_path)

            if not doc_content or doc_content.strip() == "":
                flash("Le fichier semble vide ou illisible.", "warning")

            # Généreration d'un hash du fichier pour détecter les doublons
            file_hash = generate_file_hash(file_path)

            # Vérifier si un document avec le même hash existe déjà
            existing_doc = Document.query.filter_by(file_hash=file_hash).first()

            if existing_doc:
                # Supprission de l'ancien fichier du disque
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

                # Mise à jour Elasticsearch
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
                return redirect(url_for('upload_file'))

            # Si aucun doublon n'est détecté, création d'un nouveau document
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

            # Indexation dans Elasticsearch
            try:
                es.index(index="documents", id=doc_id, body={
                    "doc_name": doc_name,
                    "doc_type": doc_type,
                    "doc_format": file_extension.lstrip('.'),
                    "doc_content": doc_content,
                    "file_path": file_path
                })
            except Exception as es_error:
                db.session.rollback()
                flash(f"Erreur lors de l'indexation dans Elasticsearch : {str(es_error)}", "danger")
                return redirect(url_for('upload_file'))

            flash("Document uploadé avec succès.", "success")
            return redirect(url_for('upload_file'))

        except Exception as e:
            db.session.rollback()
            flash(f"Erreur lors de l'upload : {str(e)}", "danger")
            return redirect(url_for('upload_file'))
        

    @app.route('/download/<string:doc_id>')
    @login_required
    def download_document(doc_id):
        """
        Permet aux utilisateurs de télécharger un document spécifique.
        """
        document = Document.query.get(doc_id)
        if not document:
            flash("Document non trouvé.", "danger")
            return redirect(url_for('documents'))

        if not os.path.exists(document.file_path):
            flash("Fichier non trouvé.", "danger")
            return redirect(url_for('documents'))

        return send_file(document.file_path, as_attachment=True)
    

    @app.route('/delete_documents', methods=['POST'])
    @login_required
    def delete_documents():
        """
        Supprime plusieurs documents en une seule requête.
        """
        try:
            # Récupération des IDs des documents à supprimer
            doc_ids = request.form.getlist('doc_ids')
            if not doc_ids:
                flash("Aucun document sélectionné.", "warning")
                return redirect(url_for('documents'))

            # Suppression de chaque document
            for doc_id in doc_ids:
                document = Document.query.get(doc_id)
                if document:
                    # Suppression du fichier du disque
                    if os.path.exists(document.file_path):
                        os.remove(document.file_path)

                    # Supprimer l'entrée dans Elasticsearch
                    try:
                        es.delete(index="documents", id=doc_id)
                    except Exception as es_error:
                        flash(f"Erreur lors de la suppression dans Elasticsearch : {str(es_error)}", "danger")
                        continue

                    # Supprimer le document de la base de données
                    db.session.delete(document)

            db.session.commit()
            flash("Documents supprimés avec succès.", "success")
            return redirect(url_for('documents'))

        except Exception as e:
            db.session.rollback()
            flash(f"Erreur lors de la suppression des documents : {str(e)}", "danger")
            return redirect(url_for('documents'))

    @app.route('/delete/<string:doc_id>', methods=['POST'])
    @login_required
    def delete_document(doc_id):
        try:
            # Récupérer le document à supprimer
            document = Document.query.get(doc_id)
            if not document:
                flash("Document non trouvé.", "danger")
                return redirect(url_for('documents'))
    
            # Supprimer le fichier du disque
            if os.path.exists(document.file_path):
                os.remove(document.file_path)
    
            # Supprimer le document de la base de données
            db.session.delete(document)
            db.session.commit()
    
            # Supprimer l'entrée dans Elasticsearch
            try:
                es.delete(index="documents", id=doc_id)
            except Exception as es_error:
                db.session.rollback()
                flash(f"Erreur lors de la suppression dans Elasticsearch : {str(es_error)}", "danger")
                return redirect(url_for('documents'))
    
            flash("Document supprimé avec succès.", "success")
            return redirect(url_for('documents'))
    
        except Exception as e:
            db.session.rollback()
            flash(f"Erreur lors de la suppression du document : {str(e)}", "danger")
            return redirect(url_for('documents'))

    @app.route('/view_document/<string:doc_id>')
    def view_document(doc_id):
        """
            Affiche un document dans le navigateur au lieu de le télécharger.
        """
        try:
            # Convertir la chaîne en UUID pour validation
            doc_uuid = UUID(doc_id)
        except ValueError:
            return "Identifiant de document invalide", 400

        # Convertir l'UUID en chaîne pour la requête SQL
        doc_id_str = str(doc_uuid)

        # Récupérer le document depuis la base de données
        document = Document.query.filter_by(doc_id=doc_id_str).first()
        if not document:
            return "Document non trouvé", 404

        # Envoyer le fichier pour affichage dans le navigateur
        return send_file(document.file_path, as_attachment=False)


"""
    Module de gestion des profils utilisateurs.

    Ce module contient les routes pour l'inscription, la connexion, la déconnexion,
    la mise à jour du profil et le changement de mot de passe.

    Routes disponibles :
    - /signup : Inscription
    - /login : Connexion
    - /logout : Déconnexion
    - /profile : Affichage du profil
    - /update_profile : Mise à jour du profil
    - /change_password : Changement de mot de passe

"""

def profiles_user(app,db,bcrypt):
    """
        Initialise les routes liées aux profils utilisateurs.

        :param app: L'application Flask
        :param db: L'instance de la base de données SQLAlchemy
        :param bcrypt: L'instance de Bcrypt pour le hachage des mots de passe
   
    """

    @app.route('/profile', methods=['GET'])
    @login_required
    def profile():
        """Affiche la page du profil utilisateur."""
        return render_template('profile.html')

    @app.route('/update_profile', methods=['POST'])
    @login_required
    def update_profile():
        """
            Met à jour les informations du profil utilisateur.

            Vérifie que tous les champs requis sont remplis et que l'email
            et le nom d'utilisateur sont valides avant d'enregistrer les modifications.
        
        """
        if request.method == 'POST':
            # Récupérer les données du formulaire
            username = request.form.get('username')
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            email = request.form.get('email')
            job_title = request.form.get('job_title')
            department = request.form.get('department')
            phone = request.form.get('phone')
            work_location = request.form.get('work_location')

            # Validation des champs obligatoires
            if not all([username, first_name, last_name, email]):
                flash("Tous les champs sont obligatoires.", 'error')
                return redirect(url_for('profile'))

            # Vérification de la validite de l'email 
            if not is_email_valid(email):
                flash("L'adresse email n'est pas valide.", 'error')
                return redirect(url_for('profile'))

            # Vérifier que le nom d'utilisateur n'existe pas déjà (sauf pour l'utilisateur actuel)
            existing_user = User.query.filter(User.username == username, User.id != current_user.id).first()
            if existing_user:
                flash("Ce nom d'utilisateur est déjà utilisé.", 'error')
                return redirect(url_for('profile'))

            # Mettre à jour les informations de l'utilisateur
            
            current_user.username = username
            current_user.first_name = first_name
            current_user.last_name = last_name
            current_user.email = email
            current_user.job_title = job_title
            current_user.department = department
            current_user.phone = phone
            current_user.work_location = work_location

            # Enregistrer les modifications dans la base de données
            db.session.commit()

            flash("Profil mis à jour avec succès !", 'success')
            return redirect(url_for('profile'))

    @app.route('/change_password', methods=['GET', 'POST'])
    @login_required
    def change_password():
        """
            Permet à l'utilisateur de changer son mot de passe.
            
            Vérifie que l'ancien mot de passe est correct et que les nouveaux
            mots de passe correspondent avant de mettre à jour la base de données.
       
        """
        if request.method == 'POST':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            # Vérifier si le mot de passe actuel est correct
            if not bcrypt.check_password_hash(current_user.password, current_password):
                flash('Mot de passe actuel incorrect.', 'error')
           
            # Vérifier si les nouveaux mots de passe correspondent
            elif new_password != confirm_password:
                flash('Les nouveaux mots de passe ne correspondent pas.', 'error')
            else:
                # Mettre à jour le mot de passe
                current_user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                db.session.commit()
                flash('Mot de passe changé avec succès !', 'success')
                return redirect(url_for('profile'))

        return render_template('change_password.html')
    
    @app.route('/signup', methods=['POST'])
    def signup():
        """
            Inscrit un nouvel utilisateur.

            Vérifie que tous les champs requis sont remplis, que l'email est valide,
            et que le nom d'utilisateur n'est pas déjà utilisé avant de créer un nouveau compte.
        """
        if request.method == 'POST':

            # Récupérer les données du formulaire

            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            job_title = request.form.get('job_title')  
            department = request.form.get('department')  
            phone = request.form.get('phone') 
            work_location = request.form.get('work_location')  

            # Validation des champs obligatoires
            if not all([first_name, last_name, username, email, password, confirm_password]):
                flash("Tous les champs obligatoires doivent être remplis.", 'error')
                return redirect(url_for('auth'))

            # Vérifier que les mots de passe correspondent
            if password != confirm_password:
                flash("Les mots de passe ne correspondent pas.", 'error')
                return redirect(url_for('auth'))

            # Vérifier que l'email est valide
            if not is_email_valid(email):  # Utilisation de la fonction is_email_valid import from utils
                flash("L'adresse email n'est pas valide.", 'error')
                return redirect(url_for('auth'))

            # Vérifier que l'email ou le nom d'utilisateur n'existe pas déjà
            if User.query.filter((User.email == email) | (User.username == username)).first():
                flash("Un compte avec cet email ou ce nom d'utilisateur existe déjà.", 'error')
                return redirect(url_for('auth'))

            # Hachage du mot de passe
            hash_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Création d'un nouveau utilisateur
            user = User(
                first_name=first_name,
                last_name=last_name,
                username=username,
                email=email,
                password=hash_password,
                job_title=job_title,  
                department=department,  
                phone=phone, 
                work_location=work_location  
            )
            db.session.add(user)
            db.session.commit()

            # Connecter l'utilisateur après l'inscription
            login_user(user)

            # Redirection vers la page d'accueil avec un message de succès
            flash("Inscription réussie !", 'success')
            return redirect(url_for('index'))
   
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """
            Connecte un utilisateur existant.

            Vérifie que les informations de connexion sont correctes avant d'autoriser l'accès.
        
        """
        if request.method == 'GET':
            return render_template('auth.html')

        elif request.method == 'POST':
            try:
                # Récupérer les données du formulaire
                username_or_email = request.form.get('username_or_email')
                password = request.form.get('password')

                # Validation des champs obligatoires
                if not username_or_email or not password:
                    flash("Tous les champs sont obligatoires.", 'error')
                    return redirect(url_for('auth'))

                # Rechercher l'utilisateur dans la base de données par username ou email
                user = User.query.filter(   (User.username == username_or_email) | (User.email == username_or_email)   ).first()
                
                # Vérifier le mot de passe
                if user and bcrypt.check_password_hash(user.password, password):
                    login_user(user)  # Connecter l'utilisateur
                    flash('Connexion réussie.', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Nom d\'utilisateur/email ou mot de passe incorrect.', 'error')
                    return redirect(url_for('auth'))

            except Exception as e:
                flash(f'Erreur lors de la connexion: {str(e)}', 'error')
                return redirect(url_for('auth'))

    

    @app.route('/logout')

    def logout():
        """Déconnecte l'utilisateur."""
        logout_user()
        return redirect(url_for('auth')) 
    
    @app.route('/secret')
    @login_required
    def secret():
        """Page secrète accessible uniquement aux utilisateurs connectés."""
        return 'My secret message'
    

