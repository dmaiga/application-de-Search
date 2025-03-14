from flask import render_template, request, redirect,url_for,flash,send_file,jsonify
from flask_login import login_user,logout_user,current_user,login_required
from models import User,Role, Document
import os
 
from datetime import datetime
import uuid
from werkzeug.utils import secure_filename 
from utils import extract_text_from_file,generate_file_hash

def register_routes(app, db,bcrypt,es):

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
    

    @app.route('/documents')
    @login_required
    def documents():
        page = request.args.get('page', 1, type=int)
        per_page = 5  
        all_documents = Document.query.paginate(page=page, per_page=per_page)
        return render_template('documents.html', documents=all_documents)

    @app.route('/search', methods=['GET'])
    @login_required
    def search_documents():
        try:
            # Récupérer les paramètres de recherche
            query = request.args.get('query', '').strip()
            doc_type = request.args.get('doc_type', '').strip()
            page = request.args.get('page', 1, type=int)
            per_page = 10  
            doc_format = request.args.get('doc_format', '').strip() 

            # Construire la requête Elasticsearch
            search_body = {
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"doc_content": query}}
                        ]
                    }
                },
                "highlight": {
                    "fields": {
                        "doc_content": {
                            "number_of_fragments": 5,  # Retourne jusqu'à 5 fragments
                            "fragment_size": 150       # Taille maximale de chaque fragment
                        }
                    }
                },
                "from": (page - 1) * per_page,
                "size": per_page
            }

            # Ajouter un filtre sur le type de document si spécifié
            if doc_format:
                search_body["query"]["bool"].setdefault("filter", []).append({"term": {"doc_format.keyword": doc_format}})


            # Exécuter la recherche dans Elasticsearch
            response = es.search(index="documents", body=search_body)

            # Traiter les résultats
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

            # Calculer le nombre total de pages
            total_results = response['hits']['total']['value']  # Nombre total de résultats
            total_pages = (total_results + per_page - 1) // per_page  # Calcul du nombre total de pages

            # Afficher les résultats dans un template
            return render_template('search_results.html', results=results, query=query, doc_type=doc_type, page=page, total_pages=total_pages)

        except Exception as e:
            flash(f"Erreur lors de la recherche : {str(e)}", "danger")
            return redirect(url_for('documents'))




def register_document_routes(app,db,es):
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limite à 16MB
    # Connexion à Elasticsearch

    # Liste dynamique des types de documents (exemple, peut être stockée en base de données)
    DOCUMENT_TYPES = ["cv", "fiche de poste", "evaluation annuelle","rapport","factures","autre"]

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
                return redirect(url_for('upload_file'))

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
        try:
            # Récupérer les IDs des documents à supprimer
            doc_ids = request.form.getlist('doc_ids')
            if not doc_ids:
                flash("Aucun document sélectionné.", "warning")
                return redirect(url_for('documents'))

            # Supprimer chaque document
            for doc_id in doc_ids:
                document = Document.query.get(doc_id)
                if document:
                    # Supprimer le fichier du disque
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




