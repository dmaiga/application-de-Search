# Projet de Recherche en Texte Intégral avec Flask et Elasticsearch





Ce projet permet de rechercher des documents en texte intégral à l'aide d'Elasticsearch. Il inclut des fonctionnalités telles que l'upload de documents, l'indexation, la recherche floue, et la gestion des utilisateurs.

## Fonctionnalités

- **Recherche en texte intégral** : Recherchez des documents en fonction de leur contenu.
- **Recherche floue** : Trouvez des résultats même en cas de fautes de frappe ou d'erreurs mineures.
- **Filtrage par format** : Filtrez les résultats par format de document (PDF, DOCX, etc.).
- **Gestion des utilisateurs** : Connexion et inscription avec des rôles (admin/user).
- **Upload de documents** : Téléversez des documents pour les indexer dans Elasticsearch.
- **Pagination** : Parcourez les résultats de recherche page par page.

## Technologies utilisées

- **Backend :**

  - Flask : Framework web Python.
  - Elasticsearch : Moteur de recherche.
  - SQLite : Base de données légère.
  - SQLAlchemy : ORM pour la gestion de la base de données.
  - Flask-Migrate : Gestion des migrations.
  - Bcrypt : Sécurisation des mots de passe.
  - Requests : Requêtes HTTP.
  - Werkzeug : Gestion des fichiers et des mots de passe.

- **Frontend :**

  - HTML
  - CSS (Bootstrap)
  - JavaScript (Vanilla JS)

- **Autres :**

  - PyPDF2 : Extraction de texte des fichiers PDF.
  - python-docx : Extraction de texte des fichiers Word.

## Prérequis

alembic
altair
bcrypt
elasticsearch
Flask
Flask-Bcrypt

Flask-Login
Flask-Migrate
Flask-SQLAlchemy
GitPython

lxml
numpy
pandas
pdfminer.six
pillow
psycopg2-binary
pyarrow
python-docx
requests
SQLAlchemy




### Installation des dépendances

```bash
pip install -r requirements.txt
```

## Structure du projet

```
mon-projet/
├── application/              # Code source de l'application
│   ├── run.py               # Exécution de l'application
│   ├── app.py               # Initialisation de l'application
│   ├── routes.py            # Gestion des routes Flask
│   ├── models.py            # Modèles de base de données
│   ├── utils.py             # Fonctions utilitaires (extraction de texte, etc.)
│   ├── templates/           # Templates HTML
│   │   ├── base.html        # Template de base
│   │   ├── index.html       # Page d'accueil
│   │   ├── auth.html        # Page de connexion/inscription
│   │   ├── upload.html      # Page d'upload de documents
│   │   ├── documents.html   # Gestion des documents
│   │   ├── search_results.html # Résultats de recherche
│   │   ├── profiles.html    # Gestion des utilisateurs
│   ├── config.py            # Configuration de l'application
├── requirements.txt         # Dépendances Python
├── README.md                # Documentation du projet
├── CONTRIBUTING.md          # Guide de contribution
├── LICENSE                  # Licence du projet (MIT)
└── .gitignore               # Fichiers ignorés par Git
```

## Contribution

Les contributions sont les bienvenues ! Consultez le fichier [CONTRIBUTING.md](CONTRIBUTING.md) pour plus de détails.

## Auteur

**Mahamane Daouda Maiga**

- 📧 Email : [md](mailto\:mdmaiga01@gmail.com)[maiga01@](https://www.linkedin.com/in/mdmaiga)[gma](mailto\:mdmaiga01@gmail.com)[il.com](https://www.linkedin.com/in/mdmaiga)



- [LinkedIn](https://www.linkedin.com/in/mdmaiga)

## [L](https://www.linkedin.com/in/mdmaiga)icence

Ce projet est sous licence [MIT](LICENSE).


