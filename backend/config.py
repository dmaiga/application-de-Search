import os

# Configuration SQLite
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_NAME = "elasticsearch.db"
DB_URI = f"sqlite:///{os.path.join(BASE_DIR, DB_NAME)}"

# Configuration Elasticsearch
ELASTICSEARCH_URL = "http://localhost:9200"
ELASTICSEARCH_USER = "elastic"
ELASTICSEARCH_PASSWORD = "-LW6SeWxa*7EfzBDpxNU"

# Clé secrète pour Flask
SECRET_KEY = "my_super_secret_key"