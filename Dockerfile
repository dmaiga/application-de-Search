# Utilisation d'une image Python légère
FROM python:3.11-slim

# Définition du répertoire de travail dans le conteneur
WORKDIR /app

# Copie des fichiers de l'application dans le conteneur
COPY application/ ./application
COPY requirements.txt ./

# Installation des dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Exposition du port sur lequel Flask fonctionne
EXPOSE 5000

# Définition de la commande de démarrage
CMD ["python", "application/run.py"]
