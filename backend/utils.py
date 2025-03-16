import os
from pdfminer.high_level import extract_text
from docx import Document
import logging
import hashlib
import re

"""
    extract_text_from_file
    generate_file_hash
    is_email_valid


"""


def extract_text_from_file(file_path):
    """
    Extrait le contenu texte d'un fichier PDF ou DOCX.
    :param file_path: Chemin du fichier à extraire
    :return: Contenu du fichier sous forme de texte ou un message d'erreur
    """
    if not os.path.exists(file_path):
        return "Erreur : Fichier introuvable."

    _, file_extension = os.path.splitext(file_path)
    file_extension = file_extension.lower().strip('.')

    try:
        if file_extension == "pdf":
            return extract_text(file_path).strip() or "Aucun texte extrait."

        elif file_extension == "docx":
            doc = Document(file_path)
            return "\n".join(para.text for para in doc.paragraphs).strip() or "Aucun texte extrait."

        else:
            return "Format non supporté. Seuls les fichiers PDF et DOCX sont acceptés."

    except Exception as e:
        logging.error(f"Erreur lors de l'extraction du texte : {e}")
        return "Erreur : Impossible d'extraire le texte."



def generate_file_hash(file_path):
    """
    Génère un hash SHA-256 du contenu d'un fichier.
    :param file_path: Chemin du fichier
    :return: Hash du fichier sous forme de chaîne hexadécimale
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()




def is_email_valid(email):
    """Vérifie si l'email est valide."""
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None