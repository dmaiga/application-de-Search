import os
from pdfminer.high_level import extract_text
from docx import Document

''' 
     extract_text_from_file extrait le contenu du fichier 
     en fonction de l'extension du fichier pdf et docx
    
'''
def extract_text_from_file(file_path, file_extension):
    text = ""
    
    if file_extension == "pdf":
        text = extract_text(file_path)
    
    elif file_extension == "docx":
        doc = Document(file_path)
        text = "\n".join([para.text for para in doc.paragraphs])
    
    return text.strip() if text else "Aucun texte extrait."
