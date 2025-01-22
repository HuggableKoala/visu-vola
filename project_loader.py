import json
import os

def load_project_file(project_file_path):
    if not os.path.exists(project_file_path):
        raise FileNotFoundError(f"No se encontró el archivo del proyecto: {project_file_path}")

    with open(project_file_path, "r") as project_file:
        project_data = json.load(project_file)
    return project_data
