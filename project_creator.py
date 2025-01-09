import json
import os
from datetime import datetime

def create_project_file(project_name, evidence_file_path, agent_name):
    project_data = {
        "project_name": project_name,
        "evidence_file_path": evidence_file_path,
        "profile": None,  # Valor por defecto hasta que se determine
        "creation_date": datetime.now().isoformat(),
        "last_modified_date": datetime.now().isoformat(),
        "agent_name": agent_name,
        "command_history": [],
        "generated_files": []
    }

    project_file_path = os.path.join("data", project_name + ".json")
    with open(project_file_path, "w") as project_file:
        json.dump(project_data, project_file, indent=4)
    print(f"Archivo del proyecto creado en: {project_file_path}")
    return project_file_path
