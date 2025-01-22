import os
import json

# Definir el área de trabajo por defecto
DEFAULT_WORKSPACE = "data"
WORKSPACE_FILE = "data/workspace.json"
RECENT_PROJECTS_FILE = "data/recent_projects.json"

def get_workspace_path():
    if not os.path.exists(WORKSPACE_FILE):
        return DEFAULT_WORKSPACE
    with open(WORKSPACE_FILE, "r") as f:
        return json.load(f).get("workspace", DEFAULT_WORKSPACE)

def create_new_project(project_name):
    workspace = get_workspace_path()
    project_path = os.path.join(workspace, project_name)

    if not os.path.exists(project_path):
        os.makedirs(project_path)
        print(f"Nuevo proyecto creado en: {project_path}")
        return project_path
    else:
        raise FileExistsError(f"El proyecto '{project_name}' ya existe en el área de trabajo.")

def load_recent_projects():
    if not os.path.exists(RECENT_PROJECTS_FILE):
        return []
    with open(RECENT_PROJECTS_FILE, "r") as f:
        return json.load(f)

def save_recent_projects(recent_projects):
    with open(RECENT_PROJECTS_FILE, "w") as f:
        json.dump(recent_projects, f)

def save_project_state(project_path, state):
    # Lógica para guardar el estado del proyecto
    state_file = os.path.join(project_path, "state.json")
    with open(state_file, "w") as f:
        json.dump(state, f)
