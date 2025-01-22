import os
import json
from volatility_runner_2 import run_volatility_command_v2
from volatility_runner_3 import run_volatility_command_v3

def detect_profiles(evidence_file_path):
    profiles_v2 = []
    profiles_v3 = []

    # Ejecutar comandos de Volatility 2 y Volatility 3 para obtener los perfiles sugeridos
    try:
        output_v2 = run_volatility_command_v2(evidence_file_path, "", "imageinfo")
        for line in output_v2.splitlines():
            if "Suggested Profile(s)" in line:
                profiles_v2 = line.split(":")[1].strip().split(", ")
                break
    except FileNotFoundError as e:
        profiles_v2.append(f"Error: {str(e)}")

    try:
        output_v3 = run_volatility_command_v3(evidence_file_path, "windows.info")
        for line in output_v3.splitlines():
            if "Suggested Profile(s)" in line:
                profiles_v3 = line.split(":")[1].strip().split(", ")
                break
    except FileNotFoundError as e:
        profiles_v3.append(f"Error: {str(e)}")

    return profiles_v2, profiles_v3

def update_project_profile(project_file_path, profile):
    if not os.path.exists(project_file_path):
        raise FileNotFoundError(f"No se encontró el archivo del proyecto: {project_file_path}")

    with open(project_file_path, "r") as project_file:
        project_data = json.load(project_file)

    project_data["profile"] = profile

    with open(project_file_path, "w") as project_file:
        json.dump(project_data, project_file, indent=4)

    return project_data


def get_pstree(evidence_file_path, profile): 
    output = run_volatility_command_v2(evidence_file_path, profile, "pstree") 
    return output 