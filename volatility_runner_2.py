import subprocess

def run_volatility_command_v2(evidence_file_path, profile, command):
    # Construir el comando según si se proporciona un perfil o no
    if profile:
        full_command = f"python2.7 -m volatility -f {evidence_file_path} --profile={profile} {command}"
    else:
        full_command = f"python2.7 -m volatility -f {evidence_file_path} {command}"
    
    result = subprocess.run(full_command, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout
    else:
        return f"Error ejecutando Volatility 2: {result.stderr}"
