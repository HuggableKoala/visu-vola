import subprocess

def run_volatility_command_v3(evidence_file_path, command):
    full_command = f"python3 -m volatility3 -f {evidence_file_path} {command}"
    result = subprocess.run(full_command, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout
    else:
        return f"Error ejecutando Volatility 3: {result.stderr}"
