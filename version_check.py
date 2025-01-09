# version_check.py

import subprocess
import sys
import os
import stat

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

def install_package(env_path, package):
    subprocess.run(f"{env_path}/bin/pip install {package}", shell=True)

def check_and_install_volatility():
    vol1_path = os.path.abspath("VolatilityApp/vol1")
    vol2_path = os.path.abspath("VolatilityApp/vol2")

    # Crear entornos virtuales si no existen
    if not os.path.exists(vol1_path):
        os.makedirs(vol1_path)
        run_command(f"python2.7 -m venv {vol1_path}")
        
    if not os.path.exists(vol2_path):
        os.makedirs(vol2_path)
        run_command(f"python3 -m venv {vol2_path}")

    # Asegurar permisos de ejecución en Linux
    if sys.platform.startswith('linux'):
        for folder in [vol1_path, vol2_path]:
            for root, dirs, files in os.walk(folder):
                for file in files:
                    full_path = os.path.join(root, file)
                    st = os.stat(full_path)
                    os.chmod(full_path, st.st_mode | stat.S_IEXEC)

    volatility2_path = None
    volatility3_path = None

    # Comprobación e instalación de Volatility 2 en vol1
    try:
        result = subprocess.run([f"{vol1_path}/bin/python", "-m", "volatility", "-h"], capture_output=True, text=True)
        if "Volatility Framework" not in result.stdout:
            raise EnvironmentError("Volatility 2 no está instalado.")
        volatility2_path = run_command(f"{vol1_path}/bin/which volatility")
    except FileNotFoundError:
        print("Volatility 2 no está instalado. Instalando en vol1...")
        install_package(vol1_path, "volatility")
        volatility2_path = run_command(f"{vol1_path}/bin/which volatility")

    # Comprobación e instalación de Volatility 3 en vol2
    try:
        result = subprocess.run([f"{vol2_path}/bin/python", "-m", "volatility3", "-h"], capture_output=True, text=True)
        if "Volatility 3 Framework" not in result.stdout:
            raise EnvironmentError("Volatility 3 no está instalado.")
        volatility3_path = run_command(f"{vol2_path}/bin/which volatility3")
    except FileNotFoundError:
        print("Volatility 3 no está instalado. Instalando en vol2...")
        install_package(vol2_path, "volatility3")
        volatility3_path = run_command(f"{vol2_path}/bin/which volatility3")

    return volatility2_path, volatility3_path

def check_python_version():
    # Comprobación de Python 2.7
    try:
        result = subprocess.run(["python2.7", "--version"], capture_output=True, text=True)
        if "Python 2.7" not in result.stdout and "Python 2.7" not in result.stderr:
            raise EnvironmentError("Python 2.7 no está instalado.")
    except FileNotFoundError:
        raise EnvironmentError("Python 2.7 no está instalado.")

    # Comprobación de Python 3.x
    if not sys.version.startswith("3"):
        raise EnvironmentError("Python 3.x no está instalado o no está configurado correctamente.")

if __name__ == "__main__":
    try:
        check_python_version()
        v2_path, v3_path = check_and_install_volatility()
        print("Las versiones necesarias de Python y Volatility están instaladas y configuradas.")
        print(f"Volatility 2 Path: {v2_path}")
        print(f"Volatility 3 Path: {v3_path}")
    except EnvironmentError as e:
        print(f"Error: {e}")
