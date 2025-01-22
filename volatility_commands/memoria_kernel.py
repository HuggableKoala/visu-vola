# volatility_commands/memoria_kernel.py

from volatility_runner_2 import run_volatility_command_v2

def modules(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "modules")

def modscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "modscan")

def moddump(evidence_file_path, profile, module_name=None):
    command = f"moddump -n {module_name}" if module_name else "moddump"
    return run_volatility_command_v2(evidence_file_path, profile, command)

def ssdt(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "ssdt")

def driverscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "driverscan")

def filescan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "filescan")

def mutantscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "mutantscan")

def symlinkscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "symlinkscan")

def thrdscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "thrdscan")

def dumpfiles(evidence_file_path, profile, file_object=None):
    command = f"dumpfiles -Q {file_object}" if file_object else "dumpfiles"
    return run_volatility_command_v2(evidence_file_path, profile, command)

def unloadedmodules(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "unloadedmodules")
