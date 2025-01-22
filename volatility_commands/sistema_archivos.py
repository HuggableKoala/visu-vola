# volatility_commands/sistema_archivos.py

from volatility_runner_2 import run_volatility_command_v2

def filescan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "filescan")

def lstfiles(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "lstfiles")

def moddump(evidence_file_path, profile, output_dir=None):
    command = f"moddump -D {output_dir}" if output_dir else "moddump"
    return run_volatility_command_v2(evidence_file_path, profile, command)

def dumpfiles(evidence_file_path, profile, dir_path=None):
    command = f"dumpfiles -D {dir_path}" if dir_path else "dumpfiles"
    return run_volatility_command_v2(evidence_file_path, profile, command)

def iehistory(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "iehistory")

def mbrparser(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "mbrparser")

def mftparser(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "mftparser")
