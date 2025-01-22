# volatility_commands/memoria_proceso.py

from volatility_runner_2 import run_volatility_command_v2

def memmap(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "memmap")

def memdump(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "memdump")

def procdump(evidence_file_path, profile, pid=None):
    command = f"procdump -p {pid}" if pid else "procdump"
    return run_volatility_command_v2(evidence_file_path, profile, command)

def vadinfo(evidence_file_path, profile, pid=None):
    command = f"vadinfo -p {pid}" if pid else "vadinfo"
    return run_volatility_command_v2(evidence_file_path, profile, command)

def vadwalk(evidence_file_path, profile, pid=None):
    command = f"vadwalk -p {pid}" if pid else "vadwalk"
    return run_volatility_command_v2(evidence_file_path, profile, command)

def vadtree(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "vadtree")

def vaddump(evidence_file_path, profile, pid=None):
    command = f"vaddump -p {pid}" if pid else "vaddump"
    return run_volatility_command_v2(evidence_file_path, profile, command)

def evtlogs(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "evtlogs")

def iehistory(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "iehistory")
