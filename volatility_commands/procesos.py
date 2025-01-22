# volatility_commands/procesos.py

from volatility_runner_2 import run_volatility_command_v2

def pslist(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "pslist")

def pstree(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "pstree")

def psscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "psscan")

def psdispscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "psdispscan")

def dlllist(evidence_file_path, profile, pid=None):
    command = f"dlllist -p {pid}" if pid else "dlllist"
    return run_volatility_command_v2(evidence_file_path, profile, command)

def dlldump(evidence_file_path, profile, pid=None, dll_name=None):
    command = f"dlldump -p {pid} -n {dll_name}" if pid and dll_name else "dlldump"
    return run_volatility_command_v2(evidence_file_path, profile, command)

def handles(evidence_file_path, profile, pid=None):
    command = f"handles -p {pid}" if pid else "handles"
    return run_volatility_command_v2(evidence_file_path, profile, command)

def getsids(evidence_file_path, profile, pid=None):
    command = f"getsids -p {pid}" if pid else "getsids"
    return run_volatility_command_v2(evidence_file_path, profile, command)

def cmdscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "cmdscan")

def consoles(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "consoles")

def privs(evidence_file_path, profile, pid=None):
    command = f"privs -p {pid}" if pid else "privs"
    return run_volatility_command_v2(evidence_file_path, profile, command)

def envars(evidence_file_path, profile, pid=None):
    command = f"envars -p {pid}" if pid else "envars"
    return run_volatility_command_v2(evidence_file_path, profile, command)

def verinfo(evidence_file_path, profile, pid=None):
    command = f"verinfo -p {pid}" if pid else "verinfo"
    return run_volatility_command_v2(evidence_file_path, profile, command)

def enumfunc(evidence_file_path, profile, pid=None):
    command = f"enumfunc -p {pid}" if pid else "enumfunc"
    return run_volatility_command_v2(evidence_file_path, profile, command)
