# volatility_commands/registro.py

from volatility_runner_2 import run_volatility_command_v2

def hivescan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "hivescan")

def hivelist(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "hivelist")

def printkey(evidence_file_path, profile, registry_key=None):
    command = f"printkey -K {registry_key}" if registry_key else "printkey"
    return run_volatility_command_v2(evidence_file_path, profile, command)

def hivedump(evidence_file_path, profile, offset=None):
    command = f"hivedump -o {offset}" if offset else "hivedump"
    return run_volatility_command_v2(evidence_file_path, profile, command)

def hashdump(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "hashdump")

def lsadump(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "lsadump")

def userassist(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "userassist")

def shellbags(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "shellbags")

def shimcache(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "shimcache")

def getservicesids(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "getservicesids")

def dumpregistry(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "dumpregistry")
