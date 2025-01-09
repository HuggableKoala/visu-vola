# volatility_commands/red.py

from volatility_runner_2 import run_volatility_command_v2

def connections(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "connections")

def connscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "connscan")

def sockets(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "sockets")

def sockscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "sockscan")

def netscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "netscan")
