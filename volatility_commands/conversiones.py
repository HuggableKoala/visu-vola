from volatility_runner_2 import run_volatility_command_v2

def crashinfo(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "crashinfo")

def hibinfo(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "hibinfo")

def imagecopy(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "imagecopy")

def raw2dmp(evidence_file_path, profile, output_path=None):
    if not output_path:
        output_path = "default_output_path"
    command = f"raw2dmp -o {output_path}"
    return run_volatility_command_v2(evidence_file_path, profile, command)

def vboxinfo(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "vboxinfo")

def vmwareinfo(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "vmwareinfo")

def hpakinfo(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "hpakinfo")

def hpakextract(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "hpakextract")
