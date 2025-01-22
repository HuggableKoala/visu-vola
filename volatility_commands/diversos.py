# volatility_commands/diversos.py

from volatility_runner_2 import run_volatility_command_v2

def clipboard(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "clipboard")

def cmdscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "cmdscan")

def consoles(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "consoles")

def crashinfo(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "crashinfo")

def deskscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "deskscan")

def dumpregistry(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "dumpregistry")

def envars(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "envars")

def evtlogs(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "evtlogs")

def files(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "files")

def gahti(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "gahti")

def getsids(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "getsids")

def handles(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "handles")

def hibinfo(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "hibinfo")

def iehistory(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "iehistory")

def imagecopy(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "imagecopy")

def jobs(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "jobs")

def kernelcomments(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "kernelcomments")

def kdbgscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "kdbgscan")

def ldrmodules(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "ldrmodules")

def lsadump(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "lsadump")

def machoinfo(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "machoinfo")

def memdump_command(self):
    output_path = simpledialog.askstring("Input", "Ingrese la ruta de salida (deje vacío para usar el directorio por defecto):")
    if not output_path:
        output_path = self.get_generated_files_dir()
    self.run_command(lambda evidence_file_path, profile: memdump(evidence_file_path, profile, output_path))


def memmap(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "memmap")

def mftparser(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "mftparser")

def mutantscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "mutantscan")

def objtypescan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "objtypescan")

def psscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "psscan")

def psxview(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "psxview")

def shellbags(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "shellbags")

def shimcache(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "shimcache")

def sockets(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "sockets")

def sockscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "sockscan")

def ssdt(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "ssdt")

def symlinkscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "symlinkscan")

def thrdscan(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "thrdscan")

def timeliner(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "timeliner")

def unloadmodules(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "unloadmodules")

def vadinfo(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "vadinfo")

def vaddump_command(self):
    pid = simpledialog.askstring("Input", "Ingrese el PID del proceso:")
    output_path = simpledialog.askstring("Input", "Ingrese la ruta de salida (deje vacío para usar el directorio por defecto):")
    if not output_path:
        output_path = self.get_generated_files_dir()
    self.run_command(lambda evidence_file_path, profile: vaddump(evidence_file_path, profile, pid, output_path))

def vadtree(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "vadtree")

def vadwalk(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "vadwalk")

def verinfo(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "verinfo")

def vmwareinfo(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "vmwareinfo")

def yara(evidence_file_path, profile):
    return run_volatility_command_v2(evidence_file_path, profile, "yara")
