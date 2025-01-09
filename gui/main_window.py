import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from project_manager import load_recent_projects, save_recent_projects, save_project_state, create_project_file, load_project_file
from work_manager import detect_profiles, update_project_profile
from volatility_commands.procesos import *
from volatility_commands.memoria_proceso import *
from volatility_commands.memoria_kernel import *
from volatility_commands.red import *
from volatility_commands.registro import *
from volatility_commands.conversiones import *
from volatility_commands.sistema_archivos import *
from volatility_commands.diversos import *

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Volatility GUI")
        self.recent_projects = load_recent_projects()
        self.current_project_file = os.path.join("data", "default_template.json")  # Ruta relativa
        self.create_widgets()
    def show_registry_cheatsheet(self):
        cheatsheet_path = os.path.join("data", "registry_cheatsheet.txt")
        
        with open(cheatsheet_path, "r") as file:
            cheatsheet_text = file.read()

        cheatsheet_window = tk.Toplevel()
        cheatsheet_window.title("Registro Cheatsheet")

        text_widget = tk.Text(cheatsheet_window, wrap="word")
        text_widget.insert(tk.END, cheatsheet_text)
        text_widget.pack(expand=True, fill='both')

        close_button = tk.Button(cheatsheet_window, text="Cerrar", command=cheatsheet_window.destroy)
        close_button.pack(pady=5)
    def create_widgets(self):
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)

        file_menu = tk.Menu(self.menu_bar, tearoff=0)
        volatility2_menu = tk.Menu(self.menu_bar, tearoff=0)
        process_menu = tk.Menu(volatility2_menu, tearoff=0)
        memory_process_menu = tk.Menu(volatility2_menu, tearoff=0)
        memory_kernel_menu = tk.Menu(volatility2_menu, tearoff=0)
        network_menu = tk.Menu(volatility2_menu, tearoff=0)
        registry_menu = tk.Menu(volatility2_menu, tearoff=0)
        conversions_menu = tk.Menu(volatility2_menu, tearoff=0)
        file_system_menu = tk.Menu(volatility2_menu, tearoff=0)
        miscellaneous_menu = tk.Menu(volatility2_menu, tearoff=0)

        self.menu_bar.add_cascade(label="Archivo", menu=file_menu)
        self.menu_bar.add_cascade(label="Volatility 2", menu=volatility2_menu)

        file_menu.add_command(label="Nuevo Proyecto", command=self.new_project)
        file_menu.add_command(label="Proyectos Recientes", command=self.show_recent_projects)
        file_menu.add_command(label="Guardar Estado del Proyecto", command=self.save_project_state)
        file_menu.add_command(label="Cargar Proyecto", command=self.load_project)
        file_menu.add_separator()
        file_menu.add_command(label="Salir", command=self.root.quit)

        volatility2_menu.add_command(label="Detectar Perfil", command=self.detect_profile)
        volatility2_menu.add_cascade(label="Procesos y DLLs", menu=process_menu)
        volatility2_menu.add_cascade(label="Memoria de Proceso", menu=memory_process_menu)
        volatility2_menu.add_cascade(label="Memoria del Kernel y Objetos", menu=memory_kernel_menu)
        volatility2_menu.add_cascade(label="Red", menu=network_menu)
        volatility2_menu.add_cascade(label="Registro", menu=registry_menu)
        volatility2_menu.add_cascade(label="Conversiones y Crash Dumps", menu=conversions_menu)
        volatility2_menu.add_cascade(label="Sistema de Archivos", menu=file_system_menu)
        volatility2_menu.add_cascade(label="Diversos", menu=miscellaneous_menu)

        self.output_frame = tk.Frame(self.root)
        self.output_frame.pack(side="left", expand=True, fill="both")
        
        self.result_text_left = tk.Text(self.output_frame, wrap="word")
        self.result_text_left.pack(side="left", expand=True, fill="both")

        self.filter_frame = tk.Frame(self.root)
        self.filter_frame.pack(side="right", expand=True, fill="both")

        self.filter_entry = tk.Entry(self.filter_frame)
        self.filter_entry.pack(pady=5)

        self.result_text_right = tk.Text(self.filter_frame, wrap="word")
        self.result_text_right.pack(expand=True, fill="both")

        self.filter_entry.bind("<Return>", self.apply_filter)

    # Añadir comandos a los menús...


        # Comandos de Procesos y DLLs
        process_menu.add_command(label="Pslist", command=self.pslist_command)
        process_menu.add_command(label="Pstree", command=self.pstree_command)
        process_menu.add_command(label="Psscan", command=self.psscan_command)
        process_menu.add_command(label="Psdispscan", command=self.psdispscan_command)
        process_menu.add_command(label="Dlllist", command=self.dlllist_command)
        process_menu.add_command(label="Dlldump", command=self.dlldump_command)
        process_menu.add_command(label="Handles", command=self.handles_command)
        process_menu.add_command(label="Getsids", command=self.getsids_command)
        process_menu.add_command(label="Cmdscan", command=self.cmdscan_command)
        process_menu.add_command(label="Consoles", command=self.consoles_command)
        process_menu.add_command(label="Privs", command=self.privs_command)
        process_menu.add_command(label="Envars", command=self.envars_command)
        process_menu.add_command(label="Verinfo", command=self.verinfo_command)
        process_menu.add_command(label="Enumfunc", command=self.enumfunc_command)

        # Comandos de Memoria de Proceso
        memory_process_menu.add_command(label="Memmap", command=self.memmap_command)
        memory_process_menu.add_command(label="Memdump", command=self.memdump_command)
        memory_process_menu.add_command(label="Procdump", command=self.procdump_command)
        memory_process_menu.add_command(label="Vadinfo", command=self.vadinfo_command)
        memory_process_menu.add_command(label="Vadwalk", command=self.vadwalk_command)
        memory_process_menu.add_command(label="Vadtree", command=self.vadtree_command)
        memory_process_menu.add_command(label="Vaddump", command=self.vaddump_command)
        memory_process_menu.add_command(label="Evtlogs", command=self.evtlogs_command)
        memory_process_menu.add_command(label="Iehistory", command=self.iehistory_command)

        # Comandos de Memoria del Kernel y Objetos
        memory_kernel_menu.add_command(label="Modules", command=self.modules_command)
        memory_kernel_menu.add_command(label="Modscan", command=self.modscan_command)
        memory_kernel_menu.add_command(label="Moddump", command=self.moddump_command)
        memory_kernel_menu.add_command(label="Ssdt", command=self.ssdt_command)
        memory_kernel_menu.add_command(label="Driverscan", command=self.driverscan_command)
        memory_kernel_menu.add_command(label="Filescan", command=self.filescan_command)
        memory_kernel_menu.add_command(label="Mutantscan", command=self.mutantscan_command)
        memory_kernel_menu.add_command(label="Symlinkscan", command=self.symlinkscan_command)
        memory_kernel_menu.add_command(label="Thrdscan", command=self.thrdscan_command)
        memory_kernel_menu.add_command(label="Dumpfiles", command=self.dumpfiles_command)
        memory_kernel_menu.add_command(label="Unloadedmodules", command=self.unloadedmodules_command)

        # Comandos de Red
        network_menu.add_command(label="Connections", command=self.connections_command)
        network_menu.add_command(label="Connscan", command=self.connscan_command)
        network_menu.add_command(label="Sockets", command=self.sockets_command)
        network_menu.add_command(label="Sockscan", command=self.sockscan_command)
        network_menu.add_command(label="Netscan", command=self.netscan_command)

        # Comandos de Registro
        registry_menu.add_command(label="Hivescan", command=self.hivescan_command)
        registry_menu.add_command(label="Hivelist", command=self.hivelist_command)
        registry_menu.add_command(label="Printkey", command=self.printkey_command)
        registry_menu.add_command(label="Hivedump", command=self.hivedump_command)
        registry_menu.add_command(label="Hashdump", command=self.hashdump_command)
        registry_menu.add_command(label="Lsadump", command=self.lsadump_command)
        registry_menu.add_command(label="Userassist", command=self.userassist_command)
        registry_menu.add_command(label="Shellbags", command=self.shellbags_command)
        registry_menu.add_command(label="Shimcache", command=self.shimcache_command)
        registry_menu.add_command(label="Getservicesids", command=self.getservicesids_command)
        registry_menu.add_command(label="Dumpregistry", command=self.dumpregistry_command)

        # Comandos de Conversiones y Crash Dumps
        conversions_menu.add_command(label="Crashinfo", command=self.crashinfo_command)
        conversions_menu.add_command(label="Hibinfo", command=self.hibinfo_command)
        conversions_menu.add_command(label="Imagecopy", command=self.imagecopy_command)
        conversions_menu.add_command(label="Raw2dmp", command=self.raw2dmp_command)
        conversions_menu.add_command(label="Vboxinfo", command=self.vboxinfo_command)
        conversions_menu.add_command(label="Vmwareinfo", command=self.vmwareinfo_command)
        conversions_menu.add_command(label="Hpakinfo", command=self.hpakinfo_command)
        conversions_menu.add_command(label="Hpakextract", command=self.hpakextract_command)

        # Comandos de Sistema de Archivos
        file_system_menu.add_command(label="Filescan", command=self.filescan_command)
        file_system_menu.add_command(label="Lstfiles", command=self.lstfiles_command)
        file_system_menu.add_command(label="Moddump", command=self.moddump_command)
        file_system_menu.add_command(label="Dumpfiles", command=self.dumpfiles_command)
        file_system_menu.add_command(label="Iehistory", command=self.iehistory_command)
        file_system_menu.add_command(label="Mbrparser", command=self.mbrparser_command)
        file_system_menu.add_command(label="Mftparser", command=self.mftparser_command)
        # Comandos de Diversos
        miscellaneous_menu.add_command(label="Clipboard", command=self.clipboard_command)
        miscellaneous_menu.add_command(label="Cmdscan", command=self.cmdscan_command)
        miscellaneous_menu.add_command(label="Consoles", command=self.consoles_command)
        miscellaneous_menu.add_command(label="Crashinfo", command=self.crashinfo_command)
        miscellaneous_menu.add_command(label="Deskscan", command=self.deskscan_command)
        miscellaneous_menu.add_command(label="Dumpregistry", command=self.dumpregistry_command)
        miscellaneous_menu.add_command(label="Envars", command=self.envars_command)
        miscellaneous_menu.add_command(label="Evtlogs", command=self.evtlogs_command)
        miscellaneous_menu.add_command(label="Files", command=self.files_command)
        miscellaneous_menu.add_command(label="Gahti", command=self.gahti_command)
        miscellaneous_menu.add_command(label="Getsids", command=self.getsids_command)
        miscellaneous_menu.add_command(label="Handles", command=self.handles_command)
        miscellaneous_menu.add_command(label="Hibinfo", command=self.hibinfo_command)
        miscellaneous_menu.add_command(label="Iehistory", command=self.iehistory_command)
        miscellaneous_menu.add_command(label="Imagecopy", command=self.imagecopy_command)
        miscellaneous_menu.add_command(label="Jobs", command=self.jobs_command)
        miscellaneous_menu.add_command(label="Kernelcomments", command=self.kernelcomments_command)
        miscellaneous_menu.add_command(label="Kdbgscan", command=self.kdbgscan_command)
        miscellaneous_menu.add_command(label="Ldrmodules", command=self.ldrmodules_command)
        miscellaneous_menu.add_command(label="Lsadump", command=self.lsadump_command)
        miscellaneous_menu.add_command(label="Machoinfo", command=self.machoinfo_command)
        miscellaneous_menu.add_command(label="Memdump", command=self.memdump_command)
        miscellaneous_menu.add_command(label="Memmap", command=self.memmap_command)
        miscellaneous_menu.add_command(label="Mftparser", command=self.mftparser_command)
        miscellaneous_menu.add_command(label="Mutantscan", command=self.mutantscan_command)
        miscellaneous_menu.add_command(label="Objtypescan", command=self.objtypescan_command)
        miscellaneous_menu.add_command(label="Psscan", command=self.psscan_command)
        miscellaneous_menu.add_command(label="Psxview", command=self.psxview_command)
        miscellaneous_menu.add_command(label="Shellbags", command=self.shellbags_command)
        miscellaneous_menu.add_command(label="Shimcache", command=self.shimcache_command)
        miscellaneous_menu.add_command(label="Sockets", command=self.sockets_command)
        miscellaneous_menu.add_command(label="Sockscan", command=self.sockscan_command)
        miscellaneous_menu.add_command(label="Ssdt", command=self.ssdt_command)
        miscellaneous_menu.add_command(label="Symlinkscan", command=self.symlinkscan_command)
        miscellaneous_menu.add_command(label="Thrdscan", command=self.thrdscan_command)
        miscellaneous_menu.add_command(label="Timeliner", command=self.timeliner_command)
        miscellaneous_menu.add_command(label="Unloadmodules", command=self.unloadmodules_command)
        miscellaneous_menu.add_command(label="Vadinfo", command=self.vadinfo_command)
        miscellaneous_menu.add_command(label="Vaddump", command=self.vaddump_command)
        miscellaneous_menu.add_command(label="Vadtree", command=self.vadtree_command)
        miscellaneous_menu.add_command(label="Vadwalk", command=self.vadwalk_command)
        miscellaneous_menu.add_command(label="Verinfo", command=self.verinfo_command)
        miscellaneous_menu.add_command(label="Vmwareinfo", command=self.vmwareinfo_command)
        miscellaneous_menu.add_command(label="Yara", command=self.yara_command)

        # Comando para mostrar el cheatsheet
        registry_menu.add_command(label="Mostrar Cheatsheet de Registro", command=self.show_registry_cheatsheet)
 
 ########### FIN WIDGETS
    def new_project(self):
        project_name = filedialog.asksaveasfilename(title="Crear Nuevo Proyecto")
        if project_name:
            try:
                evidence_file_path = filedialog.askopenfilename(title="Seleccionar Archivo de Evidencias")
                agent_name = "Nombre del Agente"  # Esto puede ser una entrada en el futuro
                project_path = create_project_file(project_name, evidence_file_path, agent_name)
                self.current_project_file = project_path  # Guardar referencia al proyecto actual
                self.recent_projects.insert(0, project_path)
                self.recent_projects = self.recent_projects[:10]  # Mantener solo los 10 últimos
                save_recent_projects(self.recent_projects)
                self.error_label.config(text=f"Nuevo proyecto creado en: {project_path}")
            except FileExistsError as e:
                self.show_error(str(e))
    def detect_profile(self):
        if self.current_project_file:
            project_data = load_project_file(self.current_project_file)
            evidence_file_path = project_data["evidence_file_path"]
            profiles_v2, profiles_v3 = detect_profiles(evidence_file_path)
            
            # Mostrar los perfiles sugeridos
            profiles = list(set(profiles_v2 + profiles_v3))  # Combinar y eliminar duplicados
            selected_profile = simpledialog.askstring(
                "Seleccionar Perfil",
                f"Perfiles Sugeridos por Volatility 2: {profiles_v2}\nPerfiles Sugeridos por Volatility 3: {profiles_v3}\n\nIngrese el perfil seleccionado:",
                initialvalue=profiles[0] if profiles else ""
            )
            
            if selected_profile in profiles:
                update_project_profile(self.current_project_file, selected_profile)
                self.error_label.config(text=f"Perfil seleccionado y guardado: {selected_profile}")
            else:
                self.show_error("Perfil seleccionado no válido.")
        else:
            self.show_error("No hay proyecto abierto para detectar el perfil.")
    def run_command(self, command_func, require_pid=False, require_dll_name=False):
        if self.current_project_file:
            project_data = load_project_file(self.current_project_file)
            evidence_file_path = project_data["evidence_file_path"]
            profile = project_data["profile"]
            if profile:
                pid = None
                dll_name = None
                if require_pid:
                    pid = simpledialog.askstring("Input", "Ingrese el PID (deje vacío si no es necesario):")
                if require_dll_name:
                    dll_name = simpledialog.askstring("Input", "Ingrese el nombre de la DLL (deje vacío si no es necesario):")
                if require_pid and require_dll_name:
                    output = command_func(evidence_file_path, profile, pid, dll_name)
                elif require_pid:
                    output = command_func(evidence_file_path, profile, pid)
                else:
                    output = command_func(evidence_file_path, profile)

                self.result_text_left.delete(1.0, tk.END)
                self.result_text_left.insert(tk.END, output)
            else:
                self.show_error("El perfil no está configurado.")
        else:
            self.show_error("No hay proyecto abierto para ejecutar el comando.")



    def apply_filter(self, event=None):
        filter_text = self.filter_entry.get()
        full_text = self.result_text_left.get(1.0, tk.END)
    
        filtered_lines = [line for line in full_text.split('\n') if filter_text.lower() in line.lower()]
    
        self.result_text_right.delete(1.0, tk.END)
        self.result_text_right.insert(tk.END, '\n'.join(filtered_lines))

    # Comandos de Procesos y DLLs
    def pslist_command(self):
        self.run_command(pslist)
    def pstree_command(self):
        self.run_command(pstree)
    def psscan_command(self):
        self.run_command(psscan)
    def psdispscan_command(self):
        self.run_command(psdispscan)
    def dlllist_command(self):
        self.run_command(dlllist, require_pid=True)
    def dlldump_command(self):
        pid = simpledialog.askstring("Input", "Ingrese el PID del proceso:")
        dll_name = simpledialog.askstring("Input", "Ingrese el nombre de la DLL:")
        output_path = simpledialog.askstring("Input", "Ingrese la ruta de salida (deje vacío para usar el directorio por defecto):")
        if not output_path:
            output_path = self.get_generated_files_dir()
        self.run_command(lambda evidence_file_path, profile: dlldump(evidence_file_path, profile, pid, dll_name, output_path))
    def handles_command(self):
        self.run_command(handles, require_pid=True)
    def getsids_command(self):
        self.run_command(getsids, require_pid=True)
    def cmdscan_command(self):
        self.run_command(cmdscan)
    def consoles_command(self):
        self.run_command(consoles)
    def privs_command(self):
        self.run_command(privs, require_pid=True)
    def envars_command(self):
        self.run_command(envars, require_pid=True)
    def verinfo_command(self):
        self.run_command(verinfo, require_pid=True)
    def enumfunc_command(self):
        self.run_command(enumfunc, require_pid=True)
    # Comandos de Memoria de Proceso
    def memmap_command(self):
        self.run_command(memmap)
    def memdump_command(self):
        output_path = simpledialog.askstring("Input", "Ingrese la ruta de salida (deje vacío para usar el directorio por defecto):")
        if not output_path:
            output_path = self.get_generated_files_dir()
        self.run_command(lambda evidence_file_path, profile: memdump(evidence_file_path, profile, output_path))
    def procdump_command(self):
        output_path = simpledialog.askstring("Input", "Ingrese la ruta de salida (deje vacío para usar el directorio por defecto):")
        if not output_path:
            output_path = self.get_generated_files_dir()
        self.run_command(lambda evidence_file_path, profile: procdump(evidence_file_path, profile, output_path))
    def vadinfo_command(self):
        self.run_command(vadinfo, require_pid=True)
    def vadwalk_command(self):
        self.run_command(vadwalk, require_pid=True)
    def vadtree_command(self):
        self.run_command(vadtree)
    def vaddump_command(self):
        pid = simpledialog.askstring("Input", "Ingrese el PID del proceso:")
        output_path = simpledialog.askstring("Input", "Ingrese la ruta de salida (deje vacío para usar el directorio por defecto):")
        if not output_path:
            output_path = self.get_generated_files_dir()
        self.run_command(lambda evidence_file_path, profile: vaddump(evidence_file_path, profile, pid, output_path))
    def evtlogs_command(self):
        self.run_command(evtlogs)
    def iehistory_command(self):
        self.run_command(iehistory)
    # Comandos de Memoria del Kernel y Objetos
    def modules_command(self):
        self.run_command(modules)
    def modscan_command(self):
        self.run_command(modscan)
    def moddump_command(self):
        module_name = simpledialog.askstring("Input", "Ingrese el nombre del módulo:")
        output_path = simpledialog.askstring("Input", "Ingrese la ruta de salida (deje vacío para usar el directorio por defecto):")
        if not output_path:
            output_path = self.get_generated_files_dir()
        self.run_command(lambda evidence_file_path, profile: moddump(evidence_file_path, profile, module_name, output_path))
    def ssdt_command(self):
        self.run_command(ssdt)
    def driverscan_command(self):
        self.run_command(driverscan)
    def filescan_command(self):
        self.run_command(filescan)
    def mutantscan_command(self):
        self.run_command(mutantscan)
    def symlinkscan_command(self):
        self.run_command(symlinkscan)
    def thrdscan_command(self):
        self.run_command(thrdscan)
    def dumpfiles_command(self):
        file_object = simpledialog.askstring("Input", "Ingrese el identificador del objeto de archivo:")
        output_path = simpledialog.askstring("Input", "Ingrese la ruta de salida (deje vacío para usar el directorio por defecto):")
        if not output_path:
            output_path = self.get_generated_files_dir()
        self.run_command(lambda evidence_file_path, profile: dumpfiles(evidence_file_path, profile, file_object, output_path))
    def unloadedmodules_command(self):
        self.run_command(unloadedmodules)
    # Comandos de Red
    def connections_command(self):
        self.run_command(connections)
    def connscan_command(self):
        self.run_command(connscan)
    def sockets_command(self):
        self.run_command(sockets)
    def sockscan_command(self):
        self.run_command(sockscan)
    def netscan_command(self):
        self.run_command(netscan)
    # Funciones para los Comandos de Registro
    def hivescan_command(self):
        self.run_command(hivescan)
    def hivelist_command(self):
        self.run_command(hivelist)
    def printkey_command(self):
        registry_key = simpledialog.askstring("Input", "Ingrese la clave del registro (ej. HKLM\\Software\\Microsoft\\Windows\\CurrentVersion):")
        self.run_command(lambda evidence_file_path, profile: printkey(evidence_file_path, profile, registry_key))
    def hivedump_command(self):
        offset = simpledialog.askstring("Input", "Ingrese el offset de la colmena del registro:")
        output_path = simpledialog.askstring("Input", "Ingrese la ruta de salida (deje vacío para usar el directorio por defecto):")
        if not output_path:
            output_path = self.get_generated_files_dir()
        self.run_command(lambda evidence_file_path, profile: hivedump(evidence_file_path, profile, offset, output_path))
    def hashdump_command(self):
        self.run_command(hashdump)
    def lsadump_command(self):
        self.run_command(lsadump)
    def userassist_command(self):
        self.run_command(userassist)
    def shellbags_command(self):
        self.run_command(shellbags)
    def shimcache_command(self):
        self.run_command(shimcache)
    def getservicesids_command(self):
        self.run_command(getservicesids)
    def dumpregistry_command(self):
        self.run_command(dumpregistry)
    # Funciones para los Comandos de Conversiones y Crash Dumps
    def crashinfo_command(self):
        self.run_command(crashinfo)
    def hibinfo_command(self):
        self.run_command(hibinfo)
    def imagecopy_command(self):
        self.run_command(imagecopy)
    def raw2dmp_command(self):
        output_path = simpledialog.askstring("Input", "Ingrese la ruta de salida (deje vacío para usar el directorio por defecto):")
        if not output_path:
            output_path = self.get_generated_files_dir()
        self.run_command(lambda evidence_file_path, profile: raw2dmp(evidence_file_path, profile, output_path))
    def vboxinfo_command(self):
        self.run_command(vboxinfo)
    def vmwareinfo_command(self):
        self.run_command(vmwareinfo)
    def hpakinfo_command(self):
        self.run_command(hpakinfo)
    def hpakextract_command(self):
        self.run_command(hpakextract)
    # Funciones para los Comandos de Sistema de Archivos
    def filescan_command(self):
        self.run_command(filescan)
    def lstfiles_command(self):
        self.run_command(lstfiles)
    def moddump_command(self):
        module_name = simpledialog.askstring("Input", "Ingrese el nombre del módulo:")
        output_path = simpledialog.askstring("Input", "Ingrese la ruta de salida (deje vacío para usar el directorio por defecto):")
        if not output_path:
            output_path = self.get_generated_files_dir()
        self.run_command(lambda evidence_file_path, profile: moddump(evidence_file_path, profile, module_name, output_path))
    def dumpfiles_command(self):
        file_object = simpledialog.askstring("Input", "Ingrese el identificador del objeto de archivo:")
        output_path = simpledialog.askstring("Input", "Ingrese la ruta de salida (deje vacío para usar el directorio por defecto):")
        if not output_path:
            output_path = self.get_generated_files_dir()
        self.run_command(lambda evidence_file_path, profile: dumpfiles(evidence_file_path, profile, file_object, output_path))
    def iehistory_command(self):
        self.run_command(iehistory)
    def mbrparser_command(self):
        self.run_command(mbrparser)
    def mftparser_command(self):
        self.run_command(mftparser)
    # Funciones para los Comandos de Diversos
    def clipboard_command(self):
        self.run_command(clipboard)
    def cmdscan_command(self):
        self.run_command(cmdscan)
    def consoles_command(self):
        self.run_command(consoles)
    def crashinfo_command(self):
        self.run_command(crashinfo)
    def deskscan_command(self):
        self.run_command(deskscan)
    def dumpregistry_command(self):
        self.run_command(dumpregistry)
    def envars_command(self):
        self.run_command(envars)
    def evtlogs_command(self):
        self.run_command(evtlogs)
    def files_command(self):
        self.run_command(files)
    def gahti_command(self):
        self.run_command(gahti)
    def getsids_command(self):
        self.run_command(getsids)
    def handles_command(self):
        self.run_command(handles)
    def hibinfo_command(self):
        self.run_command(hibinfo)
    def iehistory_command(self):
        self.run_command(iehistory)
    def imagecopy_command(self):
        self.run_command(imagecopy)
    def jobs_command(self):
        self.run_command(jobs)
    def kernelcomments_command(self):
        self.run_command(kernelcomments)
    def kdbgscan_command(self):
        self.run_command(kdbgscan)
    def ldrmodules_command(self):
        self.run_command(ldrmodules)
    def lsadump_command(self):
        self.run_command(lsadump)
    def machoinfo_command(self):
        self.run_command(machoinfo)
    def memdump_command(self):
        output_path = simpledialog.askstring("Input", "Ingrese la ruta de salida (deje vacío para usar el directorio por defecto):")
        if not output_path:
            output_path = self.get_generated_files_dir()
        self.run_command(lambda evidence_file_path, profile: memdump(evidence_file_path, profile, output_path))
    def memmap_command(self):
        self.run_command(memmap)
    def mftparser_command(self):
        self.run_command(mftparser)
    def mutantscan_command(self):
        self.run_command(mutantscan)
    def objtypescan_command(self):
        self.run_command(objtypescan)
    def psscan_command(self):
        self.run_command(psscan)
    def psxview_command(self):
        self.run_command(psxview)
    def shellbags_command(self):
        self.run_command(shellbags)
    def shimcache_command(self):
        self.run_command(shimcache)
    def sockets_command(self):
        self.run_command(sockets)
    def sockscan_command(self):
        self.run_command(sockscan)
    def ssdt_command(self):
        self.run_command(ssdt)
    def symlinkscan_command(self):
        self.run_command(symlinkscan)
    def thrdscan_command(self):
        self.run_command(thrdscan)
    def timeliner_command(self):
        self.run_command(timeliner)
    def unloadmodules_command(self):
        self.run_command(unloadmodules)
    def vadinfo_command(self):
        self.run_command(vadinfo)
    def vaddump_command(self):
        pid = simpledialog.askstring("Input", "Ingrese el PID del proceso:")
        output_path = simpledialog.askstring("Input", "Ingrese la ruta de salida (deje vacío para usar el directorio por defecto):")
        if not output_path:
            output_path = self.get_generated_files_dir()
        self.run_command(lambda evidence_file_path, profile: vaddump(evidence_file_path, profile, pid, output_path))
    def vadtree_command(self):
        self.run_command(vadtree)
    def vadwalk_command(self):
        self.run_command(vadwalk)
    def verinfo_command(self):
        self.run_command(verinfo)
    def vmwareinfo_command(self):
        self.run_command(vmwareinfo)
    def yara_command(self):
        self.run_command(yara)
    # Función para Mostrar el Cheatsheet de Registro
    def show_registry_cheatsheet(self):
        cheatsheet_path = os.path.join("data", "registry_cheatsheet.txt")     
        with open(cheatsheet_path, "r") as file:
            cheatsheet_text = file.read()
        cheatsheet_window = tk.Toplevel()
        cheatsheet_window.title("Registro Cheatsheet")
        text_widget = tk.Text(cheatsheet_window, wrap="word")
        text_widget.insert(tk.END, cheatsheet_text)
        text_widget.pack(expand=True, fill='both')
        close_button = tk.Button(cheatsheet_window, text="Cerrar", command=cheatsheet_window.destroy)
        close_button.pack(pady=5)
    def get_generated_files_dir(self):
        if self.current_project_file:
            project_data = load_project_file(self.current_project_file)
            return project_data.get("generated_files_dir", "default_generated_files_directory")
        return "default_generated_files_directory"
#####
    def show_recent_projects(self):
        recent_projects_str = "\n".join(self.recent_projects)
        messagebox.showinfo("Proyectos Recientes", recent_projects_str)
    def save_project_state(self):
        if self.current_project_file:
            # Lógica para obtener el estado actual del proyecto
            state = {"example_state_key": "example_state_value"}  # Ejemplo de estado
            save_project_state(self.current_project_file, state)
            self.error_label.config(text="Estado del proyecto guardado.")
        else:
            self.show_error("No hay proyecto abierto para guardar.")
    def load_project(self):
        project_file_path = filedialog.askopenfilename(title="Cargar Proyecto", filetypes=[("JSON files", "*.json")])
        if project_file_path:
            self.current_project_file = project_file_path
            project_data = load_project_file(self.current_project_file)
            self.error_label.config(text=f"Proyecto cargado: {self.current_project_file}")
        else:
            self.show_error("No se pudo cargar el proyecto.")
    def show_error(self, message):
        self.error_label.config(text=message)
