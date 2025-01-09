# main.py

from gui.main_window import MainWindow
from version_check import check_python_version, check_and_install_volatility
import tkinter as tk

def main():
    try:
        check_python_version()
        v2_path, v3_path = check_and_install_volatility()
        print(f"Volatility 2 Path: {v2_path}")
        print(f"Volatility 3 Path: {v3_path}")
    except EnvironmentError as e:
        print(f"Error: {e}")
        return

    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()
