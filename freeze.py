from cx_Freeze import setup, Executable

setup(
    name="antivirus-pefile",
    version="0.1.1",
    description="antivirus dengan python yang keren",
    executables=[Executable("runner.py")],
    options={"build_exe": {"packages": ["streamlit", "pandas", "pefile", "ctypes"]}}
)