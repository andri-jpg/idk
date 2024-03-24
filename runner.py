import os
import streamlit as st
import pandas as pd
import pefile
import ctypes
import sys
from streamlit.web import cli as stcli
from streamlit import runtime
import subprocess
import time


def main():
    if not os.getenv("STREAMLIT_ALREADY_RUNNING"):
        os.environ["STREAMLIT_ALREADY_RUNNING"] = "true"
        sys.argv = ["streamlit", "run", "opt.py", "--server.port", "8080", "--global.developmentMode=false"]
        from streamlit.web import cli as stcli
        sys.exit(stcli.main())

if __name__ == '__main__':
    main()
