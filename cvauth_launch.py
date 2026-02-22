# launch_cvauth_tui.py
import os
import runpy
print("LAUNCHER STARTED")
# Ensure working directory is project root
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Run the module inside THIS process (debugger will work)
runpy.run_module("cvauth.cvauth_tui", run_name="__main__")


