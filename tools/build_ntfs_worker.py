#!/usr/bin/env python3
"""Compile project code locally; never installs packages or changes the host."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from ransomware_investigator.safety import ensure_user, project_path

def build():
    ensure_user()
    directory = project_path(ROOT / ".build")
    directory.mkdir(mode=0o700, exist_ok=True)
    source = project_path(ROOT / "native/ntfs_worker.c", exists=True)
    output = project_path(directory / "ntfs_worker")
    # Fixed toolchain locations. No user-supplied compiler, flags or source path.
    args = ["/usr/bin/cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-D_FILE_OFFSET_BITS=64",
            "-I/usr/local/include", str(source), "-L/usr/local/lib", "-Wl,-rpath,/usr/local/lib", "-ltsk", "-o", str(output)]
    subprocess.run(args, check=True, timeout=60, env={"PATH":"/usr/bin:/bin", "LC_ALL":"C"})
    output.chmod(0o700)
    print(output)

if __name__ == "__main__":
    build()
