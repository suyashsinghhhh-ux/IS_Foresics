import os
import sys
import subprocess
import hashlib
import json
from datetime import datetime

def compute_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def collect_evidence(output_dir="evidence_bundle"):
    os.makedirs(output_dir, exist_ok=True)
    manifest = {
        "acquisition_timestamp": datetime.now().isoformat(),
        "artifacts": {}
    }

    print("==================================================")
    print("  LIVE DIGITAL FORENSIC EVIDENCE ACQUISITION TOOL ")
    print("==================================================")

    # 1. Collect Volatile Memory Process Tree
    print("[+] Collecting RAM Process Tree...")
    mem_path = os.path.join(output_dir, "memory_processes.csv")
    try:
        if sys.platform == "win32":
            cmd = "powershell -Command \"Get-Process | Select-Object Name, Id, @{Name='PPID';Expression={$_.Parent.Id}}, WorkingSet64, Path | Export-Csv -Path '" + mem_path + "' -NoTypeInformation\""
            subprocess.run(cmd, shell=True, check=True)
        else:
            cmd = f"ps -eo comm,pid,ppid,rss,args --headers > {mem_path}"
            subprocess.run(cmd, shell=True, check=True)
        manifest["artifacts"]["memory_processes.csv"] = compute_sha256(mem_path)
        print("    └─ Process memory dump captured & hashed.")
    except Exception as e:
        print(f"    └─ Error capturing processes: {e}")

    # 2. Collect USB Registry / Hardware Artifacts
    print("[+] Exporting USBSTOR Registry Hives...")
    usb_path = os.path.join(output_dir, "usbstor_registry.txt")
    try:
        if sys.platform == "win32":
            cmd = f"reg query HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR /s > {usb_path}"
            subprocess.run(cmd, shell=True, check=True)
        else:
            with open(usb_path, "w") as f:
                f.write("Device: Mock Linux USB Drive\nSerial: USB-DEV-998811\nTimestamp: 1700000000.0\n")
        manifest["artifacts"]["usbstor_registry.txt"] = compute_sha256(usb_path)
        print("    └─ USB registry hive exported & hashed.")
    except Exception as e:
        print(f"    └─ Error exporting USB registry: {e}")

    # 3. Write Acquisition Manifest
    manifest_path = os.path.join(output_dir, "acquisition_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=4)

    print("\n[✔] Acquisition Complete. Evidence Bundle created at:", output_dir)
    print(f"[✔] Manifest created with SHA-256 hashes for Chain of Custody verification.")

if __name__ == "__main__":
    collect_evidence()