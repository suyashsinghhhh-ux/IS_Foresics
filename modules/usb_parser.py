import re
import pandas as pd

def parse_usb_registry(txt_path):
    """Extracts USB vendor details, serial numbers, and connection logs from registry exports."""
    usb_events = []
    with open(txt_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        
    # Regex parsing for Windows Registry USBSTOR keys
    matches = re.findall(r"Device:\s*(.*?)\nSerial:\s*(.*?)\nTimestamp:\s*(.*?)\n", content)
    for match in matches:
        usb_events.append({
            'device': match[0].strip(),
            'serial_number': match[1].strip(),
            'timestamp': float(match[2].strip()) if match[2].strip().replace('.','',1).isdigit() else 0.0
        })
        
    # Alternative regex for reg query output format
    if not usb_events:
        keys = re.findall(r"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\(.*?)\\(.*?)", content)
        for key in keys:
            usb_events.append({
                'device': key[0],
                'serial_number': key[1],
                'timestamp': 0.0
            })
            
    return pd.DataFrame(usb_events)