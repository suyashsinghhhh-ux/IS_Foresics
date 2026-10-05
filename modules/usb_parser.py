import re
import pandas as pd

def parse_usb_registry(txt_path):
    """Parses USBSTOR text export for device serial numbers and connection logs."""
    usb_events = []
    with open(txt_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        
    # Regex pattern to match typical USBSTOR registry key blocks
    matches = re.findall(r"Device:\s*(.*?)\nSerial:\s*(.*?)\nTimestamp:\s*(.*?)\n", content)
    for match in matches:
        usb_events.append({
            'device': match[0].strip(),
            'serial_number': match[1].strip(),
            'timestamp': float(match[2].strip()) if match[2].strip().replace('.','',1).isdigit() else 0.0
        })
        
    return pd.DataFrame(usb_events)