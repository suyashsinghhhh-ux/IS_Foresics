import pandas as pd

def parse_memory_csv(csv_path):
    """Parses memory process CSV dump and standardizes column attributes."""
    try:
        df = pd.read_csv(csv_path)
    except Exception:
        return pd.DataFrame()
        
    # Standardize column headers across PowerShell/Volatility exports
    column_mapping = {
        'Name': 'ProcessName', 'ProcessName': 'ProcessName', 'comm': 'ProcessName',
        'Id': 'PID', 'PID': 'PID', 'pid': 'PID',
        'PPID': 'PPID', 'ppid': 'PPID',
        'WorkingSet64': 'MemoryUsageMB', 'MemoryUsageMB': 'MemoryUsageMB', 'rss': 'MemoryUsageMB',
        'Path': 'ExecutablePath'
    }
    df = df.rename(columns=column_mapping)
    
    for col in ['ProcessName', 'PID', 'PPID', 'MemoryUsageMB', 'ExecutablePath']:
        if col not in df.columns:
            df[col] = "Unknown" if col in ['ProcessName', 'ExecutablePath'] else 0

    return df