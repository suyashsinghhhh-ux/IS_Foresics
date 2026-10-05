import pandas as pd

def parse_memory_csv(csv_path):
    """Parses Volatility/Tasklist process CSV export."""
    df = pd.read_csv(csv_path)
    # Standardize column naming expected by the correlation engine
    required_cols = ['ProcessName', 'PID', 'PPID', 'MemoryUsageMB', 'CreationTime']
    for col in required_cols:
        if col not in df.columns:
            df[col] = "Unknown" if col != 'MemoryUsageMB' else 0
    return df