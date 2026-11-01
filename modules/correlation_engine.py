import numpy as np
import pandas as pd

def detect_slow_beaconing(network_df, threshold_std=5.0, min_packets=4):
    """
    Detects slow-and-low C2 beaconing by analyzing inter-arrival time standard deviation.
    Low standard deviation with high average interval indicates automated periodic beacons.
    """
    slow_anomalies = []
    if network_df.empty:
        return slow_anomalies

    grouped = network_df.groupby(['source_ip', 'dest_ip'])
    
    for (src, dst), group in grouped:
        if len(group) < min_packets:
            continue
            
        timestamps = group['timestamp'].sort_values().values
        intervals = np.diff(timestamps)
        
        std_dev = np.std(intervals)
        mean_interval = np.mean(intervals)
        
        # Periodic check: Low interval variance over sustained intervals (> 10 seconds)
        if std_dev < threshold_std and mean_interval > 10.0:
            slow_anomalies.append({
                'source': f"Network Channel ({src} -> {dst})",
                'anomaly_type': 'Slow/Low C2 Beaconing',
                'severity': 'HIGH',
                'mitre_id': 'T1071 (Application Layer Protocol)',
                'details': f"Automated periodic communication detected (~{round(mean_interval, 1)}s interval, StdDev: {round(std_dev, 2)})"
            })
            
    return slow_anomalies

def run_correlation(net_df, mem_df, usb_df, approved_usbs=None):
    """Executes cross-artifact forensic correlation matrix."""
    if approved_usbs is None:
        approved_usbs = []
        
    anomalies = []
    
    # 1. Fast Rule: Suspicious Network Ports
    suspicious_ports = ['4444', '6667', '8080', '1337', '31337']
    if not net_df.empty:
        flagged_net = net_df[net_df['dst_port'].astype(str).isin(suspicious_ports)]
        for _, row in flagged_net.iterrows():
            anomalies.append({
                'source': f"Network ({row['source_ip']})",
                'anomaly_type': 'Suspicious C2 Port',
                'severity': 'MEDIUM',
                'mitre_id': 'T1571 (Non-Standard Port)',
                'details': f"Traffic detected targeting high-risk port {row['dst_port']}"
            })

    # 2. Fast Rule: Unauthorized USB Hardware
    if not usb_df.empty:
        unapproved = usb_df[~usb_df['serial_number'].isin(approved_usbs)]
        for _, row in unapproved.iterrows():
            anomalies.append({
                'source': 'USB Registry',
                'anomaly_type': 'Unauthorized Hardware Insertion',
                'severity': 'HIGH',
                'mitre_id': 'T1091 (Replication Through Removable Media)',
                'details': f"Unapproved device: {row['device']} (S/N: {row['serial_number']})"
            })

    # 3. Fast Rule: Memory Process Execution Anomaly
    if not mem_df.empty:
        suspicious_paths = ['AppData\\Local\\Temp', 'Public', '/tmp']
        for _, row in mem_df.iterrows():
            path = str(row.get('ExecutablePath', ''))
            if any(sp in path for sp in suspicious_paths):
                anomalies.append({
                    'source': f"RAM Dump (PID: {row['PID']})",
                    'anomaly_type': 'Process Executed from Temp Directory',
                    'severity': 'HIGH',
                    'mitre_id': 'T1059 (Command and Scripting Interpreter)',
                    'details': f"Process '{row['ProcessName']}' running from anomalous path: {path}"
                })

    # 4. Slow Attack Rule: Inter-Arrival Variance Engine
    slow_beacons = detect_slow_beaconing(net_df)
    anomalies.extend(slow_beacons)
    
    return pd.DataFrame(anomalies)