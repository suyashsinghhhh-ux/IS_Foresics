import numpy as np
import pandas as pd

def detect_slow_beaconing(network_df, threshold_std=5.0, min_packets=5):
    """
    Detects slow C2 beaconing by measuring the Standard Deviation 
    of packet inter-arrival times across extended time frames.
    Low standard deviation indicates automated periodic beaconing.
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
        
        # Low variance in arrival intervals across long windows signals periodic beaconing
        if std_dev < threshold_std and mean_interval > 10.0:  # e.g. average interval > 10s
            slow_anomalies.append({
                'source': f"{src} -> {dst}",
                'anomaly_type': 'Slow/Low Beaconing (C2)',
                'severity': 'HIGH',
                'details': f"Periodic communication detected (~{round(mean_interval, 1)}s interval, StdDev: {round(std_dev, 2)})"
            })
            
    return slow_anomalies

def run_correlation(net_df, mem_df, usb_df, approved_usbs=None):
    """Runs cross-artifact correlation and rule checks."""
    if approved_usbs is None:
        approved_usbs = []
        
    anomalies = []
    
    # 1. Fast Rules: Suspicious Ports
    suspicious_ports = ['4444', '6667', '8080', '1337']
    if not net_df.empty:
        flagged_net = net_df[net_df['dst_port'].astype(str).isin(suspicious_ports)]
        for _, row in flagged_net.iterrows():
            anomalies.append({
                'source': f"Network ({row['source_ip']})",
                'anomaly_type': 'Suspicious Port Traffic',
                'severity': 'MEDIUM',
                'details': f"Traffic detected on port {row['dst_port']}"
            })

    # 2. USB Whitelist Rule
    if not usb_df.empty:
        unapproved = usb_df[~usb_df['serial_number'].isin(approved_usbs)]
        for _, row in unapproved.iterrows():
            anomalies.append({
                'source': 'USB Registry',
                'anomaly_type': 'Unauthorized Hardware',
                'severity': 'HIGH',
                'details': f"Unapproved USB Device connected: {row['device']} (S/N: {row['serial_number']})"
            })

    # 3. Slow Attack Rule: Inter-Arrival Variance Analysis
    slow_beacons = detect_slow_beaconing(net_df)
    anomalies.extend(slow_beacons)
    
    return pd.DataFrame(anomalies)