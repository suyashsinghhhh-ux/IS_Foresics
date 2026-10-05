# modules/pcap_parser.py
import pyshark
import sqlite3
import pandas as pd
from modules.evidence_integrity import calculate_sha256

def parse_pcap_to_db(pcap_path, original_hash=None, db_path="database/forensic_triage.db"):
    """Parses PCAP file into SQLite with pre-analysis integrity verification."""
    if original_hash:
        current_hash = calculate_sha256(pcap_path)
        if current_hash != original_hash:
            raise ValueError(f"CRITICAL: Integrity Check Failed for {pcap_path}! File altered.")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_packets (
            packet_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            source_ip TEXT,
            dest_ip TEXT,
            protocol TEXT,
            src_port TEXT,
            dst_port TEXT,
            length INTEGER
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_time_ip ON network_packets (timestamp, source_ip)")
    conn.commit()
    
    cap = pyshark.FileCapture(pcap_path, keep_packets=False)
    records = []
    
    for packet in cap:
        try:
            ts = float(packet.sniff_timestamp)
            ip_layer = packet.ip if 'IP' in packet else None
            src_ip = ip_layer.src if ip_layer else "N/A"
            dst_ip = ip_layer.dst if ip_layer else "N/A"
            protocol = packet.highest_layer
            
            src_port = packet[packet.transport_layer].srcport if hasattr(packet, 'transport_layer') and packet.transport_layer else "0"
            dst_port = packet[packet.transport_layer].dstport if hasattr(packet, 'transport_layer') and packet.transport_layer else "0"
            length = int(packet.length)
            
            records.append((ts, src_ip, dst_ip, protocol, src_port, dst_port, length))
        except AttributeError:
            continue
            
    cap.close()
    
    cursor.executemany("""
        INSERT INTO network_packets (timestamp, source_ip, dest_ip, protocol, src_port, dst_port, length)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, records)
    conn.commit()
    conn.close()
    
    return pd.DataFrame(records, columns=['timestamp', 'source_ip', 'dest_ip', 'protocol', 'src_port', 'dst_port', 'length'])