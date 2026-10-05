# modules/evidence_integrity.py
import hashlib
import sqlite3
import os

def calculate_sha256(file_path):
    """Calculates SHA-256 hash of a file in binary mode."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def log_evidence_manifest(file_name, file_type, file_path, db_path="database/forensic_triage.db"):
    """Stores initial file metadata and SHA-256 hash in SQLite manifest."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    file_hash = calculate_sha256(file_path)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence_manifest (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT,
            file_type TEXT,
            sha256_hash TEXT,
            upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        INSERT INTO evidence_manifest (file_name, file_type, sha256_hash)
        VALUES (?, ?, ?)
    """, (file_name, file_type, file_hash))
    
    conn.commit()
    conn.close()
    return file_hash

def verify_evidence_integrity(file_path, original_hash):
    """Re-computes hash before analysis to verify file hasn't been altered."""
    current_hash = calculate_sha256(file_path)
    is_valid = (current_hash == original_hash)
    return is_valid, current_hash