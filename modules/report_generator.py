# modules/report_generator.py
from datetime import datetime
from modules.evidence_integrity import sign_report_hmac

def generate_markdown_report(manifest, findings_df, net_count, mem_count, usb_count):
    """Generates a structured Markdown forensic report signed with an HMAC signature."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    report_text = f"""# 🛡️ DIGITAL FORENSIC TRIAGE REPORT
**Generated:** {timestamp}  
**Platform:** Automated Multi-Source Forensic Triage Dashboard  

---

## 1. EVIDENCE CHAIN OF CUSTODY MANIFEST
| File Name | Evidence Type | SHA-256 Hash | Integrity Status |
| :--- | :--- | :--- | :--- |
"""
    for item in manifest:
        report_text += f"| {item['File Name']} | {item['Type']} | `{item['SHA-256 Hash']}` | {item['Integrity Status']} |\n"

    report_text += f"""
---

## 2. INGESTION STATISTICS
* **Network Packets Indexed:** {net_count}
* **Active RAM Processes:** {mem_count}
* **USB Devices Identified:** {usb_count}

---

## 3. CORRELATION & ANOMALY FINDINGS
"""
    if not findings_df.empty:
        report_text += "| Severity | Source | Anomaly Type | MITRE ATT&CK ID | Details |\n"
        report_text += "| :--- | :--- | :--- | :--- | :--- |\n"
        for _, row in findings_df.iterrows():
            report_text += f"| {row['severity']} | {row['source']} | {row['anomaly_type']} | {row['mitre_id']} | {row['details']} |\n"
    else:
        report_text += "No security anomalies detected across ingested evidence.\n"

    # Cryptographic HMAC Signing
    hmac_signature = sign_report_hmac(report_text)
    
    report_text += f"""
---

## 4. REPORT AUTHENTICITY & NON-REPUDIATION
**Cryptographic Signature (HMAC-SHA256):**  
`{hmac_signature}`  
*Verifiable by forensic authority using server secret key.*
"""
    return report_text