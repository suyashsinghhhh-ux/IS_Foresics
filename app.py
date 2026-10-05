# app.py
import streamlit as st
import pandas as pd
import plotly.express as px
import os

from modules.evidence_integrity import log_evidence_manifest, verify_evidence_integrity
from modules.pcap_parser import parse_pcap_to_db
from modules.memory_parser import parse_memory_csv
from modules.usb_parser import parse_usb_registry
from modules.correlation_engine import run_correlation

st.set_page_config(page_title="DFIR Triage Dashboard", layout="wide")
st.title("🛡️ Automated Multi-Source Digital Forensic Triage Dashboard")

os.makedirs("data", exist_ok=True)
os.makedirs("database", exist_ok=True)

st.sidebar.header("📁 Evidence Ingestion")
pcap_file = st.sidebar.file_uploader("Upload Network PCAP (.pcap)", type=["pcap"])
mem_file = st.sidebar.file_uploader("Upload Memory Dump (.csv)", type=["csv"])
usb_file = st.sidebar.file_uploader("Upload USB Registry (.txt)", type=["txt"])

if st.sidebar.button("Run Forensic Analysis"):
    manifest = []
    net_df, mem_df, usb_df = pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

    # 1. PCAP Ingestion & Hash Check
    if pcap_file:
        pcap_path = os.path.join("data", pcap_file.name)
        with open(pcap_path, "wb") as f:
            f.write(pcap_file.getbuffer())
        
        orig_hash = log_evidence_manifest(pcap_file.name, "PCAP Network Capture", pcap_path)
        is_valid, curr_hash = verify_evidence_integrity(pcap_path, orig_hash)
        
        manifest.append({
            "File Name": pcap_file.name,
            "Type": "Network PCAP",
            "SHA-256 Hash": curr_hash,
            "Integrity Status": "✅ VERIFIED" if is_valid else "❌ TAMPERED"
        })
        
        if is_valid:
            with st.spinner("Parsing PCAP to SQLite..."):
                net_df = parse_pcap_to_db(pcap_path, original_hash=orig_hash)

    # 2. Memory Ingestion & Hash Check
    if mem_file:
        mem_path = os.path.join("data", mem_file.name)
        with open(mem_path, "wb") as f:
            f.write(mem_file.getbuffer())
            
        orig_hash = log_evidence_manifest(mem_file.name, "Memory Process Dump", mem_path)
        is_valid, curr_hash = verify_evidence_integrity(mem_path, orig_hash)
        
        manifest.append({
            "File Name": mem_file.name,
            "Type": "RAM Dump",
            "SHA-256 Hash": curr_hash,
            "Integrity Status": "✅ VERIFIED" if is_valid else "❌ TAMPERED"
        })
        
        if is_valid:
            mem_df = parse_memory_csv(mem_path)

    # 3. USB Registry Ingestion & Hash Check
    if usb_file:
        usb_path = os.path.join("data", usb_file.name)
        with open(usb_path, "wb") as f:
            f.write(usb_file.getbuffer())
            
        orig_hash = log_evidence_manifest(usb_file.name, "USB Registry Log", usb_path)
        is_valid, curr_hash = verify_evidence_integrity(usb_path, orig_hash)
        
        manifest.append({
            "File Name": usb_file.name,
            "Type": "USB Registry",
            "SHA-256 Hash": curr_hash,
            "Integrity Status": "✅ VERIFIED" if is_valid else "❌ TAMPERED"
        })
        
        if is_valid:
            usb_df = parse_usb_registry(usb_path)

    # Render Evidence Manifest (Chain of Custody)
    if manifest:
        st.subheader("🔐 Evidence Chain of Custody & Cryptographic Verification")
        st.table(pd.DataFrame(manifest))
        st.markdown("---")

    # Core Metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("Network Packets Indexed", len(net_df))
    col2.metric("Active RAM Processes", len(mem_df))
    col3.metric("USB Devices Identified", len(usb_df))

    st.markdown("---")

    # Correlation Results
    st.subheader("⚠️ Correlation Engine & Anomaly Findings")
    findings = run_correlation(net_df, mem_df, usb_df)
    
    if not findings.empty:
        st.dataframe(findings, use_container_width=True)
    else:
        st.success("No anomalies detected across ingested evidence sources.")

    st.markdown("---")

    # Visualization
    if not net_df.empty:
        st.subheader("🌐 Network Protocol Breakdown")
        fig = px.pie(net_df, names='protocol', title='Protocol Distribution')
        st.plotly_chart(fig, use_container_width=True)
else:
    st.info("Upload forensic artifacts in the sidebar and click **Run Forensic Analysis** to showcase the engine.")