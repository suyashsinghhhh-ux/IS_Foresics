import streamlit as st
import pandas as pd
import plotly.express as px
import os

from modules.evidence_integrity import log_evidence_manifest, verify_evidence_integrity
from modules.pcap_parser import parse_pcap_to_db
from modules.memory_parser import parse_memory_csv
from modules.usb_parser import parse_usb_registry
from modules.correlation_engine import run_correlation
from modules.report_generator import generate_markdown_report

st.set_page_config(page_title="DFIR Triage Dashboard", layout="wide", page_icon="🛡️")

st.title("🛡️ Automated Multi-Source Digital Forensic Triage Dashboard")
st.caption("Centralized DFIR Platform for Network, Volatile RAM, and USB Registry Artifact Analysis")

os.makedirs("data", exist_ok=True)
os.makedirs("database", exist_ok=True)

# Sidebar - Ingestion
st.sidebar.header("📁 Evidence Ingestion")
pcap_file = st.sidebar.file_uploader("Upload Network PCAP (.pcap)", type=["pcap"])
mem_file = st.sidebar.file_uploader("Upload Memory Dump (.csv)", type=["csv"])
usb_file = st.sidebar.file_uploader("Upload USB Registry (.txt)", type=["txt"])

if st.sidebar.button("Run Forensic Triage Engine"):
    manifest = []
    net_df, mem_df, usb_df = pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

    # 1. Network PCAP Processing
    if pcap_file:
        pcap_path = os.path.join("data", pcap_file.name)
        with open(pcap_path, "wb") as f:
            f.write(pcap_file.getbuffer())
        
        orig_hash = log_evidence_manifest(pcap_file.name, "Network PCAP Capture", pcap_path)
        is_valid, curr_hash = verify_evidence_integrity(pcap_path, orig_hash)
        
        manifest.append({
            "File Name": pcap_file.name,
            "Type": "Network PCAP",
            "SHA-256 Hash": curr_hash,
            "Integrity Status": "✅ VERIFIED" if is_valid else "❌ TAMPERED"
        })
        
        if is_valid:
            with st.spinner("Indexing PCAP packets into SQLite database..."):
                net_df = parse_pcap_to_db(pcap_path, original_hash=orig_hash)

    # 2. RAM Memory Dump Processing
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

    # 3. USB Registry Log Processing
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

    # Core Metric Overview
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Indexed Network Packets", len(net_df))
    m2.metric("RAM Processes Inspected", len(mem_df))
    m3.metric("USB Devices Identified", len(usb_df))
    findings = run_correlation(net_df, mem_df, usb_df)
    m4.metric("Anomalies Flagged", len(findings))

    st.markdown("---")

    # Multi-Tab Dashboard Layout
    tab1, tab2, tab3, tab4 = st.tabs(["⚠️ Anomaly Matrix", "🔐 Chain of Custody", "📊 Analytics & Traffic", "📄 Executive Report"])

    with tab1:
        st.subheader("Cross-Artifact Correlation & Anomaly Findings")
        if not findings.empty:
            st.dataframe(findings, use_container_width=True)
        else:
            st.success("No security anomalies detected across ingested evidence sources.")

    with tab2:
        st.subheader("Evidence Chain of Custody (Cryptographic Manifest)")
        if manifest:
            st.table(pd.DataFrame(manifest))
        else:
            st.info("No evidence uploaded yet.")

    with tab3:
        st.subheader("Network Protocol Breakdown")
        if not net_df.empty:
            fig = px.pie(net_df, names='protocol', title='Protocol Distribution')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Upload a PCAP file to render traffic distribution charts.")

    with tab4:
        st.subheader("Export Signed Forensic Triage Report")
        report_md = generate_markdown_report(manifest, findings, len(net_df), len(mem_df), len(usb_df))
        st.markdown(report_md)
        st.download_button(
            label="💾 Download Forensic Report (.md)",
            data=report_md,
            file_name="forensic_triage_report.md",
            mime="text/markdown"
        )
else:
    st.info("👈 Upload forensic evidence files in the sidebar and click **Run Forensic Triage Engine** to begin analysis.")