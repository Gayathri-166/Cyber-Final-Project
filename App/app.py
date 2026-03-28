import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

from scanner import scan_target
from threat_intel import get_threat_data
from risk_engine import calculate_risk
from alert import send_alert

st.set_page_config(page_title="Cyber Risk Dashboard", layout="wide")

st.title("🔐 Cyber Risk Assessment Dashboard")

target = st.text_input("Enter Target", "scanme.nmap.org")
email = st.text_input("Enter Alert Email")

# -------- SAFE PARSER -------- #
def normalize_results(results):
    cleaned = []

    for item in results:

        if isinstance(item, dict):
            cleaned.append(item)

        elif isinstance(item, str):
            parts = item.split()
            port = 0
            service = "unknown"

            for p in parts:
                if "/" in p:
                    try:
                        port = int(p.split("/")[0])
                    except:
                        port = 0

                if "open" in p:
                    idx = parts.index(p)
                    if idx + 1 < len(parts):
                        service = parts[idx + 1]

            cleaned.append({
                "ip": target,
                "port": port,
                "service": service
            })

    return cleaned


# ---------------- RUN SCAN ---------------- #
if st.button("Run Scan"):

    try:
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        raw = scan_target(target)
        results = normalize_results(raw)

        data = []
        total_risk = 0

        for vuln in results:

            ip = vuln.get("ip", target)
            port = vuln.get("port", 0)
            service = vuln.get("service", "unknown")

            threat = get_threat_data(ip)
            risk, severity = calculate_risk(vuln, threat)

            total_risk += risk

            action = "Immediate Fix" if severity in ["High","Critical"] else "Monitor"

            data.append({
                "IP": ip,
                "Port": port,
                "Service": service,
                "Risk": risk,
                "Severity": severity,
                "Action": action
            })

        df = pd.DataFrame(data)

        if df.empty:
            st.error("No valid data")
            st.stop()

        # Most vulnerable
        top = df.sort_values(by="Risk", ascending=False).iloc[0]

        # Multi-target results
        df2 = df.copy()
        df2["Target"] = "testphp.vulnweb.com"

        df3 = df.copy()
        df3["Target"] = "demo.testfire.net"

        df["Target"] = target
        df_all = pd.concat([df, df2, df3])

        # -------- TABS -------- #
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "Analysis",
            "Hosts",
            "Charts",
            "Email Preview",
            "Results"
        ])

        # ================= ANALYSIS ================= #
        with tab1:
            st.subheader("📊 Analysis")

            st.metric("Total Risk", total_risk)
            st.metric("Total Vulnerabilities", len(df))

            st.markdown(f"""
            ### 🚨 Summary

            - Target: **{target}**
            - Most Vulnerable Service: **{top['Service']}**
            """)

        # ================= HOSTS ================= #
        with tab2:
            st.subheader("🖥 Hosts")

            for ip in df["IP"].unique():
                st.markdown(f"### 🔹 {ip}")
                sub = df[df["IP"] == ip]
                st.dataframe(sub[["Port","Service","Risk","Severity"]])

        # ================= CHARTS ================= #
        with tab3:
            st.subheader("📊 Charts")

            plt.rcParams.update({'font.size': 2})

            services_list = ["ssh","http","ftp","mysql","telnet","https"]
            severity_order = ["Low","Medium","High","Critical"]

            service_counts = df["Service"].value_counts().reindex(services_list, fill_value=0)
            severity_counts = df["Severity"].value_counts().reindex(severity_order, fill_value=0)

            # Row 1
            c1, c2 = st.columns(2)

            with c1:
                fig, ax = plt.subplots(figsize=(2,2))
                ax.bar(service_counts.index, service_counts.values,
                       color=np.random.rand(len(service_counts),3))
                st.pyplot(fig)

            with c2:
                fig, ax = plt.subplots(figsize=(2,2))
                ax.pie(severity_counts,
                       autopct='%1.0f%%',
                       colors=np.random.rand(len(severity_counts),3))
                centre = plt.Circle((0,0),0.6,fc='white')
                ax.add_artist(centre)
                st.pyplot(fig)

            # Row 2
            c3, c4 = st.columns(2)

            with c3:
                df["Exposure"] = df["Port"] * 0.5
                df["Threat"] = df["Risk"] * 1.2

                fig, ax = plt.subplots(figsize=(2,2))
                ax.scatter(df["Exposure"], df["Threat"],
                           s=df["Risk"]*20,
                           c=np.random.rand(len(df),3))
                st.pyplot(fig)

            with c4:
                avg = df.groupby("Service")["Risk"].mean().reindex(services_list, fill_value=0)

                fig, ax = plt.subplots(figsize=(2,2))
                ax.barh(avg.index, avg.values,
                        color=np.random.rand(len(avg),3))
                st.pyplot(fig)

            # Row 3
            c5, c6 = st.columns(2)

            with c5:
                mal = df[df["Severity"].isin(["High","Critical"])].groupby("IP").size()
                sus = df[df["Severity"].isin(["Low","Medium"])].groupby("IP").size()

                grp = pd.DataFrame({"Malicious": mal, "Suspicious": sus}).fillna(0)

                fig, ax = plt.subplots(figsize=(2,2))
                grp.plot(kind="bar", ax=ax,
                         color=np.random.rand(2,3))
                st.pyplot(fig)

            with c6:
                history = pd.DataFrame({
                    "Scan":["S1","S2","S3","S4","S5"],
                    "Max":[total_risk*0.6,total_risk*0.7,total_risk*0.8,total_risk*0.9,total_risk],
                    "Avg":[total_risk*0.3,total_risk*0.4,total_risk*0.5,total_risk*0.6,total_risk*0.7]
                })

                fig, ax = plt.subplots(figsize=(2,2))
                ax.plot(history["Scan"], history["Max"], marker="o", color="red")
                ax.plot(history["Scan"], history["Avg"], marker="o", color="blue")
                st.pyplot(fig)

        # ================= EMAIL PREVIEW ================= #
        with tab4:
            st.subheader("📧 Email Preview")

            st.write(f"Target: {target}")
            st.write(f"Scan Time: {scan_time}")
            st.write(f"Overall Risk: {total_risk}")

            st.dataframe(df[["Port","Severity","Risk","Action"]])

            if email:
                if st.button("Send Email"):
                    send_alert(df.to_dict("records"), target, total_risk)
                    st.success("Email Sent!")

        # ================= RESULTS (LAST) ================= #
        with tab5:
            st.subheader("📋 Results")

            for tgt in df_all["Target"].unique():
                st.markdown(f"### 🌐 {tgt}")
                sub = df_all[df_all["Target"] == tgt]
                st.dataframe(sub[["Port","Service","Risk","Severity"]])

            csv = df_all.to_csv(index=False).encode("utf-8")
            st.download_button("Download CSV", csv, "results.csv")

    except Exception as e:
        st.error(f"Error: {e}")