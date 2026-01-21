# 🌍 Making Azure Security Telemetry Understandable with KQL & Maps  
### 7-Day Enterprise Security Visibility Project

---

## 📌 Project Overview

This project analyzes **real security telemetry from a live, enterprise-scale Azure lab environment** and demonstrates how large volumes of technical data can be transformed into **clear, visual insights** that are easy for **non-technical audiences** to understand.

The environment contains **1,000+ virtual machines** with internet-exposed network security controls. As a result, it experiences **constant real-world authentication attempts and malicious traffic** from global sources.

The goal of this project was to:
- Build hands-on skill with **Kusto Query Language (KQL)**
- Analyze **real Azure security logs**
- Use **geographic mapping** to summarize large datasets
- Present security activity in a way that is **digestible for recruiters, leadership, and stakeholders**

All data shown reflects **the last 7 days of telemetry**.

---

## ☁️ Azure Concepts (High-Level)

- **Azure**: Microsoft’s cloud platform used to host applications, virtual machines, and networks.
- **Entra ID (formerly Azure Active Directory)**: Azure’s identity system that manages user logins.
- **Virtual Machines (VMs)**: Cloud-based computers that users can log into remotely.
- **Network Security Groups (NSGs)**: Firewall rules that control what network traffic is allowed or blocked.
- **Log Analytics / KQL**: Azure’s system for querying and analyzing large volumes of log data.

This project focuses on **observing and summarizing activity**, not changing or blocking it.

---

## 🎯 Security Questions Analyzed

Over a 7-day period, this project answers five core questions:

1. Who successfully logged into Azure?
2. Who failed to log into Azure?
3. Who created cloud resources (VMs, NSGs, etc.)?
4. Where VM login failures originated?
5. Where malicious network traffic came from?

Each dataset is grouped by **city and country** and visualized using maps.

---

## 🔐 1. Successful Azure Sign-Ins (Entra ID)

**What this shows:**  
Where legitimate Azure user logins originated over the last 7 days.

**Why this matters:**  
This establishes a **baseline of normal access behavior**, making it easier to recognize unusual patterns later.

📄 **KQL Query**
```kql
<!-- Insert Entra ID Authentication Success KQL -->
