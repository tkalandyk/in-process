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
- Present security activity in a way that is **digestible for leadership and stakeholders**

All data shown reflects **the last 7 days of telemetry**.

---

## ☁️ Azure Concepts (High-Level)

- **Azure**: Microsoft’s cloud platform.
- **Entra ID Azure’s identity system that manages user activity.
- **Virtual Machines Cloud-based computers that users can log into remotely.
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
Where successfully loggins originated over the last 7 days.


📄 **KQL Query**
```kql
SigninLogs
| where ResultType == 0
| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])
| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(City, ", ", Country)
```
📸 Map Visualization
<img width="875" height="445" alt="Entra ID (Azure) Authentication Success" src="https://github.com/user-attachments/assets/dc8644c7-7e19-4961-bb53-0e2e71c0abf1" />


## 🚫 2. Failed Azure Sign-Ins (Entra ID)

**What this shows:**
Where failed login attempts occurred and how frequently.

**Why this matters:**
Failed logins help identify where authentication attempts are failing, which is important context for security teams and leadership.

📄 KQL Query

```
SigninLogs
| where ResultType != 0 and Identity !contains "-"
| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])
| order by LoginCount desc
| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(City, ", ", Country)

```

📸 Map Visualization
<img width="1134" height="461" alt="Entra ID (Azure) Authentication Failures" src="https://github.com/user-attachments/assets/935163cd-e9c3-4ab6-a200-530bbf65dfa2" />

📊 Summary Table (Example)

| City            | Country    | Failed Logins |
| --------------- | ---------- | ------------- |
| San Luis Obispo | US         | 505           |
| Odry            | Czechia    | 474           |
| Tashkent        | Uzbekistan | 454           |



🏗️ 3. Azure Resource Creation Activity

What this shows:
Where cloud resources (VMs, NSGs, etc.) were successfully created from.

Why this matters:
Resource creation represents administrative-level activity, making visibility into where it occurs important for accountability and auditing.

📄 KQL Query

```

// Only works for IPv4 Addresses
let GeoIPDB_FULL = _GetWatchlist("geoip");
let AzureActivityRecords = AzureActivity
| where not(Caller matches regex @"^[{(]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[)}]?$")
| where CallerIpAddress matches regex @"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
| where OperationNameValue endswith "WRITE" and (ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded")
| summarize ResouceCreationCount = count() by Caller, CallerIpAddress;
AzureActivityRecords
| evaluate ipv4_lookup(GeoIPDB_FULL, CallerIpAddress, network)
| project Caller,
         CallerPrefix = split(Caller, "@")[0],  // Splits Caller UPN and takes the part before @
         CallerIpAddress,
         ResouceCreationCount,
         Country = countryname,
         Latitude = latitude,
         Longitude = longitude,
         friendly_label = strcat(cityname, countryname)

```

📸 Map Visualization
<img width="1169" height="460" alt="Azure Resource Creation" src="https://github.com/user-attachments/assets/b5523b1b-a839-413a-9d97-50c9fadc7bbe" />

📊 Summary Table (Example)

| Country       | Resource Creations |
| ------------- | ------------------ |
| United States | 68                 |
| Germany       | 6                  |
| Taiwan        | 9                  |


💻 4. Virtual Machine Authentication Failures

What this shows:
Failed login attempts directly against virtual machines.

Why this matters:
VM login failures show direct interaction attempts with compute resources, which is useful for understanding exposure.

📄 KQL Query

```
let GeoIPDB_FULL = _GetWatchlist("geoip");
DeviceLogonEvents
| where ActionType == "LogonFailed"
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, RemoteIP, network)
| summarize LoginAttempts = count() by RemoteIP, City = cityname, Country = countryname, friendly_location = strcat(cityname, " (", countryname, ")"), Latitude = latitude, Longitude = longitude;

```

📸 Map Visualization

<img width="998" height="456" alt="VM Authentication Failures" src="https://github.com/user-attachments/assets/8dbfa083-ec4a-48b7-ac7d-ce925c469461" />


📊 Summary Table (Example)


| City           | Country | Failed Attempts |
| -------------- | ------- | --------------- |
| New York       | US      | 7               |
| Salt Lake City | US      | 5               |
| London         | UK      | 3               |


🚨 5. Malicious Network Traffic Entering the Environment

What this shows:
Confirmed malicious network flows attempting to enter the Azure network.

Why this matters:
This highlights the constant global background traffic targeting internet-exposed cloud environments.

📄 KQL Query

```
let GeoIPDB_FULL = _GetWatchlist("geoip");
let MaliciousFlows = AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow"
//| where SrcIP_s == "10.0.0.5"
| order by TimeGenerated desc
| project TimeGenerated, FlowType = FlowType_s, IpAddress = SrcIP_s, DestinationIpAddress = DestIP_s, DestinationPort = DestPort_d, Protocol = L7Protocol_s, NSGRuleMatched = NSGRules_s;
MaliciousFlows
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| project TimeGenerated, FlowType, IpAddress, DestinationIpAddress, DestinationPort, Protocol, NSGRuleMatched, latitude, longitude, city = cityname, country = countryname, friendly_location = strcat(cityname, " (", countryname, ")")

```

📸 Map Visualization

<img width="1109" height="478" alt="Malicious Traffic Entering the Network" src="https://github.com/user-attachments/assets/65ff5e70-6c4f-4427-93a3-2655f973fd4d" />


📊 Summary Table (Example)

| Country        | Malicious Flows |
| -------------- | --------------- |
| United States  | 990             |
| United Kingdom | 30              |
| Australia      | 25              |

🧠 Key Takeaways

Large volumes of Azure security logs can be simplified and visualized

Geographic mapping makes security activity immediately understandable

KQL enables efficient summarization of complex telemetry

Visual reporting improves communication with non-technical audiences

🛠️ Skills Demonstrated

Kusto Query Language (KQL)

Azure Log Analytics

Entra ID authentication analysis

Network traffic analysis

Security data visualization

Executive and recruiter-focused communication








