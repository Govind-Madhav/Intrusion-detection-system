# 🛡️ Intrusion Detection System (IDS)

> **Enterprise-Grade, Full-Stack, Real-Time Network Threat Sniffing & Analytics Platform**

[![Java](https://img.shields.io/badge/Java-17%2B-orange.svg?style=flat-square&logo=openjdk)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.5-brightgreen.svg?style=flat-square&logo=springboot)](https://spring.io/projects/spring-boot)
[![React](https://img.shields.io/badge/React-18.3-61DAFB.svg?style=flat-square&logo=react)](https://reactjs.org/)
[![Vite](https://img.shields.io/badge/Vite-5.3-646CFF.svg?style=flat-square&logo=vite)](https://vitejs.dev/)
[![MySQL](https://img.shields.io/badge/MySQL-8.0%2B-4479A1.svg?style=flat-square&logo=mysql)](https://www.mysql.com/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE)

---

## 📌 Executive Overview

The **Intrusion Detection System (IDS)** is a high-performance network security platform engineered to inspect live packet streams, apply stateful heuristic threat detection algorithms, and deliver real-time security alerts to a modern browser dashboard with sub-50ms latency.

By interfacing directly with the host machine's Network Interface Card (NIC) via native C-bindings (**Pcap4j** / **Npcap**), the backend sniffs OSI Layer 3 (IPv4) and Layer 4 (TCP/UDP/ICMP) packets. Identified threats are persisted to a **MySQL** database for forensic auditing and simultaneously broadcasted to a **React 18** frontend over **STOMP WebSockets**.

---

## ✨ Key Portfolio Highlights

- ⚡ **Zero-Latency Real-Time Alerting:** Uses STOMP over WebSockets to stream security alerts from packet capture to browser rendering in $< 50\text{ms}$.
- 🔍 **Low-Level Bitwise Protocol Parsing:** Performs deep header analysis (TCP flags bitwise masking) to detect stealth reconnaissance techniques like **Xmas Scans**, **Null Scans**, and rapid **SYN Scans**.
- 🧪 **Built-In Attack Injection Simulator:** Includes an embedded attack simulation engine allowing operators to inject synthetic threat vectors (DDoS Floods, Port Sweeps, DB Breaches) via REST endpoints or the UI dashboard for testing and demonstrations.
- 📊 **Interactive Security Operations Dashboard:** Built with React 18, Vite, and Recharts, featuring animated key metrics, live scrolling alert logs, search/filtering by severity, and temporal activity graphs.
- 🗄️ **Persistent Event Auditing:** Asynchronous database persistence layer powered by Spring Data JPA & Hibernate to log security events without blocking high-throughput packet processing.

---

## 🏗️ System Architecture & Data Pipeline

The system uses a decoupled **Producer-Processor-Consumer** pipeline:

```text
               ┌──────────────────────────────────────────┐
               │    Network Interface Card (NIC Wire)     │
               └────────────────────┬─────────────────────┘
                                    │ (Native Promiscuous Sniffing)
                                    ▼
               ┌──────────────────────────────────────────┐
               │         Pcap4j Packet Producer           │
               └────────────────────┬─────────────────────┘
                                    │ (PacketData Object Stream)
                                    ▼
               ┌──────────────────────────────────────────┐
               │     Thread-Safe Detection Engine         │
               │  [SYN Scan | ICMP Flood | Risky Port]    │
               └──────────┬────────────────────┬──────────┘
                          │                    │
        (Async DB Store)  │                    │ (WebSocket Event)
                          ▼                    ▼
               ┌────────────────────┐┌────────────────────┐
               │  MySQL Database    ││ STOMP WS Broker    │
               │  (Alert Entities)  ││ (/topic/alerts)    │
               └────────────────────┘└─────────┬──────────┘
                                               │
                                               ▼
                               ┌──────────────────────────┐
                               │ React 18 Operations UI   │
                               └──────────────────────────┘
```

### Data Pipeline Flow
1. **Packet Capture (Producer):** Native thread hooks into the host NIC using Pcap4j/Npcap, wrapping raw byte streams into structured `PacketData` domain models.
2. **Detection Engine (Processor):** Evaluates `PacketData` across a chain of modular `Detector` implementations using stateful rolling windows and TCP flag inspection.
3. **Alert Broadcasting (Consumer):** Triggered `AlertEvent` objects are dispatched concurrently—asynchronously saved to MySQL and published via WebSocket `/topic/alerts`.
4. **Operations Dashboard (Presentation):** React frontend consumes WebSocket frames to render dynamic threat counters, temporal distribution charts, and filterable log feeds.

---

## 🛡️ Threat Detectors Implemented

| Detector Engine | Logic & Algorithm | Trigger Condition | Severity Level |
| :--- | :--- | :--- | :--- |
| **SYN Sweep Detector** | Stateful sliding temporal window tracking unique target ports per source IP. Bitwise flag check: `tcpFlags == SYN`. | $> 15$ unique ports accessed within rolling $10\text{s}$ window. | `HIGH` / `CRITICAL` |
| **Stealth Scan Detector** | Inspects TCP control flag combinations for illegal states.<br>• **Null Scan:** No flags set (`0x00`).<br>• **Xmas Scan:** `FIN`, `PSH`, `URG` all set (`0x29`). | Packet header matches illegal TCP flag mask. | `CRITICAL` |
| **ICMP Flood Detector** | Monitors rolling ICMP echo request frequencies per source IP. | $> 50$ ICMP packets within rolling $10\text{s}$ window. | `HIGH` |
| **Risky Port Detector** | Flags connection attempts targeting sensitive or vulnerable service ports (e.g. 22/SSH, 23/Telnet, 3389/RDP, 3306/MySQL). | Dest Port matches restricted port list. | `MEDIUM` / `HIGH` |

---

## 💻 Tech Stack

### Backend
- **Core:** Java 17, Spring Boot 3.2.5
- **Packet Capture:** Pcap4j 1.8.2 (`libpcap`/`Npcap` wrapper)
- **Web & Real-Time:** Spring Web, Spring WebSocket, STOMP Messaging
- **Database & ORM:** MySQL 8, Spring Data JPA, Hibernate
- **Configuration:** Spring Dotenv (`me.paulschwarz:spring-dotenv`)

### Frontend
- **Framework:** React 18, Vite 5
- **Communication:** `@stomp/stompjs`, SockJS, Axios
- **Visualization & UI:** Recharts, Lucide Icons, Custom CSS Modules

---

## 📁 Repository Structure

```text
Intrusion-detection-system/
├── .env                       # Environment & MySQL Database configuration
├── pom.xml                    # Maven dependencies & build configuration
├── startup.bat                # One-click Windows startup script
├── Project_Documentation.md   # Comprehensive technical manual
├── README.md                  # System overview & portfolio documentation
├── frontend/                  # React 18 + Vite frontend
│   ├── package.json           # Frontend dependencies & scripts
│   ├── vite.config.js         # Vite configuration
│   └── src/                   # React components & UI logic
└── src/
    └── main/
        ├── java/com/ids/
        │   ├── Main.java      # Spring Boot application entry point
        │   ├── api/           # REST Controllers, DTOs, WebSockets & Simulator
        │   ├── capture/       # Native Pcap4j NIC interface listener
        │   ├── config/        # Environment & CLI argument parser
        │   ├── detection/     # Stateful Detection Engine & rulesets
        │   ├── model/         # PacketData & AlertEvent domain models
        │   └── output/        # Console & file alert loggers
        └── resources/
            └── application.properties  # Spring Boot & Database configuration
```

---

## ⚙️ Prerequisites & Setup

### Requirements (Windows)
1. **Java Development Kit (JDK):** Version 17 or higher
2. **Apache Maven:** Version 3.9+
3. **Node.js:** Version 18+ (with `npm`)
4. **MySQL Database:** Version 8.0+
5. **Npcap Driver:** Install [Npcap](https://npcap.com/) with **"WinPcap API Compatibility Mode"** checked.
6. **Administrator Privileges:** Command Prompt / PowerShell must run as Administrator to bind to network interfaces in promiscuous mode.

---

## 🚀 Quick Start Guide

### 1. Database Setup
Create a MySQL database named `ids_db`:
```sql
CREATE DATABASE ids_db;
```

### 2. Environment Configuration
Edit `.env` in the project root with your MySQL credentials and NIC interface details:
```ini
IDS_IFACE=Ethernet
IDS_WINDOW=10
IDS_SYN_THRESHOLD=15
IDS_ICMP_THRESHOLD=50
IDS_LOG_FILE=alerts.log

# MySQL Credentials
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=ids_db
DB_USERNAME=root
DB_PASSWORD=your_mysql_password
```

### 3. Running the Application

#### Option A: Automated One-Click Launch (Windows)
Double-click [`startup.bat`](file:///e:/My%20projects/Intrusion-detection-system/startup.bat) or run from an Administrator Terminal:
```cmd
.\startup.bat
```

#### Option B: Manual Terminal Execution

1. **Start Backend (Administrator Terminal):**
   ```bash
   mvn spring-boot:run
   ```
   *The backend will boot on `http://localhost:8080` and start packet capture.*

2. **Start Frontend (Second Terminal):**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
   *The frontend dashboard will open at `http://localhost:5173`.*

---

## 🔌 API & WebSocket Reference

### REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/alerts` | Retrieve paginated historical alerts from MySQL (`page`, `size`, `severity`). |
| `GET` | `/api/stats` | Retrieve aggregate metrics (Total Alerts, High/Critical counts, Top Attack Sources). |
| `POST` | `/api/simulate/attack` | Inject synthetic attack traffic (Params: `type`, `count`, `targetPort`). |

### WebSocket Broker Channels

| Protocol | Destination Channel | Description |
| :--- | :--- | :--- |
| **STOMP / WebSocket** | `/topic/alerts` | Real-time push channel emitting JSON payload on every detected `AlertEvent`. |

---

## 📜 License

Distributed under the **Apache License 2.0**. See [`LICENSE`](file:///e:/My%20projects/Intrusion-detection-system/LICENSE) and [`NOTICE`](file:///e:/My%20projects/Intrusion-detection-system/NOTICE) for details.
