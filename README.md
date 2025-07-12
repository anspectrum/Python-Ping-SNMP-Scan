

# 🖧 Network Crawler: Ping + SNMP Scanner

A lightweight GUI-based network scanning tool built in Python. It scans a subnet for alive hosts using ICMP ping and checks for SNMP-enabled devices. Results are saved in a local SQLite database and can be exported to CSV.

---

## ✨ Features

- Scan any subnet in CIDR format (e.g., `192.168.1.0/24`)
- ICMP ping scan to find alive hosts
- SNMP check for `sysName` using community string (default: `public`)
- Stores scan results in an SQLite database
- View previous scan results by selecting saved subnets
- Export SNMP results to CSV
- Delete previous scan records from the database
- Simple GUI built using Tkinter

---

## 🖥️ GUI Preview

> Launches a desktop app with input fields for subnet and SNMP community, a live log window, and export/delete functionality.

---

## 🛠 Requirements

Install the following Python packages:

You also need Python 3.6+.

---

## 🚀 Usage

    Clone this repo

git clone https://github.com/yourusername/network-crawler.git
cd network-crawler

Run the script

    python network_crawler.py

    Usage via GUI

        Enter a subnet in CIDR notation (192.168.1.0/24)

        Optionally, change the SNMP community string

        Click "Start Scan"

        View and export results, or delete subnets

## 📁 Files

    network_crawler.py: Main application

    network_scan.db: SQLite database (created at runtime)

    .csv: Exported SNMP data (if you choose to export)

## 📝 License

This project is licensed under the MIT License — see the LICENSE file for details.
📌 Notes

    SNMP checking uses OID 1.3.6.1.2.1.1.5.0 (sysName)

    High thread counts (100 for ping, 50 for SNMP) may stress the network on large scans

    For Linux users: make sure you can send ICMP pings without sudo
