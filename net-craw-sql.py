import ipaddress
import subprocess
import platform
import concurrent.futures
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime
from pysnmp.hlapi import *
import csv
from tkinter import filedialog

DB_NAME = "network_scan.db"

# ----------------------------
# Database Setup
# ----------------------------

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS subnets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subnet TEXT UNIQUE,
            last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS alive_hosts (
            ip TEXT PRIMARY KEY,
            subnet TEXT,
            is_alive INTEGER,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS snmp_hosts (
            ip TEXT PRIMARY KEY,
            sysname TEXT,
            community TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_scan_results(subnet, alive_hosts, snmp_devices, community):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("INSERT OR REPLACE INTO subnets (subnet, last_scanned) VALUES (?, ?)", 
                (subnet, datetime.now()))

    for ip in alive_hosts:
        cur.execute('''
            INSERT OR REPLACE INTO alive_hosts (ip, subnet, is_alive, last_seen)
            VALUES (?, ?, ?, ?)
        ''', (ip, subnet, 1, datetime.now()))

    for device in snmp_devices:
        cur.execute('''
            INSERT OR REPLACE INTO snmp_hosts (ip, sysname, community)
            VALUES (?, ?, ?)
        ''', (device['ip'], device['sysName'], community))

    conn.commit()
    conn.close()

def get_scanned_subnets():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT subnet FROM subnets ORDER BY last_scanned DESC")
    results = [row[0] for row in cur.fetchall()]
    conn.close()
    return results

def get_results_for_subnet(subnet):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT ip FROM alive_hosts WHERE subnet = ?", (subnet,))
    alive = [row[0] for row in cur.fetchall()]
    cur.execute("SELECT ip, sysname FROM snmp_hosts WHERE ip IN (SELECT ip FROM alive_hosts WHERE subnet = ?)", (subnet,))
    snmp = cur.fetchall()
    conn.close()
    return alive, snmp

# ----------------------------
# Network Functions
# ----------------------------

def ping_host(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    try:
        output = subprocess.check_output(['ping', param, '1', '-W', '1', str(ip)],
                                         stderr=subprocess.DEVNULL,
                                         universal_newlines=True)
        return str(ip) if "1 received" in output or "ttl" in output.lower() else None
    except subprocess.CalledProcessError:
        return None

def scan_subnet(subnet):
    alive_hosts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in subnet.hosts()}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                alive_hosts.append(result)
    return alive_hosts

SYSNAME_OID = '1.3.6.1.2.1.1.5.0'

def check_snmp(ip, community='public', oid=SYSNAME_OID):
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=0),
        UdpTransportTarget((ip, 161), timeout=1, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication or errorStatus:
        return None
    else:
        result = {str(name): str(value) for name, value in varBinds}
        return {'ip': ip, 'sysName': result.get(oid)}

def scan_snmp_devices(ip_list, community='public'):
    responsive_devices = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_snmp, ip, community): ip for ip in ip_list}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                responsive_devices.append(result)
    return responsive_devices

# ----------------------------
# GUI Code
# ----------------------------

class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Crawler: Ping + SNMP Scanner")

        self.subnet_label = ttk.Label(root, text="Subnet (CIDR):")
        self.subnet_label.grid(row=0, column=0, sticky="w")
        self.subnet_entry = ttk.Entry(root, width=30)
        self.subnet_entry.grid(row=0, column=1)

        self.subnet_dropdown = ttk.Combobox(root, values=get_scanned_subnets(), state="readonly")
        self.subnet_dropdown.grid(row=0, column=2)
        self.subnet_dropdown.bind("<<ComboboxSelected>>", self.load_previous_results)

        self.community_label = ttk.Label(root, text="SNMP Community:")
        self.community_label.grid(row=1, column=0, sticky="w")
        self.community_entry = ttk.Entry(root, width=30)
        self.community_entry.insert(0, "public")
        self.community_entry.grid(row=1, column=1)

        self.scan_button = ttk.Button(root, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=2, column=0, pady=10)

        self.export_button = ttk.Button(root, text="Export Subnet to CSV", command=self.export_to_csv)
        self.export_button.grid(row=2, column=1, pady=10)
        
        self.delete_button = ttk.Button(root, text="Delete Selected Subnet", command=self.delete_selected_subnet)
        self.delete_button.grid(row=2, column=2, pady=10)
        
        self.export_all_button = ttk.Button(root, text="Export All Subnets to CSV", command=self.export_all_to_csv)
        self.export_all_button.grid(row=4, column=0, columnspan=3, pady=5)

        self.output_box = scrolledtext.ScrolledText(root, width=80, height=25)
        self.output_box.grid(row=3, column=0, columnspan=3, padx=10, pady=10)

    def log(self, message):
        self.output_box.insert(tk.END, message + "\n")
        self.output_box.see(tk.END)

    def start_scan(self):
        subnet_input = self.subnet_entry.get().strip()
        community = self.community_entry.get().strip()

        try:
            subnet = ipaddress.ip_network(subnet_input, strict=False)
        except ValueError as e:
            messagebox.showerror("Invalid Subnet", f"Error: {e}")
            return

        self.output_box.delete(1.0, tk.END)
        self.log(f"[i] Scanning subnet: {subnet}")

        alive_hosts = scan_subnet(subnet)

        if not alive_hosts:
            self.log("[!] No alive hosts found.")
            return

        self.log(f"[+] Found {len(alive_hosts)} alive hosts:")
        for ip in alive_hosts:
            self.log(f"  - {ip}")

        self.log("\n[i] Scanning for SNMP on alive hosts...")
        snmp_devices = scan_snmp_devices(alive_hosts, community)

        if snmp_devices:
            self.log(f"[+] SNMP responded on {len(snmp_devices)} devices:")
            for device in snmp_devices:
                self.log(f"  - {device['ip']} (sysName: {device['sysName']})")
        else:
            self.log("[!] No devices responded to SNMP.")

        save_scan_results(str(subnet), alive_hosts, snmp_devices, community)
        self.subnet_dropdown['values'] = get_scanned_subnets()

    def load_previous_results(self, event):
        subnet = self.subnet_dropdown.get()
        self.output_box.delete(1.0, tk.END)
        self.log(f"[i] Loaded previous results for subnet: {subnet}")

        alive, snmp = get_results_for_subnet(subnet)
        self.log(f"[+] {len(alive)} alive hosts found:")
        for ip in alive:
            self.log(f"  - {ip}")
        
        if snmp:
            self.log(f"[+] SNMP responded on {len(snmp)} devices:")
            for ip, sysname in snmp:
                self.log(f"  - {ip} (sysName: {sysname})")
        else:
            self.log("[!] No SNMP devices previously detected.")

    def delete_selected_subnet(self):
        selected_subnet = self.subnet_dropdown.get()
        if not selected_subnet:
            messagebox.showwarning("No Subnet Selected", "Please select a subnet to delete.")
            return

        confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete data for subnet {selected_subnet}?")
        if not confirm:
            return

        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()

        cur.execute("DELETE FROM snmp_hosts WHERE ip IN (SELECT ip FROM alive_hosts WHERE subnet = ?)", (selected_subnet,))
        cur.execute("DELETE FROM alive_hosts WHERE subnet = ?", (selected_subnet,))
        cur.execute("DELETE FROM subnets WHERE subnet = ?", (selected_subnet,))
        conn.commit()
        conn.close()

        self.subnet_dropdown['values'] = get_scanned_subnets()
        self.subnet_dropdown.set('')
        self.output_box.delete(1.0, tk.END)
        self.log(f"[✓] Deleted records for subnet: {selected_subnet}")

    def export_to_csv(self):
        selected_subnet = self.subnet_dropdown.get()
        if not selected_subnet:
            messagebox.showwarning("No Subnet Selected", "Please select a subnet to export.")
            return

        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()

        cur.execute("SELECT ip, last_seen FROM alive_hosts WHERE subnet = ?", (selected_subnet,))
        alive_hosts = cur.fetchall()

        if not alive_hosts:
            messagebox.showinfo("No Data", f"No alive hosts found for subnet {selected_subnet}.")
            conn.close()
            return

        cur.execute("SELECT ip, sysname, community FROM snmp_hosts")
        snmp_data = {row[0]: row[1:] for row in cur.fetchall()}
        conn.close()

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Save Subnet Host Data As..."
        )
        if not file_path:
            return

        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["ip", "sysname", "community", "last_seen"])  # header

            for ip, last_seen in alive_hosts:
                sysname, community = snmp_data.get(ip, ("", ""))
                writer.writerow([ip, sysname, community, last_seen])

        messagebox.showinfo("Export Successful", f"Exported {len(alive_hosts)} entries to:\n{file_path}")
        self.log(f"[✓] Exported alive + SNMP data for {selected_subnet} to CSV.")

    def export_all_to_csv(self):
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()

        cur.execute("SELECT ip, subnet, last_seen FROM alive_hosts")
        alive_hosts = cur.fetchall()

        if not alive_hosts:
            messagebox.showinfo("No Data", "No alive hosts found in the database.")
            conn.close()
            return

        cur.execute("SELECT ip, sysname, community FROM snmp_hosts")
        snmp_data = {row[0]: row[1:] for row in cur.fetchall()}
        conn.close()

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Save All Subnet Data As..."
        )
        if not file_path:
            return

        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["ip", "sysname", "community", "last_seen", "subnet"])

            for ip, subnet, last_seen in alive_hosts:
                sysname, community = snmp_data.get(ip, ("", ""))
                writer.writerow([ip, sysname, community, last_seen, subnet])

        messagebox.showinfo("Export Successful", f"Exported {len(alive_hosts)} total entries to:\n{file_path}")
        self.log(f"[✓] Exported all subnets to CSV.")

# ----------------------------
# Main
# ----------------------------

if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()
