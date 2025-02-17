#!/usr/bin/env python3

import sys
import platform
import subprocess
import nmap
import netifaces
import socket
from scapy.all import ARP, Ether, srp, sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.progress import Progress
from getmac import get_mac_address
import json
from datetime import datetime
import requests
import re
import threading
import queue
import time
from rich.layout import Layout
from rich import box
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import tkinter.font as tkFont
import os
import paramiko
import ipaddress
import dns.resolver

# Set DISPLAY environment variable if running with sudo
if os.geteuid() == 0:  # Running as root
    user_name = os.getenv('SUDO_USER')
    if user_name:
        user_uid = int(subprocess.check_output(['id', '-u', user_name]).decode().strip())
        os.environ['DISPLAY'] = ':0.0'
        os.environ['XAUTHORITY'] = f'/home/{user_name}/.Xauthority'
        
class NetworkMonitorGUI:
    def __init__(self, target_ip):
        self.root = tk.Tk()
        self.root.title(f"Network Traffic Monitor - {target_ip}")
        self.root.geometry("1200x800")
        
        # Configure dark theme
        self.bg_color = '#2E2E2E'
        self.fg_color = '#00ff00'
        self.accent_color = '#ff0000'
        self.highlight_color = '#00ffff'
        
        self.root.configure(bg=self.bg_color)
        style = ttk.Style()
        style.theme_use('default')
        
        # Configure custom styles
        style.configure("Custom.TNotebook",
                       background=self.bg_color,
                       foreground=self.fg_color)
        
        style.configure("Custom.TNotebook.Tab",
                       background=self.bg_color,
                       foreground=self.fg_color,
                       padding=[20, 5])
        
        style.map("Custom.TNotebook.Tab",
                 background=[("selected", '#1a1a1a')],
                 foreground=[("selected", self.highlight_color)])
        
        # Create header
        header_frame = tk.Frame(self.root, bg=self.bg_color)
        header_frame.pack(fill='x', padx=10, pady=5)
        
        header_text = f"TARGET: {target_ip} | NETWORK INTERCEPTOR v2.0"
        header_label = tk.Label(
            header_frame,
            text=header_text,
            bg=self.bg_color,
            fg=self.highlight_color,
            font=('Helvetica', 16, 'bold')
        )
        header_label.pack(side='left')
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root, style="Custom.TNotebook")
        self.notebook.pack(expand=True, fill='both', padx=10, pady=5)
        
        # Create tabs
        self.dns_tab = ttk.Frame(self.notebook)
        self.conn_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.dns_tab, text="🌐 DNS ACTIVITY")
        self.notebook.add(self.conn_tab, text="🔌 CONNECTIONS")
        
        # Create tables
        self.setup_dns_table()
        self.setup_conn_table()
        
        # Statistics Frame
        self.stats_frame = tk.Frame(self.root, bg=self.bg_color)
        self.stats_frame.pack(fill='x', padx=10, pady=5)
        
        # Statistics Labels
        self.dns_count = tk.Label(
            self.stats_frame,
            text="DNS Queries: 0",
            bg=self.bg_color,
            fg=self.highlight_color,
            font=('Helvetica', 12, 'bold')
        )
        self.dns_count.pack(side='left', padx=20)
        
        self.conn_count = tk.Label(
            self.stats_frame,
            text="Active Connections: 0",
            bg=self.bg_color,
            fg=self.accent_color,
            font=('Helvetica', 12, 'bold')
        )
        self.conn_count.pack(side='left', padx=20)
        
        # Counters
        self.dns_counter = 0
        self.conn_counter = 0
        
        # Create context menus
        self.create_dns_context_menu()
        self.create_conn_context_menu()

    def create_dns_context_menu(self):
        """Create context menu for DNS table."""
        self.dns_menu = tk.Menu(self.root, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        
        # Lookup submenu
        lookup_menu = tk.Menu(self.dns_menu, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        lookup_menu.add_command(label="🔍 DNS Lookup", command=self.lookup_domain)
        lookup_menu.add_command(label="🌐 WHOIS Lookup", command=self.whois_lookup)
        lookup_menu.add_command(label="📡 Reverse DNS", command=self.reverse_dns_lookup)
        self.dns_menu.add_cascade(label="Lookup", menu=lookup_menu)
        
        # Security submenu
        security_menu = tk.Menu(self.dns_menu, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        security_menu.add_command(label="🔒 SSL Certificate", command=self.check_ssl)
        security_menu.add_command(label="🛡️ Security Headers", command=self.check_security_headers)
        security_menu.add_command(label="⚠️ DNS Security", command=self.check_dns_sec)
        self.dns_menu.add_cascade(label="Security", menu=security_menu)
        
        # Tools submenu
        tools_menu = tk.Menu(self.dns_menu, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        tools_menu.add_command(label="🌐 Open in Browser", command=self.open_in_browser)
        tools_menu.add_command(label="📋 Copy Domain", command=self.copy_domain)
        tools_menu.add_command(label="📊 Ping Domain", command=self.ping_domain)
        tools_menu.add_command(label="🍪 Export Cookies", command=self.export_cookies)
        self.dns_menu.add_cascade(label="Tools", menu=tools_menu)
        
        self.dns_menu.add_separator()
        self.dns_menu.add_command(label="📝 Export as CSV", command=self.export_dns_csv)
        self.dns_menu.add_command(label="💾 Save to File", command=self.save_dns_to_file)
        self.dns_menu.add_command(label="🗑️ Clear DNS History", command=self.clear_dns_history)
        
        # Bind right-click event
        self.dns_tree.bind("<Button-3>", self.show_dns_menu)

    def create_conn_context_menu(self):
        """Create context menu for Connections table."""
        self.conn_menu = tk.Menu(self.root, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        
        # Scan submenu
        scan_menu = tk.Menu(self.conn_menu, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        scan_menu.add_command(label="🔍 Quick Port Scan", command=self.scan_port)
        scan_menu.add_command(label="🔎 Full Port Scan", command=self.full_port_scan)
        scan_menu.add_command(label="🛡️ Vulnerability Scan", command=self.vuln_scan)
        self.conn_menu.add_cascade(label="Scan", menu=scan_menu)
        
        # Analysis submenu
        analysis_menu = tk.Menu(self.conn_menu, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        analysis_menu.add_command(label="📊 Traffic Analysis", command=self.analyze_traffic)
        analysis_menu.add_command(label="📈 Connection Stats", command=self.show_conn_stats)
        analysis_menu.add_command(label="🔄 Service Detection", command=self.detect_service)
        self.conn_menu.add_cascade(label="Analysis", menu=analysis_menu)
        
        # Tools submenu
        tools_menu = tk.Menu(self.conn_menu, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        tools_menu.add_command(label="🌐 Trace Route", command=self.trace_route)
        tools_menu.add_command(label="📋 Copy IP", command=self.copy_ip)
        tools_menu.add_command(label="📡 Ping IP", command=self.ping_ip)
        self.conn_menu.add_cascade(label="Tools", menu=tools_menu)
        
        self.conn_menu.add_separator()
        self.conn_menu.add_command(label="📝 Export as CSV", command=self.export_conn_csv)
        self.conn_menu.add_command(label="💾 Save to File", command=self.save_conn_to_file)
        self.conn_menu.add_command(label="🗑️ Clear Connection History", command=self.clear_conn_history)
        
        # Bind right-click event
        self.conn_tree.bind("<Button-3>", self.show_conn_menu)

    def show_dns_menu(self, event):
        """Show DNS context menu."""
        try:
            item = self.dns_tree.identify('item', event.x, event.y)
            if item:
                self.dns_tree.selection_set(item)
                self.dns_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.dns_menu.grab_release()

    def show_conn_menu(self, event):
        """Show Connections context menu."""
        try:
            item = self.conn_tree.identify('item', event.x, event.y)
            if item:
                self.conn_tree.selection_set(item)
                self.conn_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.conn_menu.grab_release()

    def lookup_domain(self):
        """Perform DNS lookup on selected domain."""
        selected = self.dns_tree.selection()
        if not selected:
            return
        
        domain = self.dns_tree.item(selected[0])['values'][1]
        try:
            import socket
            ip = socket.gethostbyname(domain)
            tk.messagebox.showinfo("DNS Lookup", f"Domain: {domain}\nIP: {ip}")
        except Exception as e:
            tk.messagebox.showerror("Error", f"Lookup failed: {str(e)}")

    def copy_domain(self):
        """Copy selected domain to clipboard."""
        selected = self.dns_tree.selection()
        if not selected:
            return
        
        domain = self.dns_tree.item(selected[0])['values'][1]
        self.root.clipboard_clear()
        self.root.clipboard_append(domain)

    def open_in_browser(self):
        """Open selected domain in default web browser."""
        selected = self.dns_tree.selection()
        if not selected:
            return
        
        domain = self.dns_tree.item(selected[0])['values'][1]
        try:
            import webbrowser
            webbrowser.open(f"http://{domain}")
        except Exception as e:
            tk.messagebox.showerror("Error", f"Failed to open browser: {str(e)}")

    def save_dns_to_file(self):
        """Save DNS history to file."""
        filename = tk.filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    for item in self.dns_tree.get_children():
                        values = self.dns_tree.item(item)['values']
                        f.write(f"Time: {values[0]}, Domain: {values[1]}, Type: {values[2]}, Response: {values[3]}\n")
                tk.messagebox.showinfo("Success", "DNS history saved successfully!")
            except Exception as e:
                tk.messagebox.showerror("Error", f"Failed to save file: {str(e)}")

    def clear_dns_history(self):
        """Clear all DNS history."""
        if tk.messagebox.askyesno("Confirm", "Are you sure you want to clear DNS history?"):
            for item in self.dns_tree.get_children():
                self.dns_tree.delete(item)
            self.dns_counter = 0
            self.dns_count.config(text="DNS Queries: 0")

    def scan_port(self):
        """Scan port of selected connection."""
        selected = self.conn_tree.selection()
        if not selected:
            return
        
        values = self.conn_tree.item(selected[0])['values']
        ip = values[2]  # Destination IP
        port = int(values[3])  # Port
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            status = "Open" if result == 0 else "Closed"
            tk.messagebox.showinfo("Port Scan", f"IP: {ip}\nPort: {port}\nStatus: {status}")
        except Exception as e:
            tk.messagebox.showerror("Error", f"Scan failed: {str(e)}")

    def copy_ip(self):
        """Copy selected IP to clipboard."""
        selected = self.conn_tree.selection()
        if not selected:
            return
        
        ip = self.conn_tree.item(selected[0])['values'][2]
        self.root.clipboard_clear()
        self.root.clipboard_append(ip)

    def trace_route(self):
        """Perform traceroute on selected IP."""
        selected = self.conn_tree.selection()
        if not selected:
            return
        
        ip = self.conn_tree.item(selected[0])['values'][2]
        try:
            import subprocess
            result = subprocess.check_output(['traceroute', ip]).decode()
            
            # Create popup window for traceroute results
            popup = tk.Toplevel(self.root)
            popup.title(f"Traceroute to {ip}")
            popup.geometry("600x400")
            popup.configure(bg=self.bg_color)
            
            text = tk.Text(popup, bg=self.bg_color, fg=self.fg_color)
            text.pack(fill='both', expand=True)
            text.insert('1.0', result)
            text.config(state='disabled')
        except Exception as e:
            tk.messagebox.showerror("Error", f"Traceroute failed: {str(e)}")

    def save_conn_to_file(self):
        """Save connection history to file."""
        filename = tk.filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    for item in self.conn_tree.get_children():
                        values = self.conn_tree.item(item)['values']
                        f.write(f"Time: {values[0]}, Protocol: {values[1]}, IP: {values[2]}, Port: {values[3]}, Service: {values[4]}, Status: {values[5]}\n")
                tk.messagebox.showinfo("Success", "Connection history saved successfully!")
            except Exception as e:
                tk.messagebox.showerror("Error", f"Failed to save file: {str(e)}")

    def clear_conn_history(self):
        """Clear all connection history."""
        if tk.messagebox.askyesno("Confirm", "Are you sure you want to clear connection history?"):
            for item in self.conn_tree.get_children():
                self.conn_tree.delete(item)
            self.conn_counter = 0
            self.conn_count.config(text="Active Connections: 0")

    def setup_dns_table(self):
        columns = ('Time', 'Domain', 'Type', 'Response')
        self.dns_tree = ttk.Treeview(self.dns_tab, columns=columns, show='headings', height=25)
        
        # Configure columns
        self.dns_tree.heading('Time', text='TIMESTAMP')
        self.dns_tree.heading('Domain', text='DOMAIN')
        self.dns_tree.heading('Type', text='TYPE')
        self.dns_tree.heading('Response', text='RESPONSE')
        
        self.dns_tree.column('Time', width=100)
        self.dns_tree.column('Domain', width=400)
        self.dns_tree.column('Type', width=100)
        self.dns_tree.column('Response', width=500)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.dns_tab, orient='vertical', command=self.dns_tree.yview)
        self.dns_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack elements
        self.dns_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

    def setup_conn_table(self):
        columns = ('Time', 'Protocol', 'Destination', 'Port', 'Service', 'Status')
        self.conn_tree = ttk.Treeview(self.conn_tab, columns=columns, show='headings', height=25)
        
        # Configure columns
        self.conn_tree.heading('Time', text='TIMESTAMP')
        self.conn_tree.heading('Protocol', text='PROTOCOL')
        self.conn_tree.heading('Destination', text='DESTINATION')
        self.conn_tree.heading('Port', text='PORT')
        self.conn_tree.heading('Service', text='SERVICE')
        self.conn_tree.heading('Status', text='STATUS')
        
        self.conn_tree.column('Time', width=100)
        self.conn_tree.column('Protocol', width=100)
        self.conn_tree.column('Destination', width=200)
        self.conn_tree.column('Port', width=100)
        self.conn_tree.column('Service', width=150)
        self.conn_tree.column('Status', width=150)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.conn_tab, orient='vertical', command=self.conn_tree.yview)
        self.conn_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack elements
        self.conn_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

    def update_dns(self, data):
        timestamp = data["timestamp"]
        domain = data["domain"]
        qtype = data["type"]
        response = data["response"]
        
        # Insert at the beginning of the table
        self.dns_tree.insert('', 0, values=(timestamp, domain, qtype, response))
        
        # Update counter
        self.dns_counter += 1
        self.dns_count.config(text=f"DNS Queries: {self.dns_counter}")

    def update_conn(self, data):
        timestamp = data["timestamp"]
        destination = data["destination"]
        protocol = data["protocol"]
        service = data["service"]
        port = data["port"]
        status = data["status"]
        
        # Insert at the beginning of the table
        self.conn_tree.insert('', 0, values=(timestamp, protocol, destination, port, service, status))
        
        # Update counter
        self.conn_counter += 1
        self.conn_count.config(text=f"Active Connections: {self.conn_counter}")
        
        # Color coding based on protocol
        last_item = self.conn_tree.get_children()[0]
        if protocol == "TCP":
            self.conn_tree.item(last_item, tags=('tcp',))
        elif protocol == "UDP":
            self.conn_tree.item(last_item, tags=('udp',))
        
        # Configure tag colors
        self.conn_tree.tag_configure('tcp', foreground='#00ff00')
        self.conn_tree.tag_configure('udp', foreground='#ff9900')

    def whois_lookup(self):
        """Perform WHOIS lookup on selected domain."""
        selected = self.dns_tree.selection()
        if not selected:
            return
        
        domain = self.dns_tree.item(selected[0])['values'][1]
        try:
            result = subprocess.check_output(['whois', domain]).decode()
            
            # Create popup window for WHOIS results
            popup = tk.Toplevel(self.root)
            popup.title(f"WHOIS Lookup - {domain}")
            popup.geometry("800x600")
            popup.configure(bg=self.bg_color)
            
            text = tk.Text(popup, bg=self.bg_color, fg=self.fg_color)
            text.pack(fill='both', expand=True)
            text.insert('1.0', result)
            text.config(state='disabled')
        except Exception as e:
            tk.messagebox.showerror("Error", f"WHOIS lookup failed: {str(e)}")

    def reverse_dns_lookup(self):
        """Perform reverse DNS lookup on selected domain."""
        selected = self.dns_tree.selection()
        if not selected:
            return
        
        domain = self.dns_tree.item(selected[0])['values'][1]
        try:
            ip = socket.gethostbyname(domain)
            hostname = socket.gethostbyaddr(ip)[0]
            tk.messagebox.showinfo("Reverse DNS Lookup", f"Domain: {domain}\nIP: {ip}\nHostname: {hostname}")
        except Exception as e:
            tk.messagebox.showerror("Error", f"Reverse DNS lookup failed: {str(e)}")

    def check_ssl(self):
        """Check SSL certificate of selected domain."""
        selected = self.dns_tree.selection()
        if not selected:
            return
        
        domain = self.dns_tree.item(selected[0])['values'][1]
        try:
            import ssl
            import OpenSSL.crypto
            
            cert = ssl.get_server_certificate((domain, 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            
            # Create popup window for certificate info
            popup = tk.Toplevel(self.root)
            popup.title(f"SSL Certificate - {domain}")
            popup.geometry("600x400")
            popup.configure(bg=self.bg_color)
            
            text = tk.Text(popup, bg=self.bg_color, fg=self.fg_color)
            text.pack(fill='both', expand=True)
            
            # Add certificate information
            text.insert('end', f"Subject: {x509.get_subject().CN}\n")
            text.insert('end', f"Issuer: {x509.get_issuer().CN}\n")
            text.insert('end', f"Valid From: {x509.get_notBefore().decode()}\n")
            text.insert('end', f"Valid Until: {x509.get_notAfter().decode()}\n")
            text.insert('end', f"Serial Number: {x509.get_serial_number()}\n")
            text.insert('end', f"Version: {x509.get_version()}\n")
            
            text.config(state='disabled')
        except Exception as e:
            tk.messagebox.showerror("Error", f"SSL check failed: {str(e)}")

    def check_security_headers(self):
        """Check security headers of selected domain."""
        selected = self.dns_tree.selection()
        if not selected:
            return
        
        domain = self.dns_tree.item(selected[0])['values'][1]
        try:
            import requests
            response = requests.get(f"https://{domain}", verify=False)
            headers = response.headers
            
            # Create popup window for headers
            popup = tk.Toplevel(self.root)
            popup.title(f"Security Headers - {domain}")
            popup.geometry("600x400")
            popup.configure(bg=self.bg_color)
            
            text = tk.Text(popup, bg=self.bg_color, fg=self.fg_color)
            text.pack(fill='both', expand=True)
            
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Referrer-Policy'
            ]
            
            for header in security_headers:
                value = headers.get(header, 'Not Set')
                text.insert('end', f"{header}: {value}\n")
            
            text.config(state='disabled')
        except Exception as e:
            tk.messagebox.showerror("Error", f"Security headers check failed: {str(e)}")

    def check_dns_sec(self):
        """Check DNSSEC of selected domain."""
        selected = self.dns_tree.selection()
        if not selected:
            return
        
        domain = self.dns_tree.item(selected[0])['values'][1]
        try:
            result = subprocess.check_output(['dig', '+dnssec', domain]).decode()
            
            # Create popup window for DNSSEC info
            popup = tk.Toplevel(self.root)
            popup.title(f"DNSSEC Check - {domain}")
            popup.geometry("600x400")
            popup.configure(bg=self.bg_color)
            
            text = tk.Text(popup, bg=self.bg_color, fg=self.fg_color)
            text.pack(fill='both', expand=True)
            text.insert('1.0', result)
            text.config(state='disabled')
        except Exception as e:
            tk.messagebox.showerror("Error", f"DNSSEC check failed: {str(e)}")

    def ping_domain(self):
        """Ping selected domain."""
        selected = self.dns_tree.selection()
        if not selected:
            return
        
        domain = self.dns_tree.item(selected[0])['values'][1]
        try:
            result = subprocess.check_output(['ping', '-c', '4', domain]).decode()
            
            # Create popup window for ping results
            popup = tk.Toplevel(self.root)
            popup.title(f"Ping Results - {domain}")
            popup.geometry("500x300")
            popup.configure(bg=self.bg_color)
            
            text = tk.Text(popup, bg=self.bg_color, fg=self.fg_color)
            text.pack(fill='both', expand=True)
            text.insert('1.0', result)
            text.config(state='disabled')
        except Exception as e:
            tk.messagebox.showerror("Error", f"Ping failed: {str(e)}")

    def export_dns_csv(self):
        """Export DNS history to CSV file."""
        filename = tk.filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if filename:
            try:
                import csv
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Time', 'Domain', 'Type', 'Response'])
                    for item in self.dns_tree.get_children():
                        values = self.dns_tree.item(item)['values']
                        writer.writerow(values)
                tk.messagebox.showinfo("Success", "DNS history exported successfully!")
            except Exception as e:
                tk.messagebox.showerror("Error", f"Failed to export CSV: {str(e)}")

    def full_port_scan(self):
        """Perform full port scan on selected IP."""
        selected = self.conn_tree.selection()
        if not selected:
            return
        
        values = self.conn_tree.item(selected[0])['values']
        ip = values[2]  # Destination IP
        
        try:
            # Create progress window
            progress_window = tk.Toplevel(self.root)
            progress_window.title(f"Port Scan - {ip}")
            progress_window.geometry("400x300")
            progress_window.configure(bg=self.bg_color)
            
            status_label = tk.Label(
                progress_window,
                text="Scanning ports...",
                bg=self.bg_color,
                fg=self.fg_color
            )
            status_label.pack(pady=10)
            
            # Start port scan in a separate thread
            def scan_thread():
                try:
                    nm = nmap.PortScanner()
                    nm.scan(ip, arguments='-p- -T4')
                    
                    result_text = tk.Text(progress_window, bg=self.bg_color, fg=self.fg_color)
                    result_text.pack(fill='both', expand=True, padx=10, pady=10)
                    
                    for proto in nm[ip].all_protocols():
                        ports = nm[ip][proto].keys()
                        for port in ports:
                            state = nm[ip][proto][port]['state']
                            service = nm[ip][proto][port]['name']
                            result_text.insert('end', f"Port {port}/{proto}: {state} ({service})\n")
                    
                    result_text.config(state='disabled')
                    status_label.config(text="Scan complete")
                except Exception as e:
                    tk.messagebox.showerror("Error", f"Port scan failed: {str(e)}")
                    progress_window.destroy()
            
            threading.Thread(target=scan_thread, daemon=True).start()
            
        except Exception as e:
            tk.messagebox.showerror("Error", f"Port scan failed: {str(e)}")

    def vuln_scan(self):
        """Perform vulnerability scan on selected IP."""
        selected = self.conn_tree.selection()
        if not selected:
            return
        
        values = self.conn_tree.item(selected[0])['values']
        ip = values[2]  # Destination IP
        port = values[3]  # Port
        
        try:
            # Create progress window
            progress_window = tk.Toplevel(self.root)
            progress_window.title(f"Vulnerability Scan - {ip}:{port}")
            progress_window.geometry("500x400")
            progress_window.configure(bg=self.bg_color)
            
            status_label = tk.Label(
                progress_window,
                text="Scanning for vulnerabilities...",
                bg=self.bg_color,
                fg=self.fg_color
            )
            status_label.pack(pady=10)
            
            result_text = tk.Text(progress_window, bg=self.bg_color, fg=self.fg_color)
            result_text.pack(fill='both', expand=True, padx=10, pady=10)
            
            def scan_thread():
                try:
                    # Basic vulnerability checks
                    result_text.insert('end', "Running basic security checks...\n\n")
                    
                    # Check for open ports
                    nm = nmap.PortScanner()
                    nm.scan(ip, arguments=f'-p{port} -sV --script=vuln')
                    
                    if 'tcp' in nm[ip] and int(port) in nm[ip]['tcp']:
                        port_info = nm[ip]['tcp'][int(port)]
                        result_text.insert('end', f"Port {port} Information:\n")
                        result_text.insert('end', f"State: {port_info['state']}\n")
                        result_text.insert('end', f"Service: {port_info['name']}\n")
                        result_text.insert('end', f"Version: {port_info.get('version', 'unknown')}\n")
                        result_text.insert('end', f"Extra Info: {port_info.get('extrainfo', 'none')}\n")
                        
                        # Check for common vulnerabilities
                        if 'script' in port_info:
                            result_text.insert('end', "\nScript Results:\n")
                            for script, output in port_info['script'].items():
                                result_text.insert('end', f"\n{script}:\n{output}")
                    
                    result_text.config(state='disabled')
                    status_label.config(text="Scan complete")
                except Exception as e:
                    tk.messagebox.showerror("Error", f"Vulnerability scan failed: {str(e)}")
                    progress_window.destroy()
            
            threading.Thread(target=scan_thread, daemon=True).start()
            
        except Exception as e:
            tk.messagebox.showerror("Error", f"Vulnerability scan failed: {str(e)}")

    def analyze_traffic(self):
        """Analyze traffic patterns for selected connection."""
        selected = self.conn_tree.selection()
        if not selected:
            return
        
        values = self.conn_tree.item(selected[0])['values']
        ip = values[2]  # Destination IP
        port = values[3]  # Port
        protocol = values[1]  # Protocol
        
        # Create analysis window
        analysis_window = tk.Toplevel(self.root)
        analysis_window.title(f"Traffic Analysis - {ip}:{port}")
        analysis_window.geometry("600x400")
        analysis_window.configure(bg=self.bg_color)
        
        # Add traffic statistics
        stats_frame = tk.Frame(analysis_window, bg=self.bg_color)
        stats_frame.pack(fill='x', padx=10, pady=5)
        
        # Count occurrences of this IP in connections
        conn_count = 0
        for item in self.conn_tree.get_children():
            if self.conn_tree.item(item)['values'][2] == ip:
                conn_count += 1
        
        tk.Label(
            stats_frame,
            text=f"Total Connections: {conn_count}",
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(anchor='w')
        
        tk.Label(
            stats_frame,
            text=f"Protocol: {protocol}",
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(anchor='w')
        
        # Add traffic graph (placeholder)
        graph_frame = tk.Frame(analysis_window, bg=self.bg_color)
        graph_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        tk.Label(
            graph_frame,
            text="Traffic Pattern Analysis",
            bg=self.bg_color,
            fg=self.fg_color
        ).pack()

    def show_conn_stats(self):
        """Show connection statistics."""
        # Create stats window
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Connection Statistics")
        stats_window.geometry("500x400")
        stats_window.configure(bg=self.bg_color)
        
        # Calculate statistics
        total_conns = len(self.conn_tree.get_children())
        tcp_count = 0
        udp_count = 0
        unique_ips = set()
        port_counts = {}
        
        for item in self.conn_tree.get_children():
            values = self.conn_tree.item(item)['values']
            protocol = values[1]
            ip = values[2]
            port = values[3]
            
            if protocol == "TCP":
                tcp_count += 1
            elif protocol == "UDP":
                udp_count += 1
            
            unique_ips.add(ip)
            port_counts[port] = port_counts.get(port, 0) + 1
        
        # Display statistics
        stats_text = tk.Text(stats_window, bg=self.bg_color, fg=self.fg_color)
        stats_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        stats_text.insert('end', f"Total Connections: {total_conns}\n")
        stats_text.insert('end', f"TCP Connections: {tcp_count}\n")
        stats_text.insert('end', f"UDP Connections: {udp_count}\n")
        stats_text.insert('end', f"Unique IPs: {len(unique_ips)}\n\n")
        
        stats_text.insert('end', "Top Ports:\n")
        sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        for port, count in sorted_ports:
            stats_text.insert('end', f"Port {port}: {count} connections\n")
        
        stats_text.config(state='disabled')

    def detect_service(self):
        """Detect service running on the selected connection."""
        selected = self.conn_tree.selection()
        if not selected:
            return
        
        values = self.conn_tree.item(selected[0])['values']
        ip = values[2]  # Destination IP
        port = int(values[3])  # Port
        
        try:
            # Create service detection window
            service_window = tk.Toplevel(self.root)
            service_window.title(f"Service Detection - {ip}:{port}")
            service_window.geometry("500x400")
            service_window.configure(bg=self.bg_color)
            
            text = tk.Text(service_window, bg=self.bg_color, fg=self.fg_color)
            text.pack(fill='both', expand=True, padx=10, pady=10)
            
            # Run nmap service detection
            nm = nmap.PortScanner()
            nm.scan(ip, arguments=f'-p{port} -sV -sC')
            
            if 'tcp' in nm[ip] and port in nm[ip]['tcp']:
                port_info = nm[ip]['tcp'][port]
                text.insert('end', f"Port: {port}\n")
                text.insert('end', f"State: {port_info['state']}\n")
                text.insert('end', f"Service: {port_info['name']}\n")
                text.insert('end', f"Product: {port_info.get('product', 'unknown')}\n")
                text.insert('end', f"Version: {port_info.get('version', 'unknown')}\n")
                text.insert('end', f"Extra Info: {port_info.get('extrainfo', 'none')}\n")
                
                if 'script' in port_info:
                    text.insert('end', "\nScript Results:\n")
                    for script, output in port_info['script'].items():
                        text.insert('end', f"\n{script}:\n{output}")
            
            text.config(state='disabled')
        except Exception as e:
            tk.messagebox.showerror("Error", f"Service detection failed: {str(e)}")

    def ping_ip(self):
        """Ping selected IP address."""
        selected = self.conn_tree.selection()
        if not selected:
            return
        
        ip = self.conn_tree.item(selected[0])['values'][2]
        try:
            result = subprocess.check_output(['ping', '-c', '4', ip]).decode()
            
            # Create popup window for ping results
            popup = tk.Toplevel(self.root)
            popup.title(f"Ping Results - {ip}")
            popup.geometry("500x300")
            popup.configure(bg=self.bg_color)
            
            text = tk.Text(popup, bg=self.bg_color, fg=self.fg_color)
            text.pack(fill='both', expand=True)
            text.insert('1.0', result)
            text.config(state='disabled')
        except Exception as e:
            tk.messagebox.showerror("Error", f"Ping failed: {str(e)}")

    def export_conn_csv(self):
        """Export connection history to CSV file."""
        filename = tk.filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if filename:
            try:
                import csv
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Time', 'Protocol', 'Destination', 'Port', 'Service', 'Status'])
                    for item in self.conn_tree.get_children():
                        values = self.conn_tree.item(item)['values']
                        writer.writerow(values)
                tk.messagebox.showinfo("Success", "Connection history exported successfully!")
            except Exception as e:
                tk.messagebox.showerror("Error", f"Failed to export CSV: {str(e)}")

    def export_cookies(self):
        """Export cookies in Netscape format for selected domain."""
        selected = self.dns_tree.selection()
        if not selected:
            return
        
        domain = self.dns_tree.item(selected[0])['values'][1]
        
        # Create a file dialog for saving cookies
        filename = tk.filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Cookie files", "*.txt"), ("All files", "*.*")],
            initialfile=f"{domain}_cookies.txt"
        )
        
        if filename:
            try:
                # Create a socket connection to get cookies
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                
                # Try to connect to port 80 first, then 443
                try:
                    sock.connect((domain, 80))
                    is_https = False
                except:
                    try:
                        sock.connect((domain, 443))
                        is_https = True
                    except:
                        tk.messagebox.showerror("Error", "Could not connect to the domain")
                        return
                
                # Send HTTP request to get cookies
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {domain}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                    f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
                    f"Accept-Language: en-US,en;q=0.5\r\n"
                    f"Connection: close\r\n\r\n"
                )
                
                if is_https:
                    import ssl
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock)
                
                sock.send(request.encode())
                
                # Read response headers
                response = b""
                cookies = []
                while True:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            break
                        response += data
                        if b"\r\n\r\n" in response:
                            break
                    except:
                        break
                
                # Parse Set-Cookie headers
                headers = response.decode('utf-8', errors='ignore').split("\r\n")
                for header in headers:
                    if header.lower().startswith("set-cookie:"):
                        cookie = header[11:].strip()
                        cookies.append(cookie)
                
                # Write cookies in Netscape format
                with open(filename, 'w') as f:
                    f.write("# Netscape HTTP Cookie File\n")
                    f.write("# http://curl.haxx.se/rfc/cookie_spec.html\n")
                    f.write("# This file was generated by Network Scanner\n\n")
                    
                    for cookie in cookies:
                        try:
                            # Parse cookie parts
                            parts = cookie.split(';')
                            main_part = parts[0].strip()
                            name, value = main_part.split('=', 1)
                            
                            # Default values
                            cookie_domain = f".{domain}"  # Add dot prefix for domain cookies
                            path = "/"
                            secure = "FALSE"
                            httponly = False
                            expiry = int(time.time() + 86400 * 30)  # 30 days default
                            
                            # Parse additional attributes
                            for part in parts[1:]:
                                part = part.strip().lower()
                                if part.startswith("domain="):
                                    cookie_domain = part[7:]
                                    if not cookie_domain.startswith('.'):
                                        cookie_domain = '.' + cookie_domain
                                elif part.startswith("path="):
                                    path = part[5:]
                                elif part == "secure":
                                    secure = "TRUE"
                                elif part == "httponly":
                                    httponly = True
                                elif part.startswith("expires="):
                                    try:
                                        expires = part[8:]
                                        # Convert expires to timestamp
                                        expiry = int(time.mktime(time.strptime(expires, "%a, %d-%b-%Y %H:%M:%S GMT")))
                                    except:
                                        pass
                            
                            # Format the cookie line
                            if httponly:
                                f.write(f"#HttpOnly_{cookie_domain}")
                            else:
                                f.write(cookie_domain)
                            
                            f.write(f"\tTRUE\t{path}\t{secure}\t{expiry}\t{name}\t{value}\n")
                            
                        except Exception as e:
                            print(f"Error processing cookie: {str(e)}")
                
                tk.messagebox.showinfo("Success", f"Cookies exported to {filename}")
                
            except Exception as e:
                tk.messagebox.showerror("Error", f"Failed to export cookies: {str(e)}")
            finally:
                try:
                    sock.close()
                except:
                    pass

class TelnetClient:
    def __init__(self, host, port=23, timeout=5):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket = None
        
    def connect(self):
        """Connect to Telnet server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.host, self.port))
            return True
        except Exception as e:
            print(f"Telnet connection failed: {e}")
            return False
    
    def read_until(self, expected, timeout=2):
        """Read from socket until expected string is found."""
        buffer = bytearray()
        start_time = time.time()
        while True:
            if time.time() - start_time > timeout:
                break
            try:
                data = self.socket.recv(1)
                if not data:
                    break
                buffer.extend(data)
                if expected in buffer:
                    return bytes(buffer)
            except socket.timeout:
                break
        return bytes(buffer)
    
    def write(self, data):
        """Write data to socket."""
        try:
            if isinstance(data, str):
                data = data.encode()
            self.socket.send(data)
            return True
        except Exception as e:
            print(f"Write failed: {e}")
            return False
    
    def close(self):
        """Close the connection."""
        if self.socket:
            self.socket.close()
            self.socket = None

def send_magic_packet(mac_address):
    """Send a Wake-on-LAN magic packet."""
    # Remove any delimiters from MAC address and convert to bytes
    mac_bytes = bytes.fromhex(mac_address.replace(':', '').replace('-', ''))
    
    # Create magic packet: 6 bytes of 0xFF followed by MAC address repeated 16 times
    magic_packet = b'\xff' * 6 + mac_bytes * 16
    
    # Create broadcast socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    try:
        # Send packet to broadcast address
        sock.sendto(magic_packet, ('255.255.255.255', 9))
        return True
    except Exception as e:
        print(f"Error sending Wake-on-LAN packet: {e}")
        return False
    finally:
        sock.close()

class DeviceInteractor:
    def __init__(self, target_ip, username=None, password=None):
        self.target_ip = target_ip
        self.username = username
        self.password = password
        self.console = Console()
        self.ssh_client = None
        self.telnet_client = None
        
    def connect_ssh(self):
        """Attempt to establish SSH connection."""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(
                self.target_ip,
                username=self.username,
                password=self.password,
                timeout=5
            )
            return True
        except Exception as e:
            self.console.print(f"[red]SSH connection failed: {str(e)}[/red]")
            return False
    
    def connect_telnet(self):
        """Attempt to establish Telnet connection."""
        try:
            self.telnet_client = TelnetClient(self.target_ip)
            if not self.telnet_client.connect():
                return False
            
            if self.username:
                response = self.telnet_client.read_until(b"login: ")
                self.telnet_client.write(self.username + "\n")
                
            if self.password:
                response = self.telnet_client.read_until(b"Password: ")
                self.telnet_client.write(self.password + "\n")
                
            # Wait for prompt
            response = self.telnet_client.read_until(b"$")
            return True
        except Exception as e:
            self.console.print(f"[red]Telnet connection failed: {str(e)}[/red]")
            return False
    
    def execute_command(self, command):
        """Execute command on device via SSH or Telnet."""
        if self.ssh_client:
            try:
                stdin, stdout, stderr = self.ssh_client.exec_command(command)
                return stdout.read().decode()
            except Exception as e:
                self.console.print(f"[red]SSH command execution failed: {str(e)}[/red]")
        elif self.telnet_client:
            try:
                self.telnet_client.write(command + "\n")
                response = self.telnet_client.read_until(b"$")
                return response.decode()
            except Exception as e:
                self.console.print(f"[red]Telnet command execution failed: {str(e)}[/red]")
        return None
    
    def send_tcp_packet(self, port, data):
        """Send custom TCP packet to device."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_ip, port))
            sock.send(data.encode())
            response = sock.recv(1024)
            sock.close()
            return response.decode()
        except Exception as e:
            self.console.print(f"[red]TCP packet send failed: {str(e)}[/red]")
            return None
    
    def send_udp_packet(self, port, data):
        """Send custom UDP packet to device."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(data.encode(), (self.target_ip, port))
            response, addr = sock.recvfrom(1024)
            sock.close()
            return response.decode()
        except Exception as e:
            self.console.print(f"[red]UDP packet send failed: {str(e)}[/red]")
            return None
    
    def wake_on_lan(self, mac_address):
        """Send Wake-on-LAN magic packet."""
        try:
            if send_magic_packet(mac_address):
                return True
        except Exception as e:
            self.console.print(f"[red]Wake-on-LAN failed: {str(e)}[/red]")
        return False
    
    def test_vulnerabilities(self):
        """Test for common vulnerabilities."""
        results = []
        
        # Test for open telnet with default credentials
        common_credentials = [
            ('admin', 'admin'),
            ('root', 'root'),
            ('admin', 'password'),
            ('administrator', 'password')
        ]
        
        for username, password in common_credentials:
            try:
                tn = telnetlib.Telnet(self.target_ip, timeout=2)
                tn.read_until(b"login: ", timeout=2)
                tn.write(username.encode() + b"\n")
                tn.read_until(b"Password: ", timeout=2)
                tn.write(password.encode() + b"\n")
                response = tn.read_until(b"$", timeout=2)
                if b"Login incorrect" not in response:
                    results.append(f"Vulnerable to default Telnet credentials: {username}/{password}")
                tn.close()
            except:
                pass
        
        # Test for open ports with banner grabbing
        common_ports = [21, 22, 23, 80, 443, 8080, 8443, 3389]
        for port in common_ports:
            try:
                sock = socket.socket()
                sock.settimeout(2)
                sock.connect((self.target_ip, port))
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024)
                sock.close()
                if banner:
                    results.append(f"Port {port} banner: {banner[:100]}")
            except:
                pass
        
        return results
    
    def close(self):
        """Close all connections."""
        if self.ssh_client:
            self.ssh_client.close()
        if self.telnet_client:
            self.telnet_client.close()

class NetworkScanner:
    def __init__(self):
        self.console = Console()
        self.devices = []
        self.os_type = platform.system().lower()
        self.mac_vendor_url = "https://api.macvendors.com/"
        self.packet_queue = queue.Queue()
        self.monitoring = False
        self.current_target = None
        self.gui = None
        self.device_interactor = None
        self.geolocation_api_url = "http://ip-api.com/json/"

    def display_banner(self):
        banner = """
    ███╗   ██╗███████╗████████╗      ██████╗███████╗██████╗ ████████╗ ██████╗ ██████╗ 
    ████╗  ██║██╔════╝╚══██╔══╝     ██╔════╝██╔════╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
    ██╔██╗ ██║█████╗     ██║        ██║     █████╗  ██████╔╝   ██║   ██║   ██║██████╔╝
    ██║╚██╗██║██╔══╝     ██║        ██║     ██╔══╝  ██╔═══╝    ██║   ██║   ██║██╔══██╗
    ██║ ╚████║███████╗   ██║███████╗╚██████╗███████╗██║        ██║   ╚██████╔╝██║  ██║
    ╚═╝  ╚═══╝╚══════╝   ╚═╝╚══════╝ ╚═════╝╚══════╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝
    
    [🔒] Advanced Network Reconnaissance & Security Analysis Tool
    [⚡] Version: 2.0.0 | Codename: Phantom Eye
    [🛡️] Developed by: CyberSecurity Research Team
    [⚠️] For Ethical Network Analysis and Security Assessment Only
    """
        # Create a styled panel with a neon effect
        styled_banner = Panel(
            Text(banner, style="bold blue"),
            border_style="cyan",
            title="[bold red][ SECURE ENVIRONMENT DETECTED ][/bold red]",
            subtitle="[bold yellow][ INITIALIZING SECURITY PROTOCOLS ][/bold yellow]"
        )
        self.console.print(styled_banner)
        
        # Add security check animation
        with Progress(transient=True) as progress:
            task1 = progress.add_task("[cyan]Initializing security protocols...", total=100)
            task2 = progress.add_task("[green]Verifying system integrity...", total=100)
            task3 = progress.add_task("[yellow]Establishing secure environment...", total=100)
            
            while not progress.finished:
                progress.update(task1, advance=0.9)
                progress.update(task2, advance=0.7)
                progress.update(task3, advance=0.8)
                time.sleep(0.01)
        
        self.console.print("\n[bold green]✓[/bold green] System ready for secure operations")
        self.console.print("[bold yellow]![/bold yellow] Ensure you have proper authorization before proceeding")

    def get_default_gateway(self):
        """Get the default gateway IP address."""
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][0]
        return default_gateway

    def get_network_range(self):
        """Get the network range based on default gateway."""
        gateway = self.get_default_gateway()
        return f"{gateway.rsplit('.', 1)[0]}.0/24"

    def _get_hostname(self, ip):
        """Get hostname for an IP address with advanced detection."""
        try:
            # Try getting hostname through DNS with shorter timeout
            socket.setdefaulttimeout(1)
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname and hostname != ip:
                return hostname

            # Quick port scan for device type identification
            nm = nmap.PortScanner()
            nm.scan(ip, arguments='-sn -T4 -F --version-light')
            
            # Common port-based device identification
            common_ports = {
                21: "FTP Server",
                22: "SSH Device",
                23: "Telnet Device",
                80: "Web Server",
                443: "HTTPS Server",
                445: "Windows Device",
                3389: "Remote Desktop",
                8080: "Web Server",
                53: "DNS Server",
                139: "Windows Device",
                515: "Printer",
                631: "Printer",
                9100: "Printer"
            }
            
            try:
                # Quick TCP connect scan for common ports
                for port in common_ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.1)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    if result == 0:
                        return common_ports[port]
            except:
                pass

            # Try SNMP for network devices
            try:
                nm.scan(ip, arguments='-sU -p161 -T4')
                if 'udp' in nm[ip] and 161 in nm[ip]['udp']:
                    return "Network Device"
            except:
                pass

            # Check if it's a mobile device based on MAC vendor
            vendor = self._get_vendor(get_mac_address(ip=ip))
            if vendor:
                if any(company in vendor.lower() for company in ['apple', 'samsung', 'xiaomi', 'huawei', 'oppo', 'vivo']):
                    return "Mobile Device"
                elif any(company in vendor.lower() for company in ['intel', 'amd', 'nvidia', 'realtek']):
                    return "Computer"
                elif any(company in vendor.lower() for company in ['tp-link', 'netgear', 'cisco', 'juniper', 'd-link']):
                    return "Network Device"

            return "Active Device"
        except:
            return "Active Device"

    def _get_vendor(self, mac):
        """Get vendor information from MAC address using API."""
        try:
            # Format MAC address
            mac = mac.replace(':', '').upper()[:6]
            
            # Try to get vendor from API
            response = requests.get(f"{self.mac_vendor_url}{mac}", timeout=2)
            if response.status_code == 200:
                return response.text.strip()
            
            # Fallback to local detection
            with open('/usr/share/nmap/nmap-mac-prefixes', 'r') as f:
                for line in f:
                    if line.startswith(mac):
                        return line.split(' ', 1)[1].strip()
            
            return "Unregistered Vendor"
        except:
            return "Unregistered Vendor"

    def scan_network(self):
        """Perform network scan using ARP."""
        try:
            network_range = self.get_network_range()
            self.console.print(f"[yellow]Scanning network: {network_range}...[/yellow]")

            # Create ARP request packet
            arp = ARP(pdst=network_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            # Send packet and get response with shorter timeout
            result = srp(packet, timeout=2, verbose=0)[0]
            
            # Process devices with progress indicator
            self.devices = []
            total_devices = len(result)
            
            for idx, (sent, received) in enumerate(result, 1):
                self.console.print(f"[cyan]Processing device {idx}/{total_devices}...[/cyan]")
                device = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'hostname': self._get_hostname(received.psrc),
                    'vendor': self._get_vendor(received.hwsrc),
                    'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                self.devices.append(device)

            return self.devices

        except Exception as e:
            self.console.print(f"[red]Error during network scan: {str(e)}[/red]")
            return []

    def monitor_device_traffic(self, target_ip):
        """Monitor network traffic for a specific IP address with enhanced features."""
        # First run the connection test
        self.test_connection(target_ip)
        
        # Ask user if they want to proceed with monitoring
        self.console.print("\n[yellow]Do you want to proceed with full traffic monitoring? (y/n)[/yellow]")
        choice = input().lower()
        if choice != 'y':
            return
        
        self.current_target = target_ip
        self.monitoring = True
        self.start_time = datetime.now()

        # Initialize GUI with status updates
        self.gui = NetworkMonitorGUI(target_ip)
        
        # Add initial status message to both DNS and Connection tables
        self.gui.root.after(0, self.gui.update_dns, {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "domain": "Monitoring Started",
            "type": "INFO",
            "response": f"Capturing traffic for {target_ip}"
        })
        
        self.gui.root.after(0, self.gui.update_conn, {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "protocol": "INFO",
            "destination": target_ip,
            "port": "-",
            "service": "Monitor",
            "status": "Active"
        })

        def packet_callback(pkt):
            if not self.monitoring:
                return

            if IP in pkt:
                if pkt[IP].src == target_ip or pkt[IP].dst == target_ip:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    
                    # DNS Traffic
                    if DNS in pkt and DNSQR in pkt:
                        try:
                            qname = pkt[DNSQR].qname.decode().rstrip('.')
                            qtype = pkt[DNSQR].qtype
                            
                            response = "No response"
                            if DNSRR in pkt:
                                if pkt[DNSRR].type == 1:  # A record
                                    response = pkt[DNSRR].rdata
                                elif pkt[DNSRR].type == 5:  # CNAME
                                    response = pkt[DNSRR].rdata.decode()
                            
                            self.gui.root.after(0, self.gui.update_dns, {
                                "timestamp": timestamp,
                                "domain": qname,
                                "type": "DNS-" + ("A" if qtype == 1 else "CNAME" if qtype == 5 else str(qtype)),
                                "response": str(response)
                            })
                        except Exception as e:
                            print(f"Error processing DNS: {str(e)}")

                    # TCP/UDP Traffic
                    if TCP in pkt or UDP in pkt:
                        try:
                            protocol = "TCP" if TCP in pkt else "UDP"
                            if TCP in pkt:
                                dport = pkt[TCP].dport
                                sport = pkt[TCP].sport
                                flags = pkt[TCP].flags
                                status = "ESTABLISHED"
                                if flags & 0x02:  # SYN
                                    status = "SYN"
                                elif flags & 0x01:  # FIN
                                    status = "FIN"
                                elif flags & 0x04:  # RST
                                    status = "RST"
                            else:
                                dport = pkt[UDP].dport
                                sport = pkt[UDP].sport
                                status = "DATAGRAM"

                            # Determine if it's incoming or outgoing
                            if pkt[IP].dst == target_ip:
                                port = dport
                                direction = "←"
                            else:
                                port = sport
                                direction = "→"

                            # Get service name
                            try:
                                service = socket.getservbyport(port, protocol.lower())
                            except:
                                service = "Unknown"
                                if port in [80, 8080]:
                                    service = "HTTP"
                                elif port == 443:
                                    service = "HTTPS"
                                elif port == 53:
                                    service = "DNS"

                            self.gui.root.after(0, self.gui.update_conn, {
                                "timestamp": timestamp,
                                "protocol": f"{protocol} {direction}",
                                "destination": pkt[IP].dst,
                                "port": port,
                                "service": service,
                                "status": status
                            })

                            # If HTTP(S) traffic detected, add to DNS table for visibility
                            if service in ["HTTP", "HTTPS"]:
                                if Raw in pkt:
                                    payload = bytes(pkt[Raw].load)
                                    host = None

                                    if service == "HTTP":
                                        host_match = re.search(rb"Host:\s*([^\r\n]+)", payload)
                                        if host_match:
                                            host = host_match.group(1).decode()
                                    elif service == "HTTPS" and len(payload) > 43:
                                        try:
                                            sni_match = re.search(rb"\x00\x00([^\x00]+?)\x00[\x00-\xff]{2}\x00", payload[43:])
                                            if sni_match:
                                                host = sni_match.group(1).decode()
                                        except:
                                            pass

                                    if host:
                                        self.gui.root.after(0, self.gui.update_dns, {
                                            "timestamp": timestamp,
                                            "domain": host,
                                            "type": service,
                                            "response": f"Port {port}"
                                        })

                        except Exception as e:
                            print(f"Error processing connection: {str(e)}")

        try:
            self.console.print(f"\n[yellow]Starting traffic monitoring for {target_ip}...[/yellow]")
            self.console.print("[cyan]Traffic information will appear in the GUI window.[/cyan]")
            self.console.print("[cyan]Close the GUI window to stop monitoring and return to menu.[/cyan]\n")
            
            # Get interface
            interface = self.get_interface_for_ip(target_ip)
            if not interface:
                self.console.print("[red]Error: Could not find appropriate interface[/red]")
                return

            # Start packet capture in a separate thread
            sniff_thread = threading.Thread(
                target=lambda: sniff(
                    filter=f"host {target_ip}",
                    prn=packet_callback,
                    store=0,
                    iface=interface
                )
            )
            sniff_thread.daemon = True
            sniff_thread.start()

            # Start GUI main loop
            self.gui.root.protocol("WM_DELETE_WINDOW", self.stop_monitoring)
            self.gui.root.mainloop()

            # After GUI closes, ensure we're fully stopped
            self.monitoring = False
            self.console.print("\n[yellow]Monitoring stopped. Returning to menu...[/yellow]")

        except KeyboardInterrupt:
            self.stop_monitoring()
        except Exception as e:
            self.console.print(f"[red]Error in monitoring: {str(e)}[/red]")
        finally:
            self.stop_monitoring()

    def stop_monitoring(self):
        """Stop monitoring and cleanup."""
        self.monitoring = False
        if self.gui:
            try:
                self.gui.root.quit()
                self.gui.root.destroy()
            except:
                pass
            self.gui = None

    def get_device_details(self, ip):
        """Get detailed information about a specific device."""
        nm = nmap.PortScanner()
        try:
            self.console.print(f"[yellow]Scanning {ip} for detailed information...[/yellow]")
            
            # Use faster scan options
            scan_args = '-T4 -F -sV --version-light --min-rate=1000'
            nm.scan(ip, arguments=scan_args)
            
            device_info = {
                'ip': ip,
                'mac': get_mac_address(ip=ip),
                'hostname': self._get_hostname(ip),
                'state': nm[ip].state(),
                'os_matches': [],
                'open_ports': [],
            }

            # Try quick OS detection
            try:
                os_matches = []
                if 'tcp' in nm[ip]:
                    ports = nm[ip]['tcp']
                    if 445 in ports and ports[445]['state'] == 'open':
                        os_matches.append({'name': 'Microsoft Windows', 'accuracy': '90'})
                    elif 22 in ports and ports[22]['state'] == 'open':
                        if 'ssh' in ports[22]['product'].lower():
                            if 'ubuntu' in ports[22]['product'].lower():
                                os_matches.append({'name': 'Ubuntu Linux', 'accuracy': '85'})
                            else:
                                os_matches.append({'name': 'Linux/Unix', 'accuracy': '80'})
                device_info['os_matches'] = os_matches
            except:
                pass

            # Get open ports and services
            if 'tcp' in nm[ip]:
                for port, data in nm[ip]['tcp'].items():
                    if data['state'] == 'open':
                        service_version = data.get('product', '') + ' ' + data.get('version', '')
                        service_version = service_version.strip() or 'unknown'
                        device_info['open_ports'].append({
                            'port': port,
                            'service': data['name'],
                            'version': service_version
                        })

            return device_info

        except Exception as e:
            self.console.print(f"[red]Error getting device details: {str(e)}[/red]")
            return None

    def display_devices(self):
        """Display list of discovered devices in a table."""
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", style="cyan")
        table.add_column("IP Address")
        table.add_column("MAC Address")
        table.add_column("Hostname")
        table.add_column("Vendor")
        table.add_column("Last Seen")

        for idx, device in enumerate(self.devices, 1):
            table.add_row(
                str(idx),
                device['ip'],
                device['mac'],
                device['hostname'],
                device['vendor'],
                device['last_seen']
            )

        self.console.print(table)

    def display_device_details(self, device_info):
        """Display detailed information about a device."""
        if not device_info:
            return

        self.console.print(Panel(Text("\n[bold green]Detailed Device Information[/bold green]", justify="center")))
        self.console.print(f"[cyan]IP Address:[/cyan] {device_info['ip']}")
        self.console.print(f"[cyan]MAC Address:[/cyan] {device_info['mac']}")
        self.console.print(f"[cyan]Hostname:[/cyan] {device_info['hostname']}")
        self.console.print(f"[cyan]State:[/cyan] {device_info['state']}")

        if device_info['os_matches']:
            self.console.print("\n[bold cyan]Operating System Matches:[/bold cyan]")
            os_table = Table(show_header=True, header_style="bold blue")
            os_table.add_column("OS Name")
            os_table.add_column("Accuracy")
            
            for os_match in device_info['os_matches']:
                os_table.add_row(
                    os_match.get('name', 'Unknown'),
                    f"{os_match.get('accuracy', '0')}%"
                )
            self.console.print(os_table)

        if device_info['open_ports']:
            self.console.print("\n[bold cyan]Open Ports and Services:[/bold cyan]")
            port_table = Table(show_header=True, header_style="bold blue")
            port_table.add_column("Port")
            port_table.add_column("Service")
            port_table.add_column("Version")

            for port_info in device_info['open_ports']:
                port_table.add_row(
                    str(port_info['port']),
                    port_info['service'],
                    port_info['version']
                )

            self.console.print(port_table)

    def test_connection(self, target_ip):
        """Test connection monitoring by making HTTP requests."""
        self.console.print(f"\n[yellow]Running connection test for {target_ip}...[/yellow]")
        self.console.print("[cyan]This will test if we can capture traffic from the target device.[/cyan]\n")
        
        # Debug information about permissions
        self.console.print("[yellow]Checking capture permissions...[/yellow]")
        try:
            import os
            is_root = os.geteuid() == 0
            self.console.print(f"Running as root: {is_root}")
        except Exception as e:
            self.console.print(f"[red]Error checking permissions: {str(e)}[/red]")
        
        # Get and display interface details
        iface = self.get_interface_for_ip(target_ip)
        self.console.print(f"[yellow]Using interface: {iface}[/yellow]")
        
        # Check and set interface mode
        try:
            # Try to set monitor mode
            subprocess.run(['sudo', 'iwconfig', iface, 'mode', 'monitor'], capture_output=True)
        except:
            self.console.print("[yellow]Could not set monitor mode, using promiscuous mode[/yellow]")
            try:
                subprocess.run(['sudo', 'ifconfig', iface, 'promisc'])
            except:
                self.console.print("[red]Warning: Could not set promiscuous mode[/red]")
        
        try:
            import subprocess
            ifconfig = subprocess.check_output(['ifconfig', iface]).decode()
            self.console.print(f"[cyan]Interface details:[/cyan]\n{ifconfig}")
            
            # Show interface capabilities
            ethtool = subprocess.check_output(['ethtool', iface]).decode()
            self.console.print(f"[cyan]Interface capabilities:[/cyan]\n{ethtool}")
        except Exception as e:
            self.console.print(f"[red]Error getting interface details: {str(e)}[/red]")
        
        # Create test table
        test_table = Table(
            title="Connection Test Results",
            title_style="bold white on blue",
            border_style="blue",
            box=box.DOUBLE_EDGE,
            show_header=True,
            header_style="bold white"
        )
        test_table.add_column("Test", style="cyan")
        test_table.add_column("Result", style="green")
        test_table.add_column("Details", style="yellow")
        
        def run_test():
            # Test 1: Basic packet capture
            test_table.add_row(
                "Packet Capture",
                "Running...",
                "Monitoring for any packets"
            )
            
            packet_count = 0
            test_packets = []
            
            def test_callback(pkt):
                nonlocal packet_count
                if IP in pkt:
                    if pkt[IP].src == target_ip or pkt[IP].dst == target_ip:
                        packet_count += 1
                        test_packets.append(pkt)
                        # Debug print for each packet
                        print(f"Captured packet: {pkt.summary()}")
            
            # Start packet capture for test
            try:
                self.console.print("\n[yellow]Starting packet capture...[/yellow]")
                self.console.print(f"Filter: host {target_ip}")
                self.console.print("Please generate some traffic (e.g., open a website) on the target device now...")
                
                # Use promiscuous mode and monitor mode if available
                sniff(
                    filter=f"host {target_ip}",
                    prn=test_callback,
                    store=0,
                    timeout=10,  # Increased timeout to 10 seconds
                    iface=iface,
                    monitor=True
                )
                
                if packet_count > 0:
                    test_table.add_row(
                        "Packet Capture",
                        "[green]Success[/green]",
                        f"Captured {packet_count} packets"
                    )
                else:
                    test_table.add_row(
                        "Packet Capture",
                        "[red]Failed[/red]",
                        "No packets captured"
                    )
                
                # Test 2: Protocol detection
                protocols = set()
                for pkt in test_packets:
                    if TCP in pkt:
                        protocols.add("TCP")
                        # Debug TCP ports
                        src_port = pkt[TCP].sport
                        dst_port = pkt[TCP].dport
                        print(f"TCP Ports - Src: {src_port}, Dst: {dst_port}")
                    if UDP in pkt:
                        protocols.add("UDP")
                    if DNS in pkt:
                        protocols.add("DNS")
                    if Raw in pkt:
                        payload = bytes(pkt[Raw].load)
                        if any(proto in payload for proto in [b"HTTP", b"GET", b"POST", b"Host:", b"HTTP/1"]):
                            protocols.add("HTTP")
                            print(f"HTTP Traffic detected in packet")
                
                if protocols:
                    test_table.add_row(
                        "Protocol Detection",
                        "[green]Success[/green]",
                        f"Detected: {', '.join(protocols)}"
                    )
                else:
                    test_table.add_row(
                        "Protocol Detection",
                        "[yellow]Warning[/yellow]",
                        "No protocols detected"
                    )
                
                # Display interface information
                test_table.add_row(
                    "Network Interface",
                    "[green]Info[/green]",
                    f"Using interface: {iface}"
                )
                
                # Display test results
                self.console.print(test_table)
                
                if packet_count == 0:
                    self.console.print("\n[red]No packets were captured. Possible issues:[/red]")
                    self.console.print("1. Insufficient permissions (try running with sudo)")
                    self.console.print("2. Wrong network interface")
                    self.console.print("3. Firewall blocking packet capture")
                    self.console.print("4. Target IP is not generating traffic")
                    
                    # Additional debug information
                    self.console.print("\n[yellow]Debug Information:[/yellow]")
                    try:
                        # Check if tcpdump works
                        self.console.print("\nTesting tcpdump:")
                        subprocess.run(['tcpdump', '-i', iface, '-c', '1', '-n'], timeout=5)
                    except Exception as e:
                        self.console.print(f"[red]tcpdump test failed: {str(e)}[/red]")
                        
                    # Check interface status
                    try:
                        self.console.print("\nChecking interface status:")
                        subprocess.run(['ip', 'link', 'show', iface])
                    except Exception as e:
                        self.console.print(f"[red]Interface status check failed: {str(e)}[/red]")
                else:
                    self.console.print("\n[green]Basic packet capture is working![/green]")
                    if "HTTP" not in protocols:
                        self.console.print("[yellow]Note: No HTTP traffic detected. Try opening a website on the target device.[/yellow]")
            
            except Exception as e:
                test_table.add_row(
                    "Error",
                    "[red]Failed[/red]",
                    str(e)
                )
                self.console.print(test_table)
                self.console.print(f"\n[red]Detailed error: {str(e)}[/red]")
        
        run_test()
    
    def get_interface_for_ip(self, target_ip):
        """Get the appropriate interface for capturing traffic for target IP."""
        interfaces = netifaces.interfaces()
        target_network = '.'.join(target_ip.split('.')[:3])
        
        # First try to find interface on the same network
        for iface in interfaces:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if 'addr' in addr:
                        if addr['addr'].startswith(target_network):
                            # Set interface to promiscuous mode
                            try:
                                subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'promisc', 'on'])
                                subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'up'])
                            except Exception as e:
                                print(f"Warning: Could not set promiscuous mode: {e}")
                            return iface
        
        # Fallback to first non-loopback interface
        for iface in interfaces:
            if iface != 'lo':
                # Set interface to promiscuous mode
                try:
                    subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'promisc', 'on'])
                    subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'up'])
                except Exception as e:
                    print(f"Warning: Could not set promiscuous mode: {e}")
                return iface
        
        return None

    def interact_with_device(self, target_ip):
        """Interact with a specific device."""
        self.device_interactor = DeviceInteractor(target_ip)
        
        while True:
            self.console.print("\n[bold cyan]Device Interaction Options:[/bold cyan]")
            self.console.print("1. Execute command (SSH/Telnet)")
            self.console.print("2. Send custom TCP packet")
            self.console.print("3. Send custom UDP packet")
            self.console.print("4. Wake-on-LAN")
            self.console.print("5. Test for vulnerabilities")
            self.console.print("6. Back to main menu")
            
            choice = input("\nEnter your choice (1-6): ")
            
            if choice == "1":
                username = input("Enter username (or press Enter to skip): ")
                password = input("Enter password (or press Enter to skip): ")
                if username:
                    self.device_interactor.username = username
                    self.device_interactor.password = password
                
                if self.device_interactor.connect_ssh():
                    self.console.print("[green]SSH connection established![/green]")
                elif self.device_interactor.connect_telnet():
                    self.console.print("[green]Telnet connection established![/green]")
                else:
                    continue
                
                while True:
                    command = input("\nEnter command (or 'exit' to quit): ")
                    if command.lower() == 'exit':
                        break
                    
                    result = self.device_interactor.execute_command(command)
                    if result:
                        self.console.print(f"\n[green]Command output:[/green]\n{result}")
            
            elif choice == "2":
                port = int(input("Enter target port: "))
                data = input("Enter data to send: ")
                response = self.device_interactor.send_tcp_packet(port, data)
                if response:
                    self.console.print(f"\n[green]Response received:[/green]\n{response}")
            
            elif choice == "3":
                port = int(input("Enter target port: "))
                data = input("Enter data to send: ")
                response = self.device_interactor.send_udp_packet(port, data)
                if response:
                    self.console.print(f"\n[green]Response received:[/green]\n{response}")
            
            elif choice == "4":
                mac = input("Enter device MAC address: ")
                if self.device_interactor.wake_on_lan(mac):
                    self.console.print("[green]Wake-on-LAN packet sent successfully![/green]")
            
            elif choice == "5":
                self.console.print("\n[yellow]Testing for vulnerabilities...[/yellow]")
                results = self.device_interactor.test_vulnerabilities()
                if results:
                    self.console.print("\n[red]Vulnerabilities found:[/red]")
                    for result in results:
                        self.console.print(f"[yellow]- {result}[/yellow]")
                else:
                    self.console.print("[green]No obvious vulnerabilities found.[/green]")
            
            elif choice == "6":
                if self.device_interactor:
                    self.device_interactor.close()
                break

    def get_device_location(self, ip):
        """Get geolocation information for a device."""
        try:
            # Check if it's a private/local IP address
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return {
                    "status": "success",
                    "country": "Local Network",
                    "regionName": "Internal",
                    "city": "Private Network",
                    "lat": 0,
                    "lon": 0,
                    "isp": "Local Network",
                    "org": "Private Network",
                    "as": "Private AS",
                    "timezone": time.tzname[0]
                }

            # For public IPs, try multiple geolocation APIs in sequence
            # First try ipinfo.io
            try:
                headers = {
                    'User-Agent': 'NetworkScanner/1.0',
                    'Accept': 'application/json'
                }
                response = requests.get(f"https://ipinfo.io/{ip}/json", headers=headers, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if "bogon" not in data:
                        # Split location into latitude and longitude
                        lat, lon = map(float, data.get("loc", "0,0").split(",")) if "loc" in data else (0, 0)
                        return {
                            "status": "success",
                            "country": data.get("country"),
                            "regionName": data.get("region"),
                            "city": data.get("city"),
                            "lat": lat,
                            "lon": lon,
                            "isp": data.get("org"),
                            "org": data.get("org"),
                            "as": data.get("asn", {}).get("asn", "Unknown"),
                            "timezone": data.get("timezone"),
                            "postal": data.get("postal"),
                            "hostname": data.get("hostname"),
                            "anycast": data.get("anycast", False),
                            "company": data.get("company", {}).get("name"),
                            "abuse": data.get("abuse", {}).get("email")
                        }
            except Exception as e:
                self.console.print(f"[yellow]Warning: ipinfo.io lookup failed: {str(e)}[/yellow]")

            # Fallback to ipapi.co
            try:
                response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if "error" not in data:
                        return {
                            "status": "success",
                            "country": data.get("country_name"),
                            "regionName": data.get("region"),
                            "city": data.get("city"),
                            "lat": data.get("latitude"),
                            "lon": data.get("longitude"),
                            "isp": data.get("org"),
                            "org": data.get("org"),
                            "as": data.get("asn"),
                            "timezone": data.get("timezone"),
                            "postal": data.get("postal"),
                            "currency": data.get("currency"),
                            "country_code": data.get("country_code"),
                            "calling_code": data.get("country_calling_code")
                        }
            except Exception as e:
                self.console.print(f"[yellow]Warning: ipapi.co lookup failed: {str(e)}[/yellow]")

            # Last resort: ip-api.com
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "success":
                        return data
            except Exception as e:
                self.console.print(f"[yellow]Warning: ip-api.com lookup failed: {str(e)}[/yellow]")

            return None
        except Exception as e:
            self.console.print(f"[yellow]Warning: Error getting location: {str(e)}[/yellow]")
            return None

    def display_location_info(self, ip):
        """Display detailed location information for a device."""
        location = self.get_device_location(ip)
        if location and location.get("status") == "success" and not all(v in ["Unknown", "Local Network", "Private Network", "Private AS"] for v in location.values()):
            # Create GUI window for location information
            if hasattr(self, 'gui') and self.gui:
                LocationInfoWindow(self.gui.root, location, ip)
            else:
                # Create a temporary root window if no GUI exists
                root = tk.Tk()
                root.withdraw()  # Hide the root window
                LocationInfoWindow(root, location, ip)
                root.mainloop()
        else:
            self.console.print("[red]Could not retrieve location information for this device.[/red]")
            
            # Show basic network information as fallback
            try:
                ip_obj = ipaddress.ip_address(ip)
                self.console.print(f"\n[cyan]Network Type:[/cyan] {'Private/Local' if ip_obj.is_private else 'Public'}")
                
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    self.console.print(f"[cyan]Hostname:[/cyan] {hostname}")
                except:
                    pass
                
                try:
                    ping_result = subprocess.check_output(['ping', '-c', '1', '-W', '2', ip]).decode()
                    time_match = re.search(r'time=(\d+\.?\d*)', ping_result)
                    if time_match:
                        self.console.print(f"[cyan]Response Time:[/cyan] {time_match.group(1)} ms")
                except:
                    pass
                
            except Exception as e:
                self.console.print(f"[red]Error showing network details: {str(e)}[/red]")

class LocationInfoWindow:
    def __init__(self, parent, location_data, ip):
        self.window = tk.Toplevel(parent)
        self.window.title(f"Location Information - {ip}")
        self.window.geometry("800x600")
        
        # Configure dark theme
        self.bg_color = '#2E2E2E'
        self.fg_color = '#00ff00'
        self.accent_color = '#00ffff'
        self.window.configure(bg=self.bg_color)
        
        # Create main frame
        main_frame = tk.Frame(self.window, bg=self.bg_color)
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Title
        title = tk.Label(
            main_frame,
            text="Device Location Information",
            font=('Helvetica', 16, 'bold'),
            bg=self.bg_color,
            fg=self.accent_color
        )
        title.pack(pady=(0, 20))
        
        # Create sections
        self.create_location_section(main_frame, location_data)
        self.create_network_section(main_frame, location_data, ip)
        self.create_organization_section(main_frame, location_data)
        
        # Create close button
        close_button = tk.Button(
            main_frame,
            text="Close",
            command=self.window.destroy,
            bg='#404040',
            fg=self.fg_color,
            relief=tk.FLAT,
            padx=20,
            pady=10
        )
        close_button.pack(pady=20)
        
        # Center window on screen
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f'{width}x{height}+{x}+{y}')
    
    def create_section_frame(self, parent, title):
        """Create a section frame with title."""
        frame = tk.LabelFrame(
            parent,
            text=title,
            bg=self.bg_color,
            fg=self.accent_color,
            font=('Helvetica', 12, 'bold')
        )
        frame.pack(fill='x', padx=10, pady=10)
        return frame
    
    def create_info_label(self, parent, label, value):
        """Create an info label with value."""
        if value and str(value).strip() and str(value) not in ["Unknown", "Local Network", "Private Network", "Private AS", "None", "0", "0.0"]:
            frame = tk.Frame(parent, bg=self.bg_color)
            frame.pack(fill='x', padx=10, pady=2)
            
            label = tk.Label(
                frame,
                text=f"{label}:",
                width=15,
                anchor='w',
                bg=self.bg_color,
                fg=self.accent_color
            )
            label.pack(side='left')
            
            value_label = tk.Label(
                frame,
                text=str(value),
                bg=self.bg_color,
                fg=self.fg_color
            )
            value_label.pack(side='left', fill='x', expand=True)
    
    def create_location_section(self, parent, data):
        """Create the location information section."""
        frame = self.create_section_frame(parent, "📍 Location Details")
        
        self.create_info_label(frame, "Country", data.get("country"))
        self.create_info_label(frame, "Region", data.get("regionName"))
        self.create_info_label(frame, "City", data.get("city"))
        self.create_info_label(frame, "Postal Code", data.get("postal"))
        
        # Create coordinates frame
        if data.get("lat") and data.get("lon"):
            coords_frame = tk.Frame(frame, bg=self.bg_color)
            coords_frame.pack(fill='x', padx=10, pady=5)
            
            coords_text = f"Latitude: {data.get('lat')}  Longitude: {data.get('lon')}"
            coords_label = tk.Label(
                coords_frame,
                text=coords_text,
                bg=self.bg_color,
                fg=self.fg_color
            )
            coords_label.pack(side='left')
            
            # Add "View on Map" button
            map_button = tk.Button(
                coords_frame,
                text="🗺️ View on Map",
                command=lambda: self.open_map(data.get('lat'), data.get('lon')),
                bg='#404040',
                fg=self.fg_color,
                relief=tk.FLAT
            )
            map_button.pack(side='right', padx=5)
    
    def create_network_section(self, parent, data, ip):
        """Create the network information section."""
        frame = self.create_section_frame(parent, "🌐 Network Information")
        
        # Get network type
        try:
            ip_obj = ipaddress.ip_address(ip)
            network_type = "Private/Local Network" if ip_obj.is_private else "Public Network"
            self.create_info_label(frame, "Network Type", network_type)
        except:
            pass
        
        self.create_info_label(frame, "Timezone", data.get("timezone"))
        self.create_info_label(frame, "Hostname", data.get("hostname"))
        
        # Add ping information
        try:
            ping_result = subprocess.check_output(['ping', '-c', '1', '-W', '2', ip]).decode()
            time_match = re.search(r'time=(\d+\.?\d*)', ping_result)
            if time_match:
                self.create_info_label(frame, "Response Time", f"{time_match.group(1)} ms")
        except:
            pass
    
    def create_organization_section(self, parent, data):
        """Create the organization information section."""
        frame = self.create_section_frame(parent, "🏢 Organization Details")
        
        self.create_info_label(frame, "ISP", data.get("isp"))
        self.create_info_label(frame, "Organization", data.get("org"))
        self.create_info_label(frame, "AS Number", data.get("as"))
        self.create_info_label(frame, "Company", data.get("company"))
        self.create_info_label(frame, "Abuse Contact", data.get("abuse"))
        
        if data.get("anycast"):
            self.create_info_label(frame, "Network Type", "Anycast Network")
    
    def open_map(self, lat, lon):
        """Open location in default web browser using OpenStreetMap."""
        import webbrowser
        url = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=12"
        webbrowser.open(url)

def main():
    scanner = NetworkScanner()
    scanner.display_banner()
    
    while True:
        try:
            scanner.console.print("\n[bold green]Available Options:[/bold green]")
            scanner.console.print("1. Scan network")
            scanner.console.print("2. Exit")
            
            choice = input("\nEnter your choice (1-2): ")
            
            if choice == '1':
                devices = scanner.scan_network()
                if devices:
                    scanner.display_devices()
                    
                    while True:
                        scanner.console.print("\n[bold cyan]Device Options:[/bold cyan]")
                        scanner.console.print("1. View detailed information")
                        scanner.console.print("2. Monitor device traffic")
                        scanner.console.print("3. Run connection test")
                        scanner.console.print("4. Interact with device")
                        scanner.console.print("5. View Location Information")
                        scanner.console.print("6. Back to main menu")
                        
                        device_option = input("\nEnter option (1-6): ")
                        
                        if device_option == "6":
                            break
                            
                        device_choice = input("\nEnter device number: ")
                        try:
                            device_idx = int(device_choice) - 1
                            if 0 <= device_idx < len(devices):
                                target_ip = devices[device_idx]['ip']
                                
                                if device_option == "1":
                                    device_details = scanner.get_device_details(target_ip)
                                    scanner.display_device_details(device_details)
                                elif device_option == "2":
                                    scanner.monitor_device_traffic(target_ip)
                                elif device_option == "3":
                                    scanner.test_connection(target_ip)
                                elif device_option == "4":
                                    scanner.interact_with_device(target_ip)
                                elif device_option == "5":
                                    scanner.display_location_info(target_ip)
                            else:
                                scanner.console.print("[red]Invalid device number![/red]")
                        except ValueError:
                            scanner.console.print("[red]Please enter a valid number![/red]")
                
            elif choice == '2':
                scanner.console.print("[yellow]Exiting...[/yellow]")
                break
            else:
                scanner.console.print("[red]Invalid choice! Please try again.[/red]")
                
        except KeyboardInterrupt:
            scanner.console.print("\n[yellow]Scan interrupted by user. Exiting...[/yellow]")
            break
        except Exception as e:
            scanner.console.print(f"[red]An error occurred: {str(e)}[/red]")

if __name__ == "__main__":
    main() 