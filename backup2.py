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
from tkinter import ttk, scrolledtext
import tkinter.font as tkFont
import os
import paramiko

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

    def display_banner(self):
        banner = """
███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ 
██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗ 
██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗   
██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗  
███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝  
╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗  
███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║  
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝  
        [Network Device Discovery & Analysis Tool]
        [Author: Ethical Hacker & Security Expert]
        [Version: 1.0.0]
"""
        self.console.print(Panel(Text(banner, style="bold blue")))

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

        # Initialize GUI
        self.gui = NetworkMonitorGUI(target_ip)
        
        def packet_callback(pkt):
            if not self.monitoring:
                return

            if IP in pkt:
                if pkt[IP].src == target_ip or pkt[IP].dst == target_ip:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    
                    # Enhanced HTTP(S) Traffic Analysis
                    if TCP in pkt:
                        dst_port = pkt[TCP].dport
                        src_port = pkt[TCP].sport
                        
                        # Check for HTTP(S) traffic - expanded port list
                        if dst_port in [80, 443, 8080, 8443] or src_port in [80, 443, 8080, 8443]:
                            try:
                                is_https = dst_port == 443 or src_port == 443 or dst_port == 8443 or src_port == 8443
                                website = pkt[IP].dst if dst_port in [80, 443, 8080, 8443] else pkt[IP].src
                                
                                if Raw in pkt:
                                    payload = bytes(pkt[Raw].load)
                                    
                                    # Enhanced HTTP Request detection with browser patterns
                                    http_methods = [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT"]
                                    browser_patterns = [
                                        b"Mozilla/5.0", b"Chrome/", b"Firefox/", b"Safari/", b"Edge/",
                                        b"Accept: text/html", b"Accept: application/json"
                                    ]
                                    
                                    # Check for HTTP request with browser patterns
                                    if any(method in payload[:20] for method in http_methods) and any(pattern in payload for pattern in browser_patterns):
                                        # Extract method
                                        method = next((m.decode() for m in http_methods if m in payload[:20]), "HTTP")
                                        
                                        # Extract path with improved regex
                                        path_match = re.search(rb"(?:" + b"|".join(http_methods) + rb")\s+([^\s]+)", payload)
                                        path = path_match.group(1).decode() if path_match else "/"
                                        
                                        # Extract host with improved regex
                                        host_match = re.search(rb"Host:\s*([^\r\n]+)", payload)
                                        if host_match:
                                            website = host_match.group(1).decode().strip()
                                        
                                        # Extract additional headers for better visibility
                                        user_agent_match = re.search(rb"User-Agent:\s*([^\r\n]+)", payload)
                                        user_agent = user_agent_match.group(1).decode().strip() if user_agent_match else ""
                                        
                                        # Extract referer for better tracking
                                        referer_match = re.search(rb"Referer:\s*([^\r\n]+)", payload)
                                        referer = referer_match.group(1).decode().strip() if referer_match else ""
                                        
                                        # Build full URL
                                        scheme = "https://" if is_https else "http://"
                                        full_url = f"{scheme}{website}{path}"
                                        
                                        self.gui.root.after(0, self.gui.update_dns, {
                                            "timestamp": timestamp,
                                            "domain": website,
                                            "type": "A" if is_https else "HTTP",
                                            "response": full_url
                                        })
                                    
                                    # Enhanced HTTP Response detection
                                    elif b"HTTP/" in payload[:20]:
                                        status_match = re.search(rb"HTTP/\d\.\d\s+(\d{3})\s+([^\r\n]+)", payload)
                                        if status_match:
                                            status_code = status_match.group(1).decode()
                                            status_text = status_match.group(2).decode()
                                            
                                            # Extract content type
                                            content_type_match = re.search(rb"Content-Type:\s*([^\r\n]+)", payload)
                                            content_type = content_type_match.group(1).decode().strip() if content_type_match else "unknown"
                                            
                                            self.gui.root.after(0, self.gui.update_dns, {
                                                "timestamp": timestamp,
                                                "domain": website,
                                                "type": "HTTP",
                                                "response": f"{status_code} {status_text}"
                                            })
                                
                                # For HTTPS, improve connection logging
                                elif is_https:
                                    # Try to get SNI (Server Name Indication) for HTTPS
                                    if Raw in pkt and len(payload) > 43:
                                        try:
                                            tls_length = int.from_bytes(payload[3:5], byteorder='big')
                                            if tls_length > 40:  # Minimum size for ClientHello
                                                # Check for ClientHello message
                                                if payload[0] == 0x16:  # Handshake
                                                    sni_match = re.search(rb"\x00\x00([^\x00]+)\x00", payload[43:])
                                                    if sni_match:
                                                        website = sni_match.group(1).decode()
                                        except Exception as e:
                                            print(f"Error parsing TLS: {str(e)}")
                                    
                                    self.gui.root.after(0, self.gui.update_dns, {
                                        "timestamp": timestamp,
                                        "domain": website,
                                        "type": "HTTPS",
                                        "response": "Encrypted Connection"
                                    })
                                    
                            except Exception as e:
                                print(f"Error processing HTTP(S): {str(e)}")

                    # Enhanced DNS Analysis
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
                                "type": "A" if qtype == 1 else "CNAME" if qtype == 5 else str(qtype),
                                "response": str(response)
                            })
                        except Exception as e:
                            print(f"Error processing DNS: {str(e)}")

                    # Enhanced Connection Tracking
                    if TCP in pkt or UDP in pkt:
                        try:
                            dst_ip = pkt[IP].dst
                            protocol = "TCP" if TCP in pkt else "UDP"
                            
                            if TCP in pkt:
                                dst_port = pkt[TCP].dport
                                status = "ESTABLISHED"
                                if pkt[TCP].flags & 0x02:  # SYN
                                    status = "SYN"
                                elif pkt[TCP].flags & 0x01:  # FIN
                                    status = "FIN"
                                elif pkt[TCP].flags & 0x04:  # RST
                                    status = "RST"
                            else:
                                dst_port = pkt[UDP].dport
                                status = "DATAGRAM"
                            
                            # Get service name
                            try:
                                service = socket.getservbyport(dst_port, protocol.lower())
                            except:
                                service = "Unknown"
                                if dst_port in [80, 8080]:
                                    service = "HTTP"
                                elif dst_port == 443:
                                    service = "HTTPS"
                                elif dst_port == 53:
                                    service = "DNS"
                            
                            self.gui.root.after(0, self.gui.update_conn, {
                                "timestamp": timestamp,
                                "destination": dst_ip,
                                "protocol": protocol,
                                "service": service,
                                "port": dst_port,
                                "status": status
                            })
                        except Exception as e:
                            print(f"Error processing connection: {str(e)}")

        try:
            self.console.print(f"\n[yellow]Starting traffic monitoring for {target_ip}...[/yellow]")
            self.console.print("[cyan]A GUI window will open. Close it to stop monitoring.[/cyan]\n")
            
            # Get all available network interfaces
            interfaces = netifaces.interfaces()
            
            # Find the interface that has the target IP's network
            target_interface = None
            target_network = '.'.join(target_ip.split('.')[:3])
            
            for iface in interfaces:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        if 'addr' in addr:
                            if addr['addr'].startswith(target_network):
                                target_interface = iface
                                break
                if target_interface:
                    break
            
            if not target_interface:
                # Fallback to default interface
                for iface in interfaces:
                    if iface != 'lo':  # Skip loopback
                        target_interface = iface
                        break
            
            # Set interface to promiscuous mode
            try:
                subprocess.run(['sudo', 'ip', 'link', 'set', target_interface, 'promisc', 'on'])
            except:
                print("Warning: Could not set promiscuous mode")
            
            # Start packet capture in a separate thread
            sniff_thread = threading.Thread(
                target=lambda: sniff(
                    filter=f"host {target_ip}",
                    prn=packet_callback,
                    store=0,
                    iface=target_interface,
                    count=0
                )
            )
            sniff_thread.daemon = True
            sniff_thread.start()

            # Start GUI main loop
            self.gui.root.protocol("WM_DELETE_WINDOW", lambda: self.stop_monitoring())
            self.gui.root.mainloop()

        except KeyboardInterrupt:
            self.stop_monitoring()
        except Exception as e:
            print(f"Error in monitoring: {str(e)}")
        finally:
            self.stop_monitoring()

    def stop_monitoring(self):
        """Stop monitoring and cleanup."""
        self.monitoring = False
        if self.gui:
            self.gui.root.quit()
            self.gui.root.destroy()
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
                        scanner.console.print("5. Back to main menu")
                        
                        device_option = input("\nEnter option (1-5): ")
                        
                        if device_option == "5":
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
                                    scanner.console.print(f"\n[yellow]Starting traffic monitoring for {target_ip}...[/yellow]")
                                    scanner.console.print("[cyan]Press Ctrl+C to stop monitoring[/cyan]")
                                    scanner.monitor_device_traffic(target_ip)
                                elif device_option == "3":
                                    scanner.test_connection(target_ip)
                                elif device_option == "4":
                                    scanner.interact_with_device(target_ip)
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