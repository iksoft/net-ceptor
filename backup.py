#!/usr/bin/env python3

import sys
import platform
import subprocess
import nmap
import netifaces
import socket
from scapy.all import ARP, Ether, srp, sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR
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

class NetworkScanner:
    def __init__(self):
        self.console = Console()
        self.devices = []
        self.os_type = platform.system().lower()
        self.mac_vendor_url = "https://api.macvendors.com/"
        self.packet_queue = queue.Queue()
        self.monitoring = False
        self.current_target = None

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
        self.current_target = target_ip
        self.monitoring = True
        
        # Create tables with professional styling
        http_table = Table(
            title="Web Traffic Analysis",
            title_style="bold white on blue",
            border_style="blue",
            box=box.DOUBLE_EDGE,
            show_header=True,
            header_style="bold white"
        )
        http_table.add_column("Timestamp", style="cyan", width=12)
        http_table.add_column("Website", style="green", width=30)
        http_table.add_column("Method", style="yellow", width=8)
        http_table.add_column("Path", style="magenta", width=30)
        http_table.add_column("Status", style="red", width=8)

        dns_table = Table(
            title="DNS Activity Monitor",
            title_style="bold white on green",
            border_style="green",
            box=box.DOUBLE_EDGE,
            show_header=True,
            header_style="bold white"
        )
        dns_table.add_column("Timestamp", style="cyan", width=12)
        dns_table.add_column("Domain", style="green", width=40)
        dns_table.add_column("Query Type", style="yellow", width=10)
        dns_table.add_column("Response", style="magenta", width=20)

        conn_table = Table(
            title="Network Connections",
            title_style="bold white on yellow",
            border_style="yellow",
            box=box.DOUBLE_EDGE,
            show_header=True,
            header_style="bold white"
        )
        conn_table.add_column("Timestamp", style="cyan", width=12)
        conn_table.add_column("Destination", style="green", width=30)
        conn_table.add_column("Protocol", style="yellow", width=10)
        conn_table.add_column("Service", style="magenta", width=15)
        conn_table.add_column("Port", style="red", width=8)
        conn_table.add_column("Status", style="blue", width=10)

        def packet_callback(pkt):
            if not self.monitoring:
                return

            if IP in pkt:
                if pkt[IP].src == target_ip or pkt[IP].dst == target_ip:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    
                    # Enhanced HTTP(S) Traffic Analysis
                    if TCP in pkt and pkt[TCP].dport in [80, 443]:
                        try:
                            payload = bytes(pkt[TCP].payload)
                            if b"HTTP" in payload:
                                # Extract HTTP method, path, and status
                                http_data = payload.split(b"\r\n")[0].decode()
                                method = http_data.split()[0]
                                path = http_data.split()[1]
                                
                                # Get host from headers
                                host_match = re.search(b"Host: (.+?)\\r\\n", payload)
                                website = host_match.group(1).decode() if host_match else "Unknown"
                                
                                # Try to get status code
                                status_match = re.search(b"HTTP/\\d.\\d (\\d{3})", payload)
                                status = status_match.group(1).decode() if status_match else "---"
                                
                                self.packet_queue.put(("http", {
                                    "timestamp": timestamp,
                                    "website": website,
                                    "method": method,
                                    "path": path,
                                    "status": status
                                }))
                        except:
                            pass

                    # Enhanced DNS Analysis
                    if DNS in pkt and DNSQR in pkt:
                        try:
                            qname = pkt[DNSQR].qname.decode().rstrip('.')
                            qtype = pkt[DNSQR].qtype
                            
                            # Get DNS response if available
                            response = "No response"
                            if DNSRR in pkt:
                                if pkt[DNSRR].type == 1:  # A record
                                    response = pkt[DNSRR].rdata
                                elif pkt[DNSRR].type == 5:  # CNAME
                                    response = pkt[DNSRR].rdata.decode()
                            
                            self.packet_queue.put(("dns", {
                                "timestamp": timestamp,
                                "domain": qname,
                                "type": "A" if qtype == 1 else "CNAME" if qtype == 5 else str(qtype),
                                "response": response
                            }))
                        except:
                            pass

                    # Enhanced Connection Tracking
                    if TCP in pkt:
                        try:
                            dst_ip = pkt[IP].dst
                            dst_port = pkt[TCP].dport
                            protocol = "TCP"
                            
                            # Determine connection status
                            status = "ESTABLISHED"
                            if pkt[TCP].flags & 0x02:  # SYN
                                status = "SYN"
                            elif pkt[TCP].flags & 0x01:  # FIN
                                status = "FIN"
                            elif pkt[TCP].flags & 0x04:  # RST
                                status = "RST"
                            
                            # Get service name
                            try:
                                service = socket.getservbyport(dst_port, protocol.lower())
                            except:
                                service = "Unknown"
                            
                            self.packet_queue.put(("conn", {
                                "timestamp": timestamp,
                                "destination": dst_ip,
                                "protocol": protocol,
                                "service": service,
                                "port": dst_port,
                                "status": status
                            }))
                        except:
                            pass
                    
                    elif UDP in pkt:
                        try:
                            dst_ip = pkt[IP].dst
                            dst_port = pkt[UDP].dport
                            protocol = "UDP"
                            
                            try:
                                service = socket.getservbyport(dst_port, protocol.lower())
                            except:
                                service = "Unknown"
                            
                            self.packet_queue.put(("conn", {
                                "timestamp": timestamp,
                                "destination": dst_ip,
                                "protocol": protocol,
                                "service": service,
                                "port": dst_port,
                                "status": "DATAGRAM"
                            }))
                        except:
                            pass

        def update_display():
            console = Console()
            layout = Layout()
            
            while self.monitoring:
                try:
                    data_type, data = self.packet_queue.get(timeout=0.25)
                    
                    if data_type == "http":
                        http_table.add_row(
                            data["timestamp"],
                            data["website"],
                            data["method"],
                            data["path"][:30] + "..." if len(data["path"]) > 30 else data["path"],
                            data["status"]
                        )
                    elif data_type == "dns":
                        dns_table.add_row(
                            data["timestamp"],
                            data["domain"],
                            data["type"],
                            str(data["response"])
                        )
                    elif data_type == "conn":
                        conn_table.add_row(
                            data["timestamp"],
                            data["destination"],
                            data["protocol"],
                            data["service"],
                            str(data["port"]),
                            data["status"]
                        )

                    # Clear screen and create professional layout
                    console.clear()
                    console.print(Panel(
                        Text("Network Traffic Analysis Dashboard", style="bold white"),
                        style="on blue"
                    ))
                    console.print(f"\n[bold cyan]Target IP:[/bold cyan] {target_ip}")
                    console.print(f"[bold cyan]Monitoring Duration:[/bold cyan] {(datetime.now() - self.start_time).seconds}s")
                    
                    # Display statistics
                    stats_table = Table(show_header=False, box=box.SIMPLE)
                    stats_table.add_row(
                        "[bold]HTTP Requests[/bold]", str(len(http_table.rows)),
                        "[bold]DNS Queries[/bold]", str(len(dns_table.rows)),
                        "[bold]Active Connections[/bold]", str(len(conn_table.rows))
                    )
                    console.print(Panel(stats_table, title="Traffic Statistics", border_style="green"))
                    
                    # Display traffic tables
                    console.print(http_table)
                    console.print(dns_table)
                    console.print(conn_table)
                    
                    console.print("\n[bold red]Press Ctrl+C to stop monitoring[/bold red]")

                except queue.Empty:
                    continue
                except KeyboardInterrupt:
                    break

        try:
            self.console.print(f"\n[yellow]Starting enhanced traffic monitoring for {target_ip}...[/yellow]")
            self.console.print("[cyan]Press Ctrl+C to stop monitoring[/cyan]\n")
            
            self.start_time = datetime.now()
            
            # Start packet capture in a separate thread
            sniff_thread = threading.Thread(
                target=lambda: sniff(
                    filter=f"host {target_ip}",
                    prn=packet_callback,
                    store=0
                )
            )
            sniff_thread.daemon = True
            sniff_thread.start()

            # Start display update in main thread
            update_display()

        except KeyboardInterrupt:
            self.monitoring = False
            self.console.print("\n[yellow]Monitoring stopped.[/yellow]")
        finally:
            self.monitoring = False

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
                        scanner.console.print("3. Back to main menu")
                        
                        device_option = input("\nEnter option (1-3): ")
                        
                        if device_option == "3":
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