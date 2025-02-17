#!/usr/bin/env python3

import sys
from scapy.all import sniff, IP, TCP, Raw, ICMP, sr1, UDP, Dot11, rdpcap, Ether
import re
from datetime import datetime
import threading
import netifaces
import subprocess
from rich.console import Console
from rich.table import Table
from rich import print as rprint
import socket
import time

class WebTrafficMonitor:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.monitoring = False
        self.console = Console()
        self.packet_count = 0
        self.error_count = 0
        
    def get_interface_for_ip(self):
        """Get the appropriate interface for capturing traffic."""
        try:
            interfaces = netifaces.interfaces()
            target_network = '.'.join(self.target_ip.split('.')[:3])
            
            # Show all interfaces for debugging
            rprint("\n[cyan]Available Network Interfaces:[/cyan]")
            for iface in interfaces:
                try:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            rprint(f"Interface: {iface}, IP: {addr.get('addr', 'No IP')}")
                except Exception as e:
                    rprint(f"[yellow]Error getting info for {iface}: {e}[/yellow]")
            
            # First try to find interface on the same network
            for iface in interfaces:
                try:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            if 'addr' in addr:
                                if addr['addr'].startswith(target_network):
                                    rprint(f"[green]Found matching interface: {iface}[/green]")
                                    return iface
                except Exception as e:
                    rprint(f"[yellow]Error checking {iface}: {e}[/yellow]")
            
            # Fallback to first wireless interface
            for iface in interfaces:
                if 'wlan' in iface or 'wifi' in iface:
                    rprint(f"[yellow]Using wireless interface: {iface}[/yellow]")
                    return iface
            
            # Last resort: first non-loopback interface
            for iface in interfaces:
                if iface != 'lo':
                    rprint(f"[yellow]Using fallback interface: {iface}[/yellow]")
                    return iface
            
            return None
        except Exception as e:
            rprint(f"[red]Error in get_interface_for_ip: {e}[/red]")
            return None

    def packet_callback(self, pkt):
        """Enhanced packet callback with website information extraction."""
        try:
            if self.error_count > 100:  # Reset if too many errors
                rprint("[red]Too many errors, resetting capture...[/red]")
                self.monitoring = False
                return
            
            if IP in pkt:
                # Only process packets related to our target
                if pkt[IP].src == self.target_ip or pkt[IP].dst == self.target_ip:
                    if TCP in pkt:
                        # HTTP(S) ports
                        dst_port = pkt[TCP].dport
                        src_port = pkt[TCP].sport
                        
                        # Format timestamp
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        
                        # Check for HTTP(S) traffic
                        if dst_port in [80, 443, 8080] or src_port in [80, 443, 8080]:
                            website = pkt[IP].dst if dst_port in [80, 443, 8080] else pkt[IP].src
                            
                            if Raw in pkt:
                                payload = bytes(pkt[Raw].load)
                                
                                # HTTP Request
                                if any(method in payload[:20] for method in [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD"]):
                                    # Extract host
                                    host_match = re.search(rb"Host:\s*([^\r\n]+)", payload)
                                    if host_match:
                                        host = host_match.group(1).decode()
                                        # Extract path
                                        path_match = re.search(rb"(?:GET|POST|PUT|DELETE|HEAD)\s+([^\s]+)", payload)
                                        path = path_match.group(1).decode() if path_match else "/"
                                        
                                        # Print website access info
                                        rprint(f"\n[cyan]{timestamp}[/cyan] [green]Website Access:[/green]")
                                        rprint(f"[yellow]Host:[/yellow] {host}")
                                        rprint(f"[yellow]Path:[/yellow] {path}")
                                        
                                        # Extract user agent for browser info
                                        ua_match = re.search(rb"User-Agent:\s*([^\r\n]+)", payload)
                                        if ua_match:
                                            ua = ua_match.group(1).decode()
                                            rprint(f"[yellow]Browser:[/yellow] {ua}")
                                
                                # HTTPS - Try to get SNI
                                elif dst_port == 443 or src_port == 443:
                                    if len(payload) > 43 and payload[0] == 0x16:  # TLS Handshake
                                        try:
                                            # Extract SNI from Client Hello
                                            sni_pattern = rb"\x00\x00([^\x00]+?)\x00[\x00-\xff]{2}\x00"
                                            sni_matches = re.finditer(sni_pattern, payload[43:])
                                            for match in sni_matches:
                                                try:
                                                    website = match.group(1).decode()
                                                    rprint(f"\n[cyan]{timestamp}[/cyan] [green]HTTPS Connection:[/green]")
                                                    rprint(f"[yellow]Website:[/yellow] {website}")
                                                    break
                                                except:
                                                    continue
                                        except Exception as e:
                                            pass
                            
                            # For HTTPS without payload (probably encrypted data)
                            elif dst_port == 443 or src_port == 443:
                                rprint(f"\n[cyan]{timestamp}[/cyan] [blue]Encrypted HTTPS Traffic:[/blue] {website}")
                
        except Exception as e:
            self.error_count += 1
            rprint(f"[red]Error in packet callback ({self.error_count}/100): {e}[/red]")

    def start_monitoring(self):
        self.monitoring = True
        self.error_count = 0
        
        # Get interface
        interface = self.get_interface_for_ip()
        if not interface:
            rprint("[red]Error: Could not find appropriate interface[/red]")
            return
        
        rprint(f"\n[yellow]Using interface: {interface}[/yellow]")
        
        # Enhanced interface setup
        try:
            # Try to bring interface down first
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], capture_output=True)
            time.sleep(1)  # Wait for interface to settle
            
            # Set promiscuous mode
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'promisc', 'on'], capture_output=True)
            
            # Try to set managed mode first
            subprocess.run(['sudo', 'iwconfig', interface, 'mode', 'managed'], capture_output=True)
            time.sleep(1)  # Wait for interface to settle
            
            # Bring interface back up
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], capture_output=True)
            time.sleep(1)  # Wait for interface to settle
            
            rprint("[green]Successfully configured interface[/green]")
            
            # Show interface status
            ifconfig = subprocess.check_output(['ifconfig', interface]).decode()
            rprint(f"\n[cyan]Interface Status:[/cyan]\n{ifconfig}")
            
            try:
                iwconfig = subprocess.check_output(['iwconfig', interface]).decode()
                rprint(f"\n[cyan]Wireless Status:[/cyan]\n{iwconfig}")
            except:
                pass
            
        except Exception as e:
            rprint(f"[red]Error setting up interface: {e}[/red]")
            return
        
        rprint("\n[green]Starting packet capture...[/green]")
        rprint("[cyan]Press Ctrl+C to stop...[/cyan]\n")
        
        try:
            # Start packet capture with enhanced settings and BPF filter
            sniff(
                iface=interface,
                prn=self.packet_callback,
                store=0,
                filter="ip or ip6"  # Only capture IP packets
            )
        except KeyboardInterrupt:
            rprint("\n[yellow]Stopping capture...[/yellow]")
        except Exception as e:
            rprint(f"[red]Error during capture: {e}[/red]")
        finally:
            self.monitoring = False
            try:
                # Reset interface more gently
                subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], capture_output=True)
                time.sleep(1)
                subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'promisc', 'off'], capture_output=True)
                subprocess.run(['sudo', 'iwconfig', interface, 'mode', 'managed'], capture_output=True)
                time.sleep(1)
                subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], capture_output=True)
            except:
                pass

def main():
    if len(sys.argv) != 2:
        rprint("[red]Usage: sudo python3 demo.py <target_ip>[/red]")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    monitor = WebTrafficMonitor(target_ip)
    monitor.start_monitoring()

if __name__ == "__main__":
    main() 