import os
import random
import socket
import threading
import logging
import time
import sys
from PyQt6 import QtWidgets, QtCore
from scapy.all import IP, ICMP, send, DNS, DNSQR

# Configure logging
logging.basicConfig(filename='network_deception.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Global variables
attack_event = threading.Event()
defense_event = threading.Event()

class DeceptionTool:
    def __init__(self):
        self.check_admin()
        self.targets = []
        self.root = None
        self.log_box = None
        self.ids_box = None
        self.target_list = None
        self.is_attacking = False  # Track attack state
        self.attack_thread = None  # Store the attack thread

    def check_admin(self):
        """Check if the script is running with admin privileges."""
        if os.geteuid() != 0:
            print("This tool requires root (admin) privileges. Please run as root.")
            sys.exit(1)
        else:
            print("Running with root privileges.")

    def log_activity(self, message, ids_alert=False):
        """Logs network activities and IDS alerts."""
        logging.info(message)  # Logging to the file
        if ids_alert:
            self.ids_box.append(f"IDS Alert: {message}")
        else:
            self.log_box.append(f"Network Log: {message}")

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

    def generate_fake_dns_query(self):
        """Generate a fake DNS query to simulate legitimate activity."""
        domains = ["google.com", "yahoo.com", "amazon.com", "twitter.com", "microsoft.com", "netflix.com", "apple.com", "wikipedia.org"]
        domain = random.choice(domains)
        return DNS(rd=1, qd=DNSQR(qname=domain))

    def simulate_browsing_activity(self):
        """Simulate realistic HTTP GET/POST requests."""
        pages = ["index.html", "login.php", "dashboard", "settings", "profile"]
        request = random.choice(pages)
        return f"GET /{request} HTTP/1.1"

    def start_attack(self):
        """Start the network attack simulation in a separate thread."""
        if self.is_attacking:
            return  # If already attacking, do nothing
        
        self.is_attacking = True
        self.log_activity("Starting attack simulation...")
        
        # Start the attack in a new thread
        self.attack_thread = threading.Thread(target=self.attack_simulation)
        self.attack_thread.daemon = True  # Ensures the thread terminates when the program ends
        self.attack_thread.start()

    def attack_simulation(self):
        """Simulate the attack."""
        while self.is_attacking:
            for target in self.targets:
                target_ip = self.resolve_to_ip(target)
                if target_ip:
                    spoofed_ip = self.generate_fake_ip()
                    self.log_activity(f"Sending traffic to {target} (IP: {target_ip}) from spoofed IP: {spoofed_ip}")
                    send(IP(dst=target_ip)/ICMP(), verbose=False)
                    time.sleep(0.1)  # Reduced sleep for faster attack (can be adjusted)

    def stop_attack(self):
        """Stop the network attack simulation."""
        if not self.is_attacking:
            return  # If no attack is running, do nothing

        self.is_attacking = False
        self.attack_thread.join()  # Wait for the attack thread to properly terminate
        self.log_activity("Attack simulation stopped.")

    def add_target(self):
        """Add a target to the list."""
        target = self.target_input.text()
        if target:
            self.targets.append(target)
            self.target_input.clear()
            self.update_target_list()
            self.log_activity(f"Added target: {target}")

    def remove_target(self):
        """Remove a selected target from the list."""
        selected_target = self.target_list.currentItem()
        if selected_target:
            target = selected_target.text()
            self.targets.remove(target)
            self.update_target_list()
            self.log_activity(f"Removed target: {target}")

    def update_target_list(self):
        """Update the displayed list of targets in the GUI."""
        self.target_list.clear()
        self.target_list.addItems(self.targets)

    def trigger_ids_alert(self):
        """Manually trigger an IDS alert."""
        self.log_activity("Manual IDS Alert: Suspicious activity detected!", ids_alert=True)

    def setup_gui(self):
        """Set up the GUI components."""
        self.root = QtWidgets.QWidget()
        self.root.setWindowTitle("Network Deception Tool")

        # Create layout
        layout = QtWidgets.QVBoxLayout()

        # Target management
        target_layout = QtWidgets.QHBoxLayout()

        self.target_input = QtWidgets.QLineEdit(self.root)
        self.target_input.setPlaceholderText("Enter target domain or IP")
        target_layout.addWidget(self.target_input)

        add_button = QtWidgets.QPushButton("Add Target", self.root)
        add_button.clicked.connect(self.add_target)
        target_layout.addWidget(add_button)

        remove_button = QtWidgets.QPushButton("Remove Target", self.root)
        remove_button.clicked.connect(self.remove_target)
        target_layout.addWidget(remove_button)

        layout.addLayout(target_layout)

        # Target list
        self.target_list = QtWidgets.QListWidget(self.root)
        layout.addWidget(self.target_list)

        # Logs
        self.log_box = QtWidgets.QTextEdit(self.root)
        self.log_box.setReadOnly(True)
        self.log_box.setPlainText("Log Section")  # Set initial text for the log box
        layout.addWidget(self.log_box)

        # IDS box
        self.ids_box = QtWidgets.QTextEdit(self.root)
        self.ids_box.setReadOnly(True)
        self.ids_box.setPlainText("IDS Section")  # Set initial text for the IDS box
        layout.addWidget(self.ids_box)

        # Set names for the target section
        self.target_list.addItem("Target Section")

        # Start/Stop attack buttons
        attack_button = QtWidgets.QPushButton("Start Attack", self.root)
        attack_button.clicked.connect(self.start_attack)
        layout.addWidget(attack_button)

        stop_button = QtWidgets.QPushButton("Stop Attack", self.root)
        stop_button.clicked.connect(self.stop_attack)
        layout.addWidget(stop_button)

        # Add a button to manually trigger IDS alerts
        alert_button = QtWidgets.QPushButton("Trigger IDS Alert", self.root)
        alert_button.clicked.connect(self.trigger_ids_alert)
        layout.addWidget(alert_button)

        # Set layout for the root widget
        self.root.setLayout(layout)
        self.root.show()

    def run(self):
        """Run the tool."""
        app = QtWidgets.QApplication([])  # Create the QApplication object
        self.setup_gui()  # Set up the GUI
        app.exec()  # Start the event loop

# Start the tool
if __name__ == "__main__":
    tool = DeceptionTool()
    tool.run()
