
# GhostTracer

## Description
**GhostTracer** is a cybersecurity tool designed to provide offense and defense through deception techniques. This advanced application enables users to simulate multi-protocol network attacks, monitor network traffic in real-time, and leverage an integrated Intrusion Detection System (IDS). The tool is ideal for educational purposes, helping users analyze attack methods, improve defensive strategies, and test network security through innovative deception mechanisms.

## Features
- **Multi-Protocol Attack Simulation**: Simulate attacks using protocols like TCP, UDP, and ICMP.
- **Real-Time Network Monitoring**: Monitor all incoming and outgoing network traffic dynamically.
- **Integrated Intrusion Detection System (IDS)**:
  - **Automatic IDS Alerts**: Automatically detects and reports suspicious activities, logging detailed alerts.
  - **Manual IDS Triggering**: Simulate detection events without actual attacks to test and train the system.
  - **Detailed Logs and Reporting**: A dedicated reporting section for IDS logs, including alerts, attack events, and automated responses.
- **Decoy and Deception Mechanisms**: Deploy decoy targets like fake IPs or vulnerable systems to mislead attackers and collect intelligence on their behavior.
- **Customizable Attack Scenarios**: Configure attack parameters such as types (e.g., DDoS, spoofing) and target characteristics.
- **Real-Time Data Visualization**: Graphs and charts for monitoring traffic, attack activity, and IDS performance.
- **IP and Domain Name Support**: Add IP addresses or domain names as targets.
- **User-Friendly GUI**: Intuitive interface for managing targets, viewing logs, and controlling attack simulations.

## Installation

### Prerequisites
- Python 3.x
- Required libraries: `scapy`, `tkinter`
- Ensure **Npcap** is installed on your system.

### Setup Instructions
1. **Clone the Repository**  
   ```bash
   git clone https://github.com/Alen-os/GhostTracer.git
   ```
2. **Navigate to Project Directory**  
   ```bash
   cd GhostTracer
   ```
3. **Install Dependencies**  
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Run GhostTracer**  
   ```bash
   python ghost_tracer.py
   ```

2. **Add a Target**  
   Enter an IP address or domain in the target input box and click **"Add Target"**.

3. **Simulate Attacks**  
   Select an attack type and click **"Start Attack"**. Use the IDS to detect and log suspicious activities. 

4. **Use Manual IDS Trigger**  
   Click **"Trigger IDS"** to test IDS responses without requiring an active attack.

5. **Analyze Logs and Reports**  
   Use the reporting section in the GUI to analyze detailed logs of IDS alerts, attack events, and system activities.

## Example Scenarios

- **Network Security Training**: Test your network defenses by simulating attacks like DoS and spoofing while monitoring the IDS alerts.
- **Deception Mechanisms in Action**: Deploy decoy systems to distract attackers and gather valuable information about their methods.
- **System Stress Testing**: Use manual IDS triggers to test the tool’s response under varying conditions.

## Contributing
We welcome contributions!  
1. **Fork the Repository**  
   Create a fork to work on your feature.

2. **Create a New Branch**  
   ```bash
   git checkout -b feature/YourFeature
   ```

3. **Commit Changes**  
   ```bash
   git commit -m "Add new feature"
   ```

4. **Push Changes**  
   ```bash
   git push origin feature/YourFeature
   ```

5. **Submit a Pull Request**

## Acknowledgments
Special thanks to the cybersecurity and open-source communities for providing tools and inspiration to create **GhostTracer**.

## Contact
For questions, suggestions, or feedback, reach out via email: **alengeorge904@gmail.com**.

