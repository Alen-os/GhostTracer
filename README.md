
# Network Deception Tool

## Description
The **Network Deception Tool** is a cybersecurity application focused on offense and defense through deception. This tool lets users simulate multi-protocol network attacks and monitor network traffic with an integrated Intrusion Detection System (IDS). Built for educational purposes, it provides a unique approach to network security by deploying deception techniques to analyze attack methods and counter them effectively.

## Features
- **Multi-Protocol Attack Simulation**: Simulate attacks using protocols like TCP, UDP, and ICMP.
- **Real-Time Network Monitoring**: Continuously monitor incoming and outgoing network traffic.
- **Integrated Intrusion Detection System (IDS)**: Detects and reports suspicious activity automatically. 
    - **Manual IDS Triggering**: Users can manually trigger the IDS to simulate attack detection even when no actual attack is detected. This helps in testing and training the system without needing a live attack.
    - **Automatic IDS Alerts**: When an attack is detected, the IDS will automatically trigger alerts and logs for analysis.
    - **IDS Logs and Reporting**: The GUI includes a dedicated section for IDS logs, showing detailed alerts, attack events, and responses.
- **Decoy and Deception Mechanisms**: Mislead attackers and study potential attack methods. Deploy decoy targets, such as fake IPs or vulnerable systems, to distract and confuse attackers.
- **User-Friendly GUI**: Manage targets, view logs, and control attack functions easily. The tool provides a simple interface to add targets, start/stop attacks, and monitor network traffic.
- **IP and Domain Name Support**: Input either IP addresses or domain names as attack targets.
- **Customizable Attack Scenarios**: Customize the attack scenarios, including different types of attacks (e.g., DDoS, spoofing, etc.) and target behavior.
- **Real-Time Data Visualization**: View real-time graphs and charts of network traffic, attack activity, and IDS performance for better situational awareness.

## Installation

### Prerequisites
- Python 3.x
- Required libraries: `scapy`, `tkinter`
- Install Npcap in your system before using this tool

### Setup Instructions
1. **Clone the Repository**  
   ```bash
   git clone https://github.com/Alen-os/Network-Deception-Tool.git
   ```
2. **Navigate to Project Directory**  
   ```bash
   cd Network-Deception-Tool
   ```
3. **Install Dependencies**  
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Run the Tool**  
   ```bash
   python deception_tool.py
   ```

2. **Add a Target**  
   Enter an IP address or domain in the target input box and click "Add Target."

3. **Start Attack or Monitoring**  
   Click "Start Attack" to simulate an attack on the added target. The IDS will detect and log any threats. Alternatively, click the **Manual IDS Trigger** button to simulate an attack for testing IDS alerts.

4. **View Logs and Reports**  
   The GUI has a dedicated reporting section for logs of attacks, IDS alerts, and target management messages. This helps monitor and analyze each action performed by the system.

## Example Scenarios

- **Testing Network Defenses**: Simulate various attack types, such as a DoS (Denial of Service) attack, and observe IDS alerts for each event.
- **Deception in Action**: Deploy decoy targets and study attacker behavior in a controlled environment. This helps understand the tactics used by attackers and how to defend against them effectively.
- **IDS Stress Testing**: Use the **Manual IDS Trigger** button to simulate a variety of attack scenarios, testing the effectiveness of the IDS and its response time.

## Contributing
1. **Fork the repository**  
   Create a fork of the repository to add your contributions.

2. **Create a New Branch**  
   ```bash
   git checkout -b feature/YourFeature
   ```

3. **Commit Changes**  
   ```bash
   git commit -m "Add new feature"
   ```

4. **Push to Branch**  
   ```bash
   git push origin feature/YourFeature
   ```

5. **Open a Pull Request**

## Acknowledgments
Special thanks to the open-source community for tools and libraries like Scapy that made this project possible.

## Contact
For any questions or feedback, please reach out at alengeorge904@gmail.com.
```

