# Network Deception Tool

## Description
The **Network Deception Tool** is a cybersecurity application focused on offense and defense through deception. This tool lets users simulate multi-protocol network attacks and monitor network traffic with an integrated Intrusion Detection System (IDS). Built for educational purposes, it provides a unique approach to network security by deploying deception techniques to analyze attack methods and counter them effectively.

## Features
- **Multi-Protocol Attack Simulation**: Simulate attacks using protocols like TCP, UDP, and ICMP.
- **Real-Time Network Monitoring**: Continuously monitor incoming and outgoing network traffic.
- **Integrated Intrusion Detection System (IDS)**: Detects and reports suspicious activity automatically.
- **Decoy and Deception Mechanisms**: Mislead attackers and study potential attack methods.
- **User-Friendly GUI**: Manage targets, view logs, and control attack functions easily.
- **IP and Domain Name Support**: Input either IP addresses or domain names as attack targets.

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
   Click "Start Attack" to simulate an attack on the added target. The IDS will detect and log any threats.

4. **View Logs and Reports**  
   The GUI has a dedicated reporting section for logs of attacks, IDS alerts, and target management messages.

## Example Scenarios

- **Testing Network Defenses**: Simulate various attack types and observe IDS alerts for each event.
- **Deception in Action**: Deploy decoy targets and study attacker behavior in a controlled environment.

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

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Acknowledgments
Special thanks to the open-source community for tools and libraries like Scapy that made this project possible.

## Contact
For any questions or feedback, please reach out at alengeorge904@gmail.com.
