# 📡 Packet Sniffer
# 📖 Overview
The Packet Sniffer is a Python-based network monitoring tool that captures live traffic, filters by protocol, and flags suspicious patterns. It helps security students and professionals understand how attackers probe networks and how defenders detect anomalies. The tool also supports logging, Wireshark validation, and a real-time Flask dashboard for visualization.

# ✨ Features
Protocol Filters: Capture only TCP, UDP, or all traffic.
Suspicious Traffic Detection: Flags repeated SYN packets (possible port scans).
Logging: Save captured packets to CSV or JSON for later analysis.
Wireshark Validation: Export logs and import them into Wireshark for deeper inspection.
Flask Dashboard: Real-time web interface to visualize captured traffic.

# 🛠️ Tech Stack
Language: Python 3
Libraries: scapy, argparse, csv, json, flask

# ⚙️ Installation
Clone the repository and navigate into the project folder:
bash:
# git clone https://github.com/your-username/packet-sniffer.git
# cd packet-sniffer
Install dependencies:
bash:
# pip install scapy flask

# 🚀 Usage
- Capture all traffic
 bash:
 # sudo python packet_sniffer.py --filter all

-Capture only TCP packets and log to CSV
 bash:
 # sudo python packet_sniffer.py --filter tcp --log csv

- Capture UDP packets and show dashboard
 bash:
 # sudo python packet_sniffer.py --filter udp --dashboard

- Open your browser at:
 Code: 
 # http://localhost:5000

# 📂 Project Structure
- Code
packet-sniffer/

│── packet_sniffer.py  # Main script

│── README.md           # Documentation

│── packets_log.csv     # Example log output

│── packets_log.json    # Example log output

# 🔮 Future Enhancements
Add charts and graphs (e.g., protocol distribution, traffic volume) using Chart.js.
Integrate with SQLite for persistent storage.
Implement alerting system (e.g., email or sound notification for suspicious traffic).
Advanced filtering (HTTP, DNS, ICMP).

# ⚠️ Disclaimer
This tool is for educational and security research purposes only.
Do not use it against networks or systems without explicit permission. Unauthorized sniffing may be illegal.
