from scapy.all import sniff, IP, TCP, UDP
import argparse
import csv
import json
from flask import Flask, render_template_string

# Global log storage
captured_packets = []

def packet_callback(packet, filter_proto=None, log_format=None):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Protocol filter
        if filter_proto == "tcp" and not packet.haslayer(TCP):
            return
        if filter_proto == "udp" and not packet.haslayer(UDP):
            return

        packet_info = {
            "src": ip_src,
            "dst": ip_dst,
            "proto": proto
        }

        captured_packets.append(packet_info)
        print(f"[+] {ip_src} -> {ip_dst} | Protocol: {proto}")

        # Suspicious traffic example
        if TCP in packet and packet[TCP].flags == "S":
            print(f"    [!] Possible port scan detected from {ip_src}")

def save_logs(log_format="csv", filename="packets_log"):
    if log_format == "csv":
        with open(f"{filename}.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["src", "dst", "proto"])
            writer.writeheader()
            writer.writerows(captured_packets)
    elif log_format == "json":
        with open(f"{filename}.json", "w") as f:
            json.dump(captured_packets, f, indent=4)

# Flask dashboard
app = Flask(__name__)

@app.route("/")
def dashboard():
    html = """
    <h2>Packet Sniffer Dashboard</h2>
    <table border="1">
        <tr><th>Source</th><th>Destination</th><th>Protocol</th></tr>
        {% for pkt in packets %}
        <tr><td>{{pkt.src}}</td><td>{{pkt.dst}}</td><td>{{pkt.proto}}</td></tr>
        {% endfor %}
    </table>
    """
    return render_template_string(html, packets=captured_packets)

def main():
    parser = argparse.ArgumentParser(description="Advanced Packet Sniffer")
    parser.add_argument("--filter", choices=["tcp", "udp", "all"], default="all", help="Protocol filter")
    parser.add_argument("--log", choices=["csv", "json"], help="Save logs format")
    parser.add_argument("--dashboard", action="store_true", help="Enable Flask dashboard")
    args = parser.parse_args()

    print("Starting packet sniffer... Press Ctrl+C to stop.")
    sniff(prn=lambda pkt: packet_callback(pkt, args.filter, args.log), count=0)

    if args.log:
        save_logs(args.log)

    if args.dashboard:
        app.run(host="0.0.0.0", port=5000)

if __name__ == "__main__":
    main()
