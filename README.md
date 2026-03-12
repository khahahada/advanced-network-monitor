# Advanced Network Monitor

Diving into cybersecurity, I wanted a hands-on project to truly grasp networking concepts like a sponge. So I built this network monitoring tool in Python to explore, detect, and analyze real-time traffic.

## Features

• Monitors live network traffic per IP  
• Detects high packet rates (possible DDoS attacks)  
• Detects potential SYN flood attacks  
• Detects unusual DNS request volumes (DNS tunneling or abuse)  
• Detects port scanning behavior  
• Logs all alerts to `alerts.log`  
• Provides periodic traffic summaries in `traffic_summary.txt`  

## Built With / Skills Learned

- Python (asyncio, dataclasses, collections)  
- PyShark for live packet capture and analysis  
- Networking fundamentals: TCP, UDP, DNS, ICMP, SYN flood, port scanning  
- Real-time monitoring, logging, and alert management  
- Packet analysis and research with Wireshark and Scapy  
- Developing a professional, maintainable Python project  

## Run the monitor on your network interface (example: en0):
sudo python3 advanced_network_monitor.py --iface en0

##  notes
Requires administrative privileges to capture live packets. Alerts are appended to alerts.log and summaries are written to traffic_summary.txt. This project has been tested on macOS and Linux.
