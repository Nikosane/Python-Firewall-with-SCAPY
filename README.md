# Python Firewall with Packet Filtering and Logging

This project implements a simple network firewall using Python and scapy. It filters packets based on IP addresses and ports, detects IP spoofing, logs allowed and blocked packets, and can even redirect HTTP traffic to another port.

**Features**:
- **Port Filtering**: Block or allow traffic based on destination ports.
- **Logging**: Record allowed and blocked packets in a log file.
- **Packet Redirection**: Redirect specific traffic (e.g., HTTP on port 80) to another IP/port.
- **IP Spoofing Detection**: Basic detection of packets with spoofed source IP addresses.


**Requirements**:
- Python 3.x
- Install scapy for network packet manipulation:
  ```bash
  pip install scapy
  ```

 **How It Works**:
- The script listens for incoming and outgoing packets on your network interface.
- It checks the packets against several filtering rules:
    - Allowed IPs: Only packets from specific IP addresses are allowed.
    - Allowed Ports: Only packets to specific destination ports (e.g., SSH or HTTPS) are allowed.
    - Blocked Ports: Packets to blocked ports (e.g., HTTP on port 80) are dropped.
    - IP Spoofing: If the source IP doesn't match the allowed list, it is considered spoofed and blocked.
    - Redirection: HTTP traffic (port 80) is redirected to a different IP and port (e.g., 8080).

**Logging**:

All allowed and blocked packets are logged in a file named firewall_log.txt. You can check this log for details on what packets were processed.


**Modifying the Script**:
- Change Allowed IPs: Modify the `allowed_ips` list in the script.
- Change Allowed Ports: Modify the `allowed_ports` list to specify which ports are allowed.
- Modify Logging: Logs are stored in `firewall_log.txt`. You can change the logging settings as needed.


---

# Explanation of the Firewall Features
1. **Port Filtering**:
    -  I created a list of `allowed_ports` (SSH on port 22 and HTTPS on port 443) and a `blocked_ports` list (HTTP on port 80).
    -  If a packet arrives with a destination port that’s in the `blocked_ports` list (HTTP traffic), it is blocked (dropped).

2. **Logging**:
    -  We use Python's built-in logging module to log allowed and blocked packets into a file called firewall_log.txt. The log entries include timestamps for when the action took place.
