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
    - **Allowed IPs**: Only packets from specific IP addresses are allowed.
    - **Allowed Ports**: Only packets to specific destination ports (e.g., SSH or HTTPS) are allowed.
    - **Blocked Ports**: Packets to blocked ports (e.g., HTTP on port 80) are dropped.
    - **IP Spoofing**: If the source IP doesn't match the allowed list, it is considered spoofed and blocked.
    - **Redirection**: HTTP traffic (port 80) is redirected to a different IP and port (e.g., 8080).

**Logging**:

All allowed and blocked packets are logged in a file named firewall_log.txt. You can check this log for details on what packets were processed.


**Modifying the Script**:
- **Change Allowed IPs**: Modify the `allowed_ips` list in the script.
- **Change Allowed Ports**: Modify the `allowed_ports` list to specify which ports are allowed.
- **Modify Logging**: Logs are stored in `firewall_log.txt`. You can change the logging settings as needed.


---

# Explanation of the Firewall Features
1. **Port Filtering**:
    -  I created a list of `allowed_ports` (SSH on port 22 and HTTPS on port 443) and a `blocked_ports` list (HTTP on port 80).
    -  If a packet arrives with a destination port that’s in the `blocked_ports` list (HTTP traffic), it is blocked (dropped).

2. **Logging**:
    -  We use Python's built-in logging module to log allowed and blocked packets into a file called firewall_log.txt. The log entries include timestamps for when the action took place.

3. **Packet Dropping or Redirection**:
    -  If a packet is from an allowed source IP and the destination port is 80 (HTTP), we simulate a packet redirection to a different port (8080) and IP (192.168.1.100). The packet is modified and sent to the new destination.
    -  For all blocked packets (like HTTP packets), the script simply ignores them, effectively dropping the packet.

4. **IP Spoofing Detection**:
    -  We added a basic IP spoofing detection mechanism. If the source IP address of a packet is not in the allowed_ips list, it is flagged as a spoofed packet and blocked.
    -  Spoofing can be a complex topic, and more advanced checks could involve matching source IPs with expected traffic patterns (e.g., validating that a response packet is from the same source as the request).

**Running the Script**:
  1. Start the script: This will begin sniffing network traffic. You'll see logs generated for allowed and blocked packets in the firewall_log.txt file.
  2. Test the script: You can test it by trying to connect to the blocked ports (e.g., port 80 for HTTP traffic) and see if they get blocked. You can also try to spoof a source IP to see if it gets detected and blocked.



Example Log Entries:
```bash
2024-11-15 22:15:00 - Blocked HTTP packet from 192.168.1.100 to 192.168.1.2 on port 80
2024-11-15 22:16:00 - Allowed packet from 192.168.1.1 to 192.168.1.2 on port 443
2024-11-15 22:17:00 - IP Spoofing detected: Source IP 192.168.1.300 is not in allowed list
```

# Contribution:
Feel free to fork this project, raise issues, or submit pull requests for improvements.
