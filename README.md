# Python-Firewall-with-SCAPY

A firewall essentially works by filtering traffic based on certain rules, such as allowing or blocking packets based on IP address, port number, or protocol. You can achieve this using Python libraries like scapy, socket, and iptables (if you're using a Linux system) to build the firewall. Below is an overview of how you can create a basic Python firewall.
**Steps to Build a Basic Python Firewall**
1. **Use `scapy` for Packet Sniffing and Filtering**: `scapy` is a powerful Python library for packet manipulation and analysis. You can use it to intercept and analyze network packets, apply filtering rules, and decide whether to drop or allow the packet.
2. **Socket Programming for Packet Handling**: You can also use Python's `socket` library to create low-level network connections and control how packets are routed through the system.
3. **Using `iptables` (Linux)**: On a Linux system, you can combine Python with system tools like `iptables` to implement firewall rules that directly interact with the OS networking stack.

---

# Python Firewall with Packet Filtering and Logging

This project implements a simple network firewall using Python and scapy. It filters packets based on IP addresses and ports, detects IP spoofing, logs allowed and blocked packets, and can even redirect HTTP traffic to another port.

**Features**:
- Port Filtering: Block or allow traffic based on destination ports.
- Logging: Record allowed and blocked packets in a log file.
- Packet Redirection: Redirect specific traffic (e.g., HTTP on port 80) to another IP/port.
- IP Spoofing Detection: Basic detection of packets with spoofed source IP addresses.


