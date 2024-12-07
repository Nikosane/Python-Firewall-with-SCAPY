import logging
from scapy.all import sniff, IP, TCP, UDP


logging.basicConfig(
    filename="firewall.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)


RULES = {
    "block_ips": ["192.168.1.1", "10.0.0.2"],  
    "allow_ips": [],  
    "block_ports": [80, 443],  
    "block_protocols": ["TCP", "UDP"],  
}


def load_rules():
    try:
        with open("rules.config", "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("block_ips:"):
                    RULES["block_ips"] = line.split(":")[1].split(",")
                elif line.startswith("allow_ips:"):
                    RULES["allow_ips"] = line.split(":")[1].split(",")
                elif line.startswith("block_ports:"):
                    RULES["block_ports"] = list(map(int, line.split(":")[1].split(",")))
                elif line.startswith("block_protocols:"):
                    RULES["block_protocols"] = line.split(":")[1].split(",")
        print("Rules loaded successfully.")
    except FileNotFoundError:
        print("No configuration file found. Using default rules.")
    except Exception as e:
        print(f"Error loading rules: {e}")


def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet.getlayer(2).name if packet.haslayer(2) else "Unknown"

        
        if src_ip in RULES["allow_ips"]:
            print(f"Allowed: {src_ip} -> {dst_ip} [Allowed by Rule]")
            return

        if src_ip in RULES["block_ips"]:
            log_packet(packet, "Blocked (Source IP)")
            return

        
        if TCP in packet or UDP in packet:
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            if dst_port in RULES["block_ports"]:
                log_packet(packet, "Blocked (Destination Port)")
                return

        
        if protocol.upper() in RULES["block_protocols"]:
            log_packet(packet, "Blocked (Protocol)")
            return

        
        print(f"Allowed: {src_ip} -> {dst_ip} [{protocol}]")
    else:
        print("Non-IP packet detected and ignored.")


def log_packet(packet, action):
    src_ip = packet[IP].src if IP in packet else "Unknown"
    dst_ip = packet[IP].dst if IP in packet else "Unknown"
    protocol = packet.getlayer(2).name if packet.haslayer(2) else "Unknown"
    log_message = f"{action}: {src_ip} -> {dst_ip} [{protocol}]"
    print(log_message)
    logging.info(log_message)


if __name__ == "__main__":
    print("Loading rules...")
    load_rules()
    print("Starting the firewall...")
    sniff(prn=packet_callback, filter="ip", store=0)
