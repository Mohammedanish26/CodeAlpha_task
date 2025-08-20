from scapy.all import sniff

# Function to process each packet
def analyze_packet(packet):
    if packet.haslayer("IP"):
        ip_layer = packet["IP"]
        print(f"[+] {ip_layer.src} → {ip_layer.dst} | Protocol: {ip_layer.proto}")

        # Check for payload data
        if packet.haslayer("Raw"):
            payload = packet["Raw"].load
            print(f"    Payload: {payload}")
        print("-" * 50)

# Start sniffing
print("🔎 Starting packet sniffing... (Press Ctrl+C to stop)")
sniff(prn=analyze_packet, store=False)
