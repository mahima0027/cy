import socket
  import time
  import random
  import argparse
  import os

  def simulate_exfil(dest_ip, dest_port, num_packets=5, packet_size=100):
      """
      Simulates a small data exfiltration attempt to a specified destination.
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
                  time.sleep(random.uniform(0.1, 0.5)) # Small random delay
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
      """
      with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
          s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow immediate reuse of address
          try:
              s.bind((listen_ip, listen_port))
              s.listen(1)
              print(f"[LISTENER] Started on {listen_ip}:{listen_port}. Waiting for connections...")
              conn, addr = s.accept()
              with conn:
                  print(f"[LISTENER] Connected by {addr}")
                  while True:
                      data = conn.recv(1024)
                      if not data:
                          break
                      print(f"[LISTENER] Received: {data.decode(errors='ignore')}")
              print("[LISTENER] Connection closed by client.")
          except OSError as e:
              print(f"[LISTENER ERROR] Could not bind to {listen_ip}:{listen_port}. Is the port already in use? Error: {e}")
          except Exception as e:
              print(f"[LISTENER ERROR] An unexpected error occurred: {e}")

  if __name__ == "__main__":
      parser = argparse.ArgumentParser(description="Simple network attack simulator/listener.")
      parser.add_argument('--simulate', action='store_true', help='Run as attack simulator.')
      parser.add_argument('--listen', nargs=2, help='Run as listener (IP Port). Example: --listen 127.0.0.1 31337')
      args = parser.parse_args()

      if args.listen:
          listen_ip, listen_port = args.listen[0], int(args.listen[1])
          simple_listener(listen_ip, listen_port)
      elif args.simulate:
          target_ip = "127.0.0.1" # Target is localhost for this simulation
          target_port = 31337      # Our chosen "unusual" port
          simulate_exfil(target_ip, target_port)
      else:
          print("Please specify --simulate to run the attack, or --listen <IP> <Port> to run the listener.")
          print("Example: python3 network_attack_sim.py --listen 127.0.0.1 31337")
          print("Example: python3 network_attack_sim.py --simulate")
