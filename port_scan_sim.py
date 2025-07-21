import socket
import threading
import time
import argparse

# --- Configuration for the Port Scanner ---
TARGET_IP = "127.0.0.1" # Target is localhost for simulation
START_PORT = 1          # Start scanning from this port
END_PORT = 1024         # End scanning at this port (common ports)
NUM_THREADS = 10        # Number of concurrent threads for faster scanning
TIMEOUT = 0.5           # Socket timeout in seconds for connection attempts

def scan_port(ip, port, results):
    """Attempts to connect to a single port."""
    try:
        # Create a TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT) # Set a timeout for the connection attempt
        
        # Attempt to connect
        result = s.connect_ex((ip, port)) # connect_ex returns an error indicator
        
        if result == 0: # 0 means success (port is open)
            results.append(f"[SCANNER] Port {port} is OPEN")
        else:
            # For a scan, we're interested in all attempts, even if closed/filtered
            results.append(f"[SCANNER] Port {port} is CLOSED/FILTERED (Error: {result})")
        s.close()
    except socket.gaierror:
        results.append(f"[SCANNER ERROR] Hostname could not be resolved.")
    except socket.error as e:
        results.append(f"[SCANNER ERROR] Could not connect to port {port}: {e}")
    except Exception as e:
        results.append(f"[SCANNER ERROR] An unexpected error occurred on port {port}: {e}")

def run_port_scan(target_ip, start_port, end_port, num_threads):
    """Orchestrates the multi-threaded port scan."""
    print(f"[SCANNER] Starting port scan on {target_ip} from port {start_port} to {end_port}...")
    
    open_ports = []
    threads = []
    
    # Use a lock to safely append results from multiple threads
    results_lock = threading.Lock()
    all_scan_results = []

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(target_ip, port, all_scan_results))
        threads.append(thread)
        thread.start()
        
        # Limit active threads to avoid overwhelming the system
        while threading.active_count() > num_threads:
            time.sleep(0.01) # Small delay

    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    print(f"[SCANNER] Port scan complete on {target_ip}.")
    for res in all_scan_results:
        print(res) # Print all results for verification

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple multi-threaded port scanner.")
    parser.add_argument('--scan', action='store_true', help='Run the port scan simulation.')
    parser.add_argument('--target', type=str, default=TARGET_IP, help=f'Target IP address (default: {TARGET_IP})')
    parser.add_argument('--start_port', type=int, default=START_PORT, help=f'Starting port (default: {START_PORT})')
    parser.add_argument('--end_port', type=int, default=END_PORT, help=f'Ending port (default: {END_PORT})')
    parser.add_argument('--threads', type=int, default=NUM_THREADS, help=f'Number of threads (default: {NUM_THREADS})')
    
    args = parser.parse_args()

    if args.scan:
        run_port_scan(args.target, args.start_port, args.end_port, args.threads)
    else:
        print("Please specify --scan to run the port scan simulation.")
        print("Example: python3 port_scan_sim.py --scan")
        print("Example: python3 port_scan_sim.py --scan --target 192.168.1.1 --start_port 1 --end_port 100")
