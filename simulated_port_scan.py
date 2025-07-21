import pandas as pd
from scapy.all import rdpcap, TCP, IP
import time
import numpy as np
import os

# --- Configuration ---
# Make sure this matches the name of the PCAP file you saved from Wireshark/tcpdump
PCAP_FILE_PATH = "simulated_port_scan.pcapng" # Or .pcap if you used tcpdump
OUTPUT_CSV_PATH = "simulated_port_scan_features.csv"
SCANNER_IP = "127.0.0.1" # The source IP of your simulated scanner (usually localhost for simulation)

# --- Feature Extraction Function for Port Scan ---
def extract_port_scan_features(pcap_file, scanner_ip):
    """
    Extracts features characteristic of a port scan from a PCAP file.
    Focuses on the activity of the specified scanner IP.
    """
    print(f"[*] Loading PCAP file: {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"Error: PCAP file '{pcap_file}' not found. Please ensure it exists.")
        return pd.DataFrame()
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        return pd.DataFrame()

    print(f"[*] Analyzing {len(packets)} packets for port scan characteristics...")

    if not packets:
        print("No packets found in the PCAP file.")
        return pd.DataFrame()

    # Initialize scan metrics
    unique_dest_ports = set()
    total_syn_packets = 0
    total_packets_from_scanner = 0
    start_time = float('inf')
    end_time = 0

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            # Check if the packet is from the scanner IP
            if pkt[IP].src == scanner_ip:
                total_packets_from_scanner += 1
                unique_dest_ports.add(pkt[TCP].dport)
                
                # Check for SYN flag (connection attempt)
                if pkt[TCP].flags & 0x02: # SYN flag is 0x02
                    total_syn_packets += 1
                
                # Update scan duration
                if pkt.time < start_time:
                    start_time = pkt.time
                if pkt.time > end_time:
                    end_time = pkt.time

    scan_duration = end_time - start_time if end_time > start_time else 0

    # Create a single row DataFrame for the port scan summary
    if total_packets_from_scanner == 0:
        print(f"No traffic observed from scanner IP {scanner_ip}.")
        return pd.DataFrame()

    # Create a dictionary for the extracted features
    # We'll also add dummy/placeholder values for columns that are in the Kaggle dataset
    # but cannot be directly derived from a simple port scan PCAP.
    # This helps in aligning the schema for concatenation later.
    features = {
        'Time': pd.to_datetime('now').strftime('%Y-%m-%d %H:%M:%S'),
        'Protocol': 'TCP', # Port scans typically use TCP
        'Flag': 'SYN', # Dominant flag in a port scan
        'Family': 'Port Scan', # New attack family
        'Clusters': 99, # A distinct cluster ID for anomalies
        'SeddAddress': scanner_ip, # Source IP of the scanner
        'ExpAddress': '127.0.0.1', # Target IP (localhost)
        'BTC': 0.0, # Dummy
        'USD': 0.0, # Dummy
        'Netflow Bytes': total_packets_from_scanner * 60, # Approximation: avg packet size * total packets
        'IP Address': scanner_ip, # Scanner IP
        'Threat Level': 'Zero-Day Attack', # Classify as a zero-day for detection
        'Port': 0, # Placeholder, as many ports are scanned (will be excluded later)
        'Prediction': 'Attack Detected',
        'Payload Size': 0, # Typically no payload in scan attempts
        'Number of Packets': total_packets_from_scanner,
        'Application Layer Data': 'Scan_Attempt',
        'User-Agent': 'N/A_Scanner',
        'Geolocation': 'Localhost',
        'Logistics ID': 'SCAN001',
        'Anomaly Score': 0.95, # High anomaly score
        'Event Description': 'Port Scan Activity',
        'Response Time': scan_duration / total_packets_from_scanner if total_packets_from_scanner > 0 else 0.0,
        'Session ID': 'SCAN_SESS_001',
        'Data Transfer Rate': 0.0, # No significant data transfer
        'Error Code': 0, # No explicit error code from scan itself
        'SourcePort': 0, # Many source ports used by scanner, or ephemeral
        'DestPort': 0, # Many destination ports scanned
        
        # Specific Port Scan Metrics (These are the key features for a port scan)
        'Unique_Dest_Ports_Scanned': len(unique_dest_ports),
        'Total_SYN_Packets': total_syn_packets,
        'Scan_Duration_Seconds': scan_duration,
        
        'Label': 'Simulated_PortScan' # Custom label for this specific anomaly
    }

    # Ensure numerical types are correct
    for key in ['BTC', 'USD', 'Netflow Bytes', 'Payload Size', 'Number of Packets',
                'Response Time', 'Data Transfer Rate', 'Clusters', 'Anomaly Score', 'Error Code',
                'Unique_Dest_Ports_Scanned', 'Total_SYN_Packets', 'Scan_Duration_Seconds',
                'SourcePort', 'DestPort', 'Port']:
        if key in features:
            features[key] = pd.to_numeric(features[key], errors='coerce')

    return pd.DataFrame([features])

# --- Main Execution ---
if __name__ == "__main__":
    print("Starting feature extraction for simulated port scan data...")
    
    # Ensure the PCAP file exists before proceeding
    if not os.path.exists(PCAP_FILE_PATH):
        print(f"Error: PCAP file '{PCAP_FILE_PATH}' not found. Please ensure it's in the same directory as this script.")
        exit()

    simulated_port_scan_df = extract_port_scan_features(PCAP_FILE_PATH, SCANNER_IP)

    if not simulated_port_scan_df.empty:
        # Define the exact column order expected by your Autoencoder script based on Kaggle dataset
        # This list should be a superset of Kaggle's features and your new port scan features.
        # YOU SHOULD VERIFY AND ADJUST THIS LIST BASED ON THE ACTUAL COLUMNS IN YOUR KAGGLE CSV
        # AND THE FEATURES YOU INTEND TO USE IN YOUR AUTOENCODER.
        
        # This list should contain ALL columns that might appear in your combined dataset
        # (Kaggle features + simulated exfil features + simulated port scan features)
        expected_combined_cols = [
            'Time', 'Protocol', 'Flag', 'Family', 'Clusters', 'SeddAddress', 'ExpAddress',
            'BTC', 'USD', 'Netflow Bytes', 'IP Address', 'Threat Level', 'Port', 'Prediction',
            'Payload Size', 'Number of Packets', 'Application Layer Data', 'User-Agent',
            'Geolocation', 'Logistics ID', 'Anomaly Score', 'Event Description',
            'Response Time', 'Session ID', 'Data Transfer Rate', 'Error Code',
            'SourcePort', 'DestPort',
            'Unique_Dest_Ports_Scanned', 'Total_SYN_Packets', 'Scan_Duration_Seconds', # New port scan features
            'Label'
        ]
        
        # Create a new DataFrame with all expected columns and fill with NaNs/defaults
        final_simulated_port_scan_df = pd.DataFrame(columns=expected_combined_cols)
        
        # Populate the new DataFrame with extracted data and dummy values
        for col in final_simulated_port_scan_df.columns:
            if col in simulated_port_scan_df.columns:
                final_simulated_port_scan_df[col] = simulated_port_scan_df[col]
            else:
                # Assign default values for columns not directly generated by this simulation
                # Ensure types match.
                if col == 'Time': final_simulated_port_scan_df[col] = pd.to_datetime('now').strftime('%Y-%m-%d %H:%M:%S')
                elif col in ['BTC', 'USD', 'Netflow Bytes', 'Payload Size', 'Number of Packets',
                            'Response Time', 'Data Transfer Rate', 'Clusters', 'Anomaly Score', 'Error Code',
                            'SourcePort', 'DestPort', 'Port', 'Unique_Dest_Ports_Scanned', 'Total_SYN_Packets', 'Scan_Duration_Seconds']:
                    final_simulated_port_scan_df[col] = 0.0 # Numerical default
                elif col == 'Threat Level': final_simulated_port_scan_df[col] = 'Zero-Day Attack'
                elif col == 'Prediction': final_simulated_port_scan_df[col] = 'Attack Detected'
                elif col == 'Event Description': final_simulated_port_scan_df[col] = 'Port Scan Activity'
                elif col == 'Label': final_simulated_port_scan_df[col] = 'Simulated_PortScan'
                elif col == 'Family': final_simulated_port_scan_df[col] = 'Port Scan'
                elif col == 'SeddAddress': final_simulated_port_scan_df[col] = SCANNER_IP
                elif col == 'ExpAddress': final_simulated_port_scan_df[col] = '127.0.0.1'
                elif col == 'IP Address': final_simulated_port_scan_df[col] = SCANNER_IP
                elif col == 'Geolocation': final_simulated_port_scan_df[col] = 'Localhost'
                elif col == 'User-Agent': final_simulated_port_scan_df[col] = 'N/A_Scanner'
                elif col == 'Application Layer Data': final_simulated_port_scan_df[col] = 'Scan_Attempt'
                else: final_simulated_port_scan_df[col] = 'N/A_Default' # Generic string default

        # Ensure 'Label' column is always present and correct
        final_simulated_port_scan_df['Label'] = 'Simulated_PortScan'

        # Ensure numerical columns are correctly typed
        numerical_cols_to_convert = [
            'BTC', 'USD', 'Netflow Bytes', 'Payload Size', 'Number of Packets',
            'Response Time', 'Data Transfer Rate', 'Clusters', 'Error Code', 'Anomaly Score',
            'SourcePort', 'DestPort', 'Port',
            'Unique_Dest_Ports_Scanned', 'Total_SYN_Packets', 'Scan_Duration_Seconds'
        ]
        for col in numerical_cols_to_convert:
            if col in final_simulated_port_scan_df.columns:
                final_simulated_port_scan_df[col] = pd.to_numeric(final_simulated_port_scan_df[col], errors='coerce').fillna(0)


        print("\n--- Final Extracted Features for Simulated Port Scan (First 5 Rows) ---")
        print(final_simulated_port_scan_df.head())
        print(f"\nShape of final extracted simulated port scan features: {final_simulated_port_scan_df.shape}")

        # Save to CSV
        final_simulated_port_scan_df.to_csv(OUTPUT_CSV_PATH, index=False)
        print(f"\nFeatures saved to: {OUTPUT_CSV_PATH}")
    else:
        print("No features extracted for port scan. Check PCAP file and scanner IP.")
```
