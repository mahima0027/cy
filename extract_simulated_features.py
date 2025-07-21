import pandas as pd
from scapy.all import rdpcap, TCP, UDP, IP
import time
import numpy as np
import os # Import os module for path handling

# --- Configuration ---
# Make sure this matches the name of the file you saved from Wireshark
PCAP_FILE_PATH = "simulated_anomalous_traffic.pcapng" # Default name from Wireshark save
OUTPUT_CSV_PATH = "simulated_anomalies_features.csv"
SIMULATED_ATTACK_DEST_PORT = 31337 # The port used in network_attack_sim.py

# --- Feature Extraction Function ---
def extract_features_from_pcap(pcap_file, attack_dest_port):
    """
    Extracts simplified network flow features from a PCAP file,
    focusing on traffic related to the simulated attack.
    """
    print(f"[*] Loading PCAP file: {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"Error: PCAP file '{pcap_file}' not found. Please ensure it exists.")
        return pd.DataFrame() # Return empty DataFrame
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        return pd.DataFrame()

    print(f"[*] Analyzing {len(packets)} packets...")

    flows_data = []
    current_flow = {}
    flow_id_counter = 0

    # Simple flow tracking for the specific simulation
    # This aggregates all packets to the attack_dest_port into one "flow"
    # For robust, general flow analysis, use dedicated tools like Zeek.

    for i, pkt in enumerate(packets):
        if IP in pkt and (TCP in pkt or UDP in pkt):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            protocol = pkt[IP].proto # 6 for TCP, 17 for UDP

            src_port = None
            dst_port = None
            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                protocol_name = 'TCP'
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                protocol_name = 'UDP'
            else:
                continue # Skip non-TCP/UDP IP packets

            # Focus only on the simulated attack traffic based on destination port
            if dst_port == attack_dest_port and dst_ip == '127.0.0.1':
                # This is a packet from our simulated attack flow
                
                # Initialize flow if it's the first packet for this "flow"
                if not current_flow:
                    flow_id_counter += 1
                    current_flow = {
                        'FlowID': flow_id_counter,
                        'Start_Time': pkt.time,
                        'End_Time': pkt.time,
                        'Protocol': protocol_name,
                        'SourcePort': src_port,
                        'DestPort': dst_port,
                        'PacketsIn': 0,
                        'PacketsOut': 0,
                        'BytesIn': 0,
                        'BytesOut': 0,
                        'Payload Size': 0, # Sum of payload sizes for this flow
                        'Number of Packets': 0, # Total packets in this flow
                        'Label': 'Simulated_ZeroDay' # Custom label for your simulated data
                    }
                
                # Update flow details
                current_flow['End_Time'] = pkt.time
                current_flow['Number of Packets'] += 1
                
                # Approximate BytesIn/BytesOut based on direction relative to target
                # Assuming attacker is source (client) and listener is destination (server)
                packet_len = len(pkt) # Total packet length
                if src_ip == '127.0.0.1' and src_port != attack_dest_port: # Outbound from attacker
                    current_flow['BytesOut'] += packet_len
                elif dst_ip == '127.0.0.1' and dst_port == attack_dest_port: # Inbound to listener
                    current_flow['BytesIn'] += packet_len
                
                # Payload Size (for the flow, sum of packet lengths)
                current_flow['Payload Size'] += len(pkt.payload) if pkt.haslayer(TCP) or pkt.haslayer(UDP) else 0

    # After iterating through all packets, finalize the flow
    if current_flow:
        flow_duration = current_flow['End_Time'] - current_flow['Start_Time']
        current_flow['FlowDuration'] = flow_duration
        
        # Add dummy/approximated features to match Kaggle dataset's expected columns
        # These are placeholders and may not be derived accurately from simple PCAP
        current_flow['BTC'] = 0.0 # Dummy value
        current_flow['USD'] = 0.0 # Dummy value
        current_flow['Netflow Bytes'] = current_flow['BytesIn'] + current_flow['BytesOut'] # Approximation
        current_flow['Response Time'] = flow_duration / current_flow['Number of Packets'] if current_flow['Number of Packets'] > 0 else 0.0 # Avg response time per packet
        current_flow['Data Transfer Rate'] = (current_flow['Netflow Bytes'] * 8) / flow_duration if flow_duration > 0 else 0.0 # bits/sec
        current_flow['Clusters'] = -1 # Dummy value for anomaly cluster
        current_flow['Geolocation'] = 'Localhost' # Dummy value
        current_flow['User-Agent'] = 'Simulated' # Dummy value
        current_flow['Family'] = 'Simulated' # Dummy value
        current_flow['Prediction'] = 'Attack Detected' # Dummy value for prediction
        current_flow['Event Description'] = 'Simulated Exfiltration/C2' # Dummy value
        current_flow['Logistics ID'] = 'SIM001' # Dummy value
        current_flow['Session ID'] = 'SIM_SESS_001' # Dummy value
        current_flow['Error Code'] = 0 # Dummy value

        flows_data.append(current_flow)

    if not flows_data:
        print("No simulated attack traffic found for the specified port in the PCAP.")

    return pd.DataFrame(flows_data)

# --- Main Execution ---
if __name__ == "__main__":
    print("Starting feature extraction for simulated attack data...")
    
    # Ensure the PCAP file exists before proceeding
    if not os.path.exists(PCAP_FILE_PATH):
        print(f"Error: PCAP file '{PCAP_FILE_PATH}' not found. Please ensure it's in the same directory as this script.")
        exit()

    simulated_df = extract_features_from_pcap(PCAP_FILE_PATH, SIMULATED_ATTACK_DEST_PORT)

    if not simulated_df.empty:
        # Define the exact column order expected by your Autoencoder script based on Kaggle dataset
        # This list MUST match the columns you expect from the Kaggle dataset after loading it
        # and identifying its features. This is critical for consistent preprocessing later.
        
        # Based on the Kaggle dataset snippet you provided previously, these are the likely columns.
        # YOU SHOULD VERIFY AND ADJUST THIS LIST BASED ON THE ACTUAL COLUMNS IN YOUR KAGGLE CSV.
        expected_kaggle_cols = [
            'Time', 'Protocol', 'Flag', 'Family', 'Clusters', 'SeddAddress', 'ExpAddress',
            'BTC', 'USD', 'Netflow Bytes', 'IP Address', 'Threat Level', 'Port', 'Prediction',
            'Payload Size', 'Number of Packets', 'Application Layer Data', 'User-Agent',
            'Geolocation', 'Logistics ID', 'Anomaly Score', 'Event Description',
            'Response Time', 'Session ID', 'Data Transfer Rate', 'Error Code'
        ]
        
        # Add SourcePort and DestPort if they are distinct features in Kaggle dataset and not covered by 'Port'
        # (Often 'Port' might refer to destination port, or a generic port, so having explicit Source/Dest is good)
        if 'SourcePort' not in expected_kaggle_cols:
            expected_kaggle_cols.append('SourcePort')
        if 'DestPort' not in expected_kaggle_cols:
            expected_kaggle_cols.append('DestPort')

        # Add the 'Label' column which we use for our custom simulated data
        expected_kaggle_cols.append('Label')

        # Create a new DataFrame with all expected columns and fill with NaNs/defaults
        final_simulated_df_reordered = pd.DataFrame(columns=expected_kaggle_cols)
        
        # Populate the new DataFrame with extracted data and dummy values
        for col in final_simulated_df_reordered.columns:
            if col in simulated_df.columns:
                final_simulated_df_reordered[col] = simulated_df[col]
            else:
                # Assign default values for columns not directly generated by simulation
                if col == 'Time':
                    final_simulated_df_reordered[col] = pd.to_datetime('now').strftime('%Y-%m-%d %H:%M:%S')
                elif col in ['BTC', 'USD', 'Clusters', 'Error Code', 'Anomaly Score']:
                    final_simulated_df_reordered[col] = 0.0 # Numerical default
                elif col in ['Netflow Bytes', 'Response Time', 'Data Transfer Rate']:
                    # These might be derived later or set to 0.0 if not directly from PCAP
                    final_simulated_df_reordered[col] = 0.0
                elif col in ['Threat Level', 'Prediction', 'Event Description', 'Logistics ID', 'Session ID', 'User-Agent', 'Family', 'Geolocation', 'IP Address', 'SeddAddress', 'ExpAddress', 'Application Layer Data', 'Flag', 'Port']:
                    # Categorical/String defaults
                    if col == 'Threat Level': final_simulated_df_reordered[col] = 'Zero-Day Attack' # This is our simulated attack
                    elif col == 'Prediction': final_simulated_df_reordered[col] = 'Attack Detected'
                    elif col == 'Event Description': final_simulated_df_reordered[col] = 'Simulated Exfiltration/C2'
                    elif col == 'Logistics ID': final_simulated_df_reordered[col] = 'SIM001'
                    elif col == 'Session ID': final_simulated_df_reordered[col] = 'SIM_SESS_001'
                    elif col == 'User-Agent': final_simulated_df_reordered[col] = 'Simulated'
                    elif col == 'Family': final_simulated_df_reordered[col] = 'Simulated'
                    elif col == 'Geolocation': final_simulated_df_reordered[col] = 'Localhost'
                    elif col == 'IP Address': final_simulated_df_reordered[col] = '127.0.0.1' # Source/Dest IP for loopback
                    elif col == 'SeddAddress': final_simulated_df_reordered[col] = '127.0.0.1'
                    elif col == 'ExpAddress': final_simulated_df_reordered[col] = '127.0.0.1'
                    elif col == 'Application Layer Data': final_simulated_df_reordered[col] = 'Simulated_Data'
                    elif col == 'Flag': final_simulated_df_reordered[col] = 'ACK' # Or 'SYN' based on initial packet
                    elif col == 'Port': final_simulated_df_reordered[col] = SIMULATED_ATTACK_DEST_PORT # Use the destination port
                    else: final_simulated_df_reordered[col] = 'N/A_Simulated' # Generic fallback

        # Ensure 'Label' column is always present and correct for simulated data
        final_simulated_df_reordered['Label'] = 'Simulated_ZeroDay'

        # Ensure correct dtypes for numerical columns
        numerical_cols_to_convert = [
            'BTC', 'USD', 'Netflow Bytes', 'Payload Size', 'Number of Packets',
            'FlowDuration', 'BytesIn', 'BytesOut', 'Response Time', 'Data Transfer Rate',
            'Clusters', 'Error Code', 'Anomaly Score', 'SourcePort', 'DestPort', 'Port'
        ]
        for col in numerical_cols_to_convert:
            if col in final_simulated_df_reordered.columns:
                final_simulated_df_reordered[col] = pd.to_numeric(final_simulated_df_reordered[col], errors='coerce').fillna(0)


        print("\n--- Final Extracted Features for Simulated Anomalies (First 5 Rows) ---")
        print(final_simulated_df_reordered.head())
        print(f"\nShape of final extracted simulated features: {final_simulated_df_reordered.shape}")

        # Save to CSV
        final_simulated_df_reordered.to_csv(OUTPUT_CSV_PATH, index=False)
        print(f"\nFeatures saved to: {OUTPUT_CSV_PATH}")
    else:
        print("No features extracted. Check PCAP file and attack simulation.")
