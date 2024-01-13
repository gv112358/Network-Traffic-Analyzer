import sys
import logging
from scapy.all import *
import pandas as pd
from tabulate import tabulate
from tqdm import tqdm
import matplotlib.pyplot as plt

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

def read_pcap(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        logger.error(f"PCAP file not found: {pcap_file}")
        sys.exit(1)
    except Scapy_Exception as e:
        logger.error(f"Error reading PCAP file: {e}")
        sys.exit(1)
    return packets

def extract_packet_data(packets):
    packet_data = []

    for packet in tqdm(packets, desc="Processing packets", unit="packet"):
        if IP in packet:
            ip_layer = packet[IP]
            src_ip, dst_ip, protocol, size = ip_layer.src, ip_layer.dst, ip_layer.proto, len(packet)
            packet_data.append({"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol, "size": size})

    return pd.DataFrame(packet_data)

def protocol_name(number):
    protocol_dict = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    return protocol_dict.get(number, f"Unknown({number})")

def analyze_packet_data(df):
    total_bandwidth = df["size"].sum()
    protocol_counts = df["protocol"].value_counts(normalize=True) * 100
    protocol_counts.index = protocol_counts.index.map(protocol_name)

    ip_communication = df.groupby(["src_ip", "dst_ip"]).size().sort_values(ascending=False)
    ip_communication_percentage = ip_communication / ip_communication.sum() * 100
    ip_communication_table = pd.concat([ip_communication, ip_communication_percentage], axis=1).reset_index()

    protocol_frequency = df["protocol"].value_counts()
    protocol_frequency.index = protocol_frequency.index.map(protocol_name)

    protocol_counts_df = pd.concat([protocol_frequency, protocol_counts], axis=1).reset_index()
    protocol_counts_df.columns = ["Protocol", "Count", "Percentage"]

    ip_communication_protocols = df.groupby(["src_ip", "dst_ip", "protocol"]).size().reset_index()
    ip_communication_protocols.columns = ["Source IP", "Destination IP", "Protocol", "Count"]
    ip_communication_protocols["Protocol"] = ip_communication_protocols["Protocol"].apply(protocol_name)

    ip_communication_protocols["Percentage"] = ip_communication_protocols.groupby(["Source IP", "Destination IP"])["Count"].apply(lambda x: x / x.sum() * 100)

    return total_bandwidth, protocol_counts_df, ip_communication_table, protocol_frequency, ip_communication_protocols

def extract_packet_data_security(packets):
    packet_data = []

    for packet in tqdm(packets, desc="Processing packets for port scanning activity", unit="packet"):
        if IP in packet:
            ip_layer = packet[IP]
            src_ip, dst_ip, protocol, size = ip_layer.src, ip_layer.dst, ip_layer.proto, len(packet)

            if TCP in packet:
                dst_port = packet[TCP].dport
            else:
                dst_port = 0

            packet_data.append({"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol, "size": size, "dst_port": dst_port})

    return pd.DataFrame(packet_data)

def detect_port_scanning(df, port_scan_threshold):
    port_scan_df = df.groupby(['src_ip', 'dst_port']).size().reset_index(name='count')
    unique_ports_per_ip = port_scan_df.groupby('src_ip').size().reset_index(name='unique_ports')
    
    potential_port_scanners = unique_ports_per_ip[unique_ports_per_ip['unique_ports'] >= port_scan_threshold]
    ip_addresses = potential_port_scanners['src_ip'].unique()
    
    if len(ip_addresses) > 0:
        logger.warning(f"Potential port scanning detected from IP addresses: {', '.join(ip_addresses)}")

def print_results(total_bandwidth, protocol_counts_df, ip_communication_table, protocol_frequency, ip_communication_protocols):
    bandwidth_unit = "Mbps" if total_bandwidth < 10**9 else "Gbps"
    total_bandwidth /= 10**6 if bandwidth_unit == "Mbps" else 10**9

    logger.info(f"Total bandwidth used: {total_bandwidth:.2f} {bandwidth_unit}")
    logger.info("\nProtocol Distribution:\n")
    logger.info(tabulate(protocol_counts_df, headers=["Protocol", "Count", "Percentage"], tablefmt="grid"))
    logger.info("\nTop IP Address Communications:\n")
    logger.info(tabulate(ip_communication_table, headers=["Source IP", "Destination IP", "Count", "Percentage"], tablefmt="grid", floatfmt=".2f"))
    logger.info("\nShare of each protocol between IPs:\n")
    logger.info(tabulate(ip_communication_protocols, headers=["Source IP", "Destination IP", "Protocol", "Count", "Percentage"], tablefmt="grid", floatfmt=".2f"))

def plot_all_graphs(protocol_counts, ip_communication_protocols):
    plot_protocol_distribution(protocol_counts)
    plot_share_of_protocols_between_ips(ip_communication_protocols)

def main(pcap_file, port_scan_threshold):
    packets = read_pcap(pcap_file)
    df = extract_packet_data(packets)
    total_bandwidth, protocol_counts, ip_communication_table, protocol_frequency, ip_communication_protocols = analyze_packet_data(df)
    print_results(total_bandwidth, protocol_counts, ip_communication_table, protocol_frequency, ip_communication_protocols)

    df_security = extract_packet_data_security(packets)
    detect_port_scanning(df_security, port_scan_threshold)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        logger.error("Please provide the path to the PCAP file.")
        sys.exit(1)

    pcap_file = sys.argv[1]
    port_scan_threshold = int(sys.argv[2]) if len(sys.argv) >= 3 else 100

    main(pcap_file, port_scan_threshold)
