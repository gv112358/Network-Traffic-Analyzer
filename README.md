# Network-Traffic-Analyzer
The Network Traffic Analyzer is a **Python** tool designed for dissecting network traffic captured within PCAP files, captured with **wireshark** for example. It provides insights into IP communication, protocol distribution, and potential port scanning activities. The application aims to practice and enhance network troubleshooting and security vulnerability identification.

## Main Features
- Analyze network traffic from PCAP files
- Identify top IP address communications
- Calculate total bandwidth used
- Display protocol distribution
- Detect potential port scanning activities

## Usage
To analyze a PCAP file, run the following command:

python NetworkTrafficAnalyzer.py <path_to_pcap_file> <port_scan_threshold>

Replace `<path_to_pcap_file>` with the path to your PCAP file, and `<port_scan_threshold>` (defualt is set to 100) with the desired threshold for detecting port scanning activities.
