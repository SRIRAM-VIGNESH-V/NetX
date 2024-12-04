# NetX: Advanced Network Analysis and Security Toolkit

NetX is a powerful, multi-purpose tool designed for network engineers and cybersecurity analysts. It enables detailed analysis of live network data and PCAP files, with a focus on usability and precision. NetX provides real-time monitoring, advanced scanning, and intuitive visualizations to help users identify vulnerabilities and secure their networks.

## Key Features

- **Real-time Network Monitoring**: Analyze live traffic from various interfaces with dynamic filtering options.
- **Packet Capture (PCAP) Analysis**: Perform in-depth analysis on previously captured traffic.
- **Advanced Packet Filtering**: Over 120 combinations of packet filtering to refine your insights.
- **Port Scanning & OS Detection**: Utilize Nmap for reconnaissance and OS fingerprinting.
- **Network Vulnerability Mapping**: Identify potential weaknesses in your network.
- **Live Host Identification**: Pinpoint active devices on the network.
- **Network Topology Visualization**: Generate and map live network topologies.
- **Firewall Integrity Validation**: Test and validate firewall configurations.
- **IP Analysis & Geo-Location Mapping**: Analyze IP addresses with GeoIP integration.
- **User-Friendly Interface**: Streamlit-based web UI for seamless interaction.

## Tech Stack

- **Python**: Core programming language for flexibility and power.
- **Streamlit**: For creating the intuitive web-based UI.
- **Scapy**: For packet sniffing and analysis.
- **Nmap**: For advanced scanning and network mapping.
- **Pandas**: For data manipulation and analysis.
- **GeoIP**: For geolocation of IP addresses.
- **Cisco Threat Grid**: For enhanced threat intelligence.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/SRIRAM-VIGNESH-V/NetX.git
    cd NetX
    ```

2. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Run the application:
    ```bash
    streamlit run app.py
    ```

## Usage

1. Open the Streamlit app in your browser.
2. Select your desired functionality from the sidebar menu.
3. Follow the intuitive interface to configure scans, analyze traffic, or visualize network data.

## Functionality Highlights

### 1. **Live Traffic Monitoring**
   - Select a network interface.
   - Apply dynamic filters to refine your analysis.
   - View real-time packet details.

### 2. **PCAP Analysis**
   - Upload a PCAP file for detailed insights.
   - Extract protocol statistics, visualize traffic patterns, and identify anomalies.

### 3. **Advanced Scanning**
   - Conduct port scans, OS detection, and vulnerability assessments using Nmap.
   - Leverage custom scan profiles based on Zenmap templates.

### 4. **Firewall Integrity Validation**
   - Verify the configuration and effectiveness of firewalls.

### 5. **Network Topology Mapping**
   - Visualize network devices and their interconnections.
   - Perform live updates as the topology changes.

### 6. **GeoIP Analysis**
   - Map IP addresses to their geographic locations for enhanced insights.

## Contributions

Contributions are welcome! If you have suggestions, feature requests, or bug reports, please create an issue or submit a pull request.

1. Fork the repository.
2. Create a new branch for your feature:
    ```bash
    git checkout -b feature-name
    ```
3. Commit your changes:
    ```bash
    git commit -m "Add feature description"
    ```
4. Push to your branch:
    ```bash
    git push origin feature-name
    ```
5. Submit a pull request.

## License

This project is licensed under the MIT LICENSE.

---

**Developed by:**
- **SRIRAM VIGNESH V**
Happy Networking! 🚀
