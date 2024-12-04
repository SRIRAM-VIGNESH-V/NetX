# ///////////////////////////////////////////
# /////////    Main Dev Only  ///////////////
# ///////////////////////////////////////////
import nmap
import subprocess
import threading
import nmap3
from datetime import datetime
import numpy as np
import plost
import requests
import streamlit as st
import os
import random
import base64
from streamlit_folium import folium_static
from folium.plugins import MarkerCluster
import folium
from scapy.all import sniff, wrpcap,rdpcap, IP, TCP, ICMP
import collections
import tempfile
import sys
import pandas as pd
from scapy.utils import corrupt_bytes
from streamlit_echarts import st_echarts
import geoip2.database
import pydeck as pdk
import folium
from streamlit_option_menu import option_menu
# from scapy.layers.inet import IP,TCP,UDP,
from utils.pcap_decode import PcapDecode
import time
import plotly.express as px
from scapy.all import sniff, wrpcap
import tempfile
from collections import defaultdict
from datetime import datetime

# from streamlit_pandas_profiling import st_profile_report
# from folium.plugins import HeatMap

PD = PcapDecode()  # Parser
PCAPS = None  # Packets
captured_packets = []

if 'uploaded_file' not in st.session_state:
    st.session_state.uploaded_file = None

if 'pcap_data' not in st.session_state:
    st.session_state.pcap_data = None

def get_all_pcap(PCAPS, PD):
    pcaps = collections.OrderedDict()
    for count, i in enumerate(PCAPS, 1):
        pcaps[count] = PD.ether_decode(i)
    return pcaps


def get_filter_pcap(PCAPS, PD, key, value):
    pcaps = collections.OrderedDict()
    count = 1
    for p in PCAPS:
        pcap = PD.ether_decode(p)
        if key == 'Procotol':
            if value == pcap.get('Procotol').upper():
                pcaps[count] = pcap
                count += 1
            else:
                pass
        elif key == 'Source':
            if value == pcap.get('Source').upper():
                pcaps[count] = pcap
                count += 1
        elif key == 'Destination':
            if value == pcap.get('Destination').upper():
                pcaps[count] = pcap
                count += 1
        else:
            pass
    return pcaps


def process_json_data(json_data):
    # Convert JSON data to a pandas DataFrame
    df = pd.DataFrame.from_dict(json_data, orient='index')
    return df
# Placeholder for captured packets
captured_packets = []

# Function to start sniffing
# Function to start sniffing and display packets in real time
# Function to start sniffing and display packets in real time
def start_sniffing(interface, packet_count):
    global captured_packets  # Declare as global

    # Clear previous captured packets
    captured_packets = []

    # Streamlit container to hold the real-time packet display
    st.write(f"Sniffing {packet_count} packets from {interface}...")
    packet_display = st.empty()

    # Real-time packet list
    def packet_callback(packet):
        captured_packets.append(packet)  # Append to global list

        # Create a list of packet summaries
        packet_summaries = [f"Packet {i+1}: {pkt.summary()}" for i, pkt in enumerate(captured_packets)]

        # Display all captured packets so far
        packet_display.text("\n".join(packet_summaries))

    # Start sniffing with real-time packet updates
    sniff(iface=interface, count=packet_count, prn=packet_callback)

    st.success(f"Captured {len(captured_packets)} packets.")



# Function to save the sniffed packets
def save_pcap():
    global captured_packets  # Declare as global

    if captured_packets:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as temp_file:
            wrpcap(temp_file.name, captured_packets)
            st.success(f"Packets saved to {temp_file.name}")
    else:
        st.warning("No packets to save!")


# To Calculate Live Time
def calculate_live_time(pcap_data):
    timestamps = [float(packet.time) for packet in pcap_data]  # Convert to float
    start_time = min(timestamps)
    end_time = max(timestamps)
    live_time_duration = end_time - start_time
    live_time_duration_str = str(pd.Timedelta(seconds=live_time_duration))
    return start_time, end_time, live_time_duration, live_time_duration_str


# protocol length statistics
def pcap_len_statistic(PCAPS):
    pcap_len_dict = {'0-300': 0, '301-600': 0, '601-900': 0, '901-1200': 0, '1201-1500': 0, '1500-more': 0}
    if PCAPS is None:
        return pcap_len_dict
    for pcap in PCAPS:
        pcap_len = len(corrupt_bytes(pcap))
        if 0 < pcap_len < 300:
            pcap_len_dict['0-300'] += 1
        elif 301 <= pcap_len < 600:
            pcap_len_dict['301-600'] += 1
        elif 601 <= pcap_len < 900:
            pcap_len_dict['601-900'] += 1
        elif 901 <= pcap_len < 1200:
            pcap_len_dict['901-1200'] += 1
        elif 1201 <= pcap_len <= 1500:
            pcap_len_dict['1201-1500'] += 1
        elif pcap_len > 1500:
            pcap_len_dict['1500-more'] += 1
        else:
            pass
    return pcap_len_dict


# protocol freq statistics
def common_proto_statistic(PCAPS):
    common_proto_dict = collections.OrderedDict()
    common_proto_dict['IP'] = 0
    common_proto_dict['IPv6'] = 0
    common_proto_dict['TCP'] = 0
    common_proto_dict['UDP'] = 0
    common_proto_dict['ARP'] = 0
    common_proto_dict['ICMP'] = 0
    common_proto_dict['DNS'] = 0
    common_proto_dict['HTTP'] = 0
    common_proto_dict['HTTPS'] = 0
    common_proto_dict['Others'] = 0

    if PCAPS is None:
        return common_proto_dict
    for pcap in PCAPS:
        if pcap.haslayer("IP"):
            common_proto_dict['IP'] += 1
        elif pcap.haslayer("IPv6"):
            common_proto_dict['IPv6'] += 1
        if pcap.haslayer("TCP"):
            common_proto_dict['TCP'] += 1
        elif pcap.haslayer("UDP"):
            common_proto_dict['UDP'] += 1
        if pcap.haslayer("ARP"):
            common_proto_dict['ARP'] += 1
        elif pcap.haslayer("ICMP"):
            common_proto_dict['ICMP'] += 1
        elif pcap.haslayer("DNS"):
            common_proto_dict['DNS'] += 1
        elif pcap.haslayer("TCP"):
            tcp = pcap.getlayer("TCP")
            dport = tcp.dport
            sport = tcp.sport
            if dport == 80 or sport == 80:
                common_proto_dict['HTTP'] += 1
            elif dport == 443 or sport == 443:
                common_proto_dict['HTTPS'] += 1
            else:
                common_proto_dict['Others'] += 1
        elif pcap.haslayer("UDP"):
            udp = pcap.getlayer("UDP")
            dport = udp.dport
            sport = udp.sport
            if dport == 5353 or sport == 5353:
                common_proto_dict['DNS'] += 1
            else:
                common_proto_dict['Others'] += 1
        elif pcap.haslayer("ICMPv6ND_NS"):
            common_proto_dict['ICMP'] += 1
        else:
            common_proto_dict['Others'] += 1
    return common_proto_dict


# maximum protocol statistics
def most_proto_statistic(PCAPS, PD):
    protos_list = list()
    for pcap in PCAPS:
        data = PD.ether_decode(pcap)
        protos_list.append(data['Procotol'])
    most_count_dict = collections.OrderedDict(collections.Counter(protos_list).most_common(10))
    return most_count_dict


# http/https Protocol Statistics
def http_statistic(PCAPS):
    http_dict = dict()
    for pcap in PCAPS:
        # Check if the packet has a TCP layer
        if pcap.haslayer("TCP"):
            tcp = pcap.getlayer("TCP")
            dport = tcp.dport
            sport = tcp.sport
            ip = None

            # Ensure the packet has an IP layer before accessing .src or .dst
            if pcap.haslayer("IP"):
                if dport == 80 or dport == 443:
                    ip = pcap.getlayer("IP").dst
                elif sport == 80 or sport == 443:
                    ip = pcap.getlayer("IP").src

            if ip:
                if ip in http_dict:
                    http_dict[ip] += 1
                else:
                    http_dict[ip] = 1
    return http_dict


def https_stats_main(PCAPS):
    http_dict = http_statistic(PCAPS)
    http_dict = sorted(http_dict.items(),
                       key=lambda d: d[1], reverse=False)
    http_key_list = list()
    http_value_list = list()
    for key, value in http_dict:
        http_key_list.append(key)
        http_value_list.append(value)
    return http_key_list, http_value_list


# DNS Protocol Statistics
def dns_statistic(PCAPS):
    dns_dict = dict()
    for pcap in PCAPS:
        if pcap.haslayer("DNSQR"):
            qname = pcap.getlayer("DNSQR").qname
            if qname in dns_dict:
                dns_dict[qname] += 1
            else:
                dns_dict[qname] = 1
    return dns_dict


def dns_stats_main(PCAPS):
    dns_dict = dns_statistic(PCAPS)
    dns_dict = sorted(dns_dict.items(), key=lambda d: d[1], reverse=False)
    dns_key_list = list()
    dns_value_list = list()
    for key, value in dns_dict:
        dns_key_list.append(key.decode('utf-8'))
        dns_value_list.append(value)
    return dns_key_list, dns_value_list


def time_flow(PCAPS):
    time_flow_dict = collections.OrderedDict()
    start = PCAPS[0].time
    time_flow_dict[time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(PCAPS[0].time)))] = len(
        corrupt_bytes(PCAPS[0]))
    for pcap in PCAPS:
        timediff = pcap.time - start
        time_flow_dict[float('%.3f' % timediff)] = len(corrupt_bytes(pcap))
    return time_flow_dict


def get_host_ip(PCAPS):
    ip_list = list()
    for pcap in PCAPS:
        if pcap.haslayer("IP"):
            ip_list.append(pcap.getlayer("IP").src)
            ip_list.append(pcap.getlayer("IP").dst)
    host_ip = collections.Counter(ip_list).most_common(1)[0][0]
    return host_ip


def data_flow(PCAPS, host_ip):
    data_flow_dict = {'IN': 0, 'OUT': 0}
    for pcap in PCAPS:
        if pcap.haslayer("IP"):
            if pcap.getlayer("IP").src == host_ip:
                data_flow_dict['OUT'] += 1
            elif pcap.getlayer("IP").dst == host_ip:
                data_flow_dict['IN'] += 1
            else:
                pass
    return data_flow_dict


def data_in_out_ip(PCAPS, host_ip):
    in_ip_packet_dict = dict()
    in_ip_len_dict = dict()
    out_ip_packet_dict = dict()
    out_ip_len_dict = dict()
    for pcap in PCAPS:
        if pcap.haslayer("IP"):
            dst = pcap.getlayer("IP").dst
            src = pcap.getlayer("IP").src
            pcap_len = len(corrupt_bytes(pcap))
            if dst == host_ip:
                if src in in_ip_packet_dict:
                    in_ip_packet_dict[src] += 1
                    in_ip_len_dict[src] += pcap_len
                else:
                    in_ip_packet_dict[src] = 1
                    in_ip_len_dict[src] = pcap_len
            elif src == host_ip:
                if dst in out_ip_packet_dict:
                    out_ip_packet_dict[dst] += 1
                    out_ip_len_dict[dst] += pcap_len
                else:
                    out_ip_packet_dict[dst] = 1
                    out_ip_len_dict[dst] = pcap_len
            else:
                pass

    in_packet_dict = in_ip_packet_dict
    in_len_dict = in_ip_len_dict
    out_packet_dict = out_ip_packet_dict
    out_len_dict = out_ip_len_dict
    in_packet_dict = sorted(in_packet_dict.items(), key=lambda d: d[1], reverse=False)
    in_len_dict = sorted(in_len_dict.items(), key=lambda d: d[1], reverse=False)
    out_packet_dict = sorted(out_packet_dict.items(), key=lambda d: d[1], reverse=False)
    out_len_dict = sorted(out_len_dict.items(), key=lambda d: d[1], reverse=False)
    in_keyp_list = list()
    in_packet_list = list()
    for key, value in in_packet_dict:
        in_keyp_list.append(key)
        in_packet_list.append(value)
    in_keyl_list = list()
    in_len_list = list()
    for key, value in in_len_dict:
        in_keyl_list.append(key)
        in_len_list.append(value)
    out_keyp_list = list()
    out_packet_list = list()
    for key, value in out_packet_dict:
        out_keyp_list.append(key)
        out_packet_list.append(value)
    out_keyl_list = list()
    out_len_list = list()
    for key, value in out_len_dict:
        out_keyl_list.append(key)
        out_len_list.append(value)
    in_ip_dict = {'in_keyp': in_keyp_list, 'in_packet': in_packet_list, 'in_keyl': in_keyl_list, 'in_len': in_len_list,
                  'out_keyp': out_keyp_list, 'out_packet': out_packet_list, 'out_keyl': out_keyl_list,
                  'out_len': out_len_list}
    return in_ip_dict


def proto_flow(PCAPS):
    proto_flow_dict = collections.OrderedDict()
    proto_flow_dict['IP'] = 0
    proto_flow_dict['IPv6'] = 0
    proto_flow_dict['TCP'] = 0
    proto_flow_dict['UDP'] = 0
    proto_flow_dict['ARP'] = 0
    proto_flow_dict['ICMP'] = 0
    proto_flow_dict['DNS'] = 0
    proto_flow_dict['HTTP'] = 0
    proto_flow_dict['HTTPS'] = 0
    proto_flow_dict['Others'] = 0
    for pcap in PCAPS:
        pcap_len = len(corrupt_bytes(pcap))
        if pcap.haslayer("IP"):
            proto_flow_dict['IP'] += pcap_len
        elif pcap.haslayer("IPv6"):
            proto_flow_dict['IPv6'] += pcap_len
        if pcap.haslayer("TCP"):
            proto_flow_dict['TCP'] += pcap_len
        elif pcap.haslayer("UDP"):
            proto_flow_dict['UDP'] += pcap_len
        if pcap.haslayer("ARP"):
            proto_flow_dict['ARP'] += pcap_len
        elif pcap.haslayer("ICMP"):
            proto_flow_dict['ICMP'] += pcap_len
        elif pcap.haslayer("DNS"):
            proto_flow_dict['DNS'] += pcap_len
        elif pcap.haslayer("TCP"):
            tcp = pcap.getlayer("TCP")
            dport = tcp.dport
            sport = tcp.sport
            if dport == 80 or sport == 80:
                proto_flow_dict['HTTP'] += pcap_len
            elif dport == 443 or sport == 443:
                proto_flow_dict['HTTPS'] += pcap_len
            else:
                proto_flow_dict['Others'] += pcap_len
        elif pcap.haslayer("UDP"):
            udp = pcap.getlayer("UDP")
            dport = udp.dport
            sport = udp.sport
            if dport == 5353 or sport == 5353:
                proto_flow_dict['DNS'] += pcap_len
            else:
                proto_flow_dict['Others'] += pcap_len
        elif pcap.haslayer("ICMPv6ND_NS"):
            proto_flow_dict['ICMP'] += pcap_len
        else:
            proto_flow_dict['Others'] += pcap_len
    return proto_flow_dict


def most_flow_statistic(PCAPS, PD):
    most_flow_dict = collections.defaultdict(int)
    for pcap in PCAPS:
        data = PD.ether_decode(pcap)
        most_flow_dict[data['Procotol']] += len(corrupt_bytes(pcap))
    return most_flow_dict


def getmyip():
    try:
        headers = {'User-Agent': 'Baiduspider+(+http://www.baidu.com/search/spider.htm'}
        ip = requests.get('http://icanhazip.com', headers=headers).text
        return ip.strip()
    except:
        return None


import requests

def get_geo(ip):
    try:
        # Try ipinfo.io first
        response = requests.get(f'http://ipinfo.io/{ip}/json')
        data = response.json()

        if 'bogon' in data:  # Bogon refers to private IPs
            return None
        
        city = data.get('city', 'Unknown City')
        country = data.get('country', 'Unknown Country')
        loc = data.get('loc', '0,0')
        latitude, longitude = loc.split(',')

        return [f"{city}, {country}", float(longitude), float(latitude)]
    
    except Exception as e:
        st.write(f"ipinfo.io failed for {ip}: {str(e)}")

        # Fallback to ipapi.co
        try:
            response = requests.get(f'https://ipapi.co/{ip}/json/')
            data = response.json()

            if 'error' in data:
                return None

            city = data.get('city', 'Unknown City')
            country = data.get('country_name', 'Unknown Country')
            latitude = data.get('latitude', 0)
            longitude = data.get('longitude', 0)

            return [f"{city}, {country}", longitude, latitude]
        except Exception as e2:
            st.write(f"ipapi.co failed for {ip}: {str(e2)}")
            return None


def get_ipmap(PCAPS, host_ip):
    geo_dict = dict()
    ip_value_dict = dict()
    ip_value_list = list()
    for pcap in PCAPS:
        if pcap.haslayer("IP"):
            src = pcap.getlayer("IP").src
            dst = pcap.getlayer("IP").dst
            pcap_len = len(corrupt_bytes(pcap))
            if src == host_ip:
                oip = dst
            else:
                oip = src
            if oip in ip_value_dict:
                ip_value_dict[oip] += pcap_len
            else:
                ip_value_dict[oip] = pcap_len
    for ip, value in ip_value_dict.items():
        geo_list = get_geo(ip)
        if geo_list:
            geo_dict[geo_list[0]] = [geo_list[1], geo_list[2]]
            Mvalue = str(float('%.2f' % (value / 1024.0))) + ':' + ip
            ip_value_list.append({geo_list[0]: Mvalue})
        else:
            pass
    return [geo_dict, ip_value_list]


# def ipmap(PCAPS):
#     myip = getmyip()
#     host_ip = get_host_ip(PCAPS)
#     ipdata = get_ipmap(PCAPS, host_ip)
#     geo_dict = ipdata[0]
#     ip_value_list = ipdata[1]
#     myip_geo = get_geo(myip)
#     ip_value_list = [(list(d.keys())[0], list(d.values())[0])
#                      for d in ip_value_list]
#     # st.write('ip_value_list', ip_value_list)
#     # st.write('geo_dict', geo_dict)
#     # return render_template('./dataanalyzer/ipmap.html', geo_data=geo_dict, ip_value=ip_value_list, mygeo=myip_geo)
#     return geo_dict, ip_value_list, myip_geo


def ipmap(PCAPS):
    # Assuming these functions are defined elsewhere in your code
    myip = getmyip()
    host_ip = get_host_ip(PCAPS)
    ipdata = get_ipmap(PCAPS, host_ip)
    geo_dict = ipdata[0]
    ip_value_list = ipdata[1]
    myip_geo = get_geo(myip)
    ip_value_list = [(list(d.keys())[0], list(d.values())[0]) for d in ip_value_list]

    # Create DataFrames from the dictionaries and lists
    geo_df = pd.DataFrame(list(geo_dict.items()), columns=['Location', 'Coordinates'])
    ip_df = pd.DataFrame(ip_value_list, columns=['Location', 'IP'])

    # Check if myip_geo is not None before creating the DataFrame
    # if myip_geo is not None:
    #     myip_geo_df = pd.DataFrame(myip_geo, columns=['MyLocation', 'MyCoordinates'])
    #
    #     # Merge the DataFrames based on the 'Location' column
    #     merged_df = geo_df.merge(ip_df, on='Location', how='left').merge(myip_geo_df, left_on='Location',
    #                                                                      right_on='MyLocation', how='left')
    # else:
    #     # If myip_geo is None, merge only geo_df and ip_df
    merged_df = geo_df.merge(ip_df, on='Location', how='left')

    # Split the 'IP' column into 'Numeric_Value' and 'IP_Address'
    merged_df[['Data_Traffic', 'IP_Address']] = merged_df['IP'].str.split(':', expand=True)

    # Drop the original 'IP' column
    merged_df = merged_df.drop('IP', axis=1)
    # st.write("merged_df>>", merged_df)

    # Display the merged DataFrame
    with st.expander("Geo Data Associated with PCAPs "):
        st.write(merged_df)

    return merged_df


def page_file_upload():
    # # File upload
    # uploaded_file = st.file_uploader("Choose a CSV file", type=["csv","pcap", "cap"])
    #
    # # Store the uploaded file in session state
    # st.session_state.uploaded_file = uploaded_file
    #
    # if uploaded_file is not None:
    #     st.success("File uploaded successfully!")
    if "uploaded_file" not in st.session_state or st.session_state.uploaded_file is None:
        # File upload
        uploaded_file = st.file_uploader("Choose a CSV file", type=["csv", "pcap", "cap"])

        # Store the uploaded file in session state
        st.session_state.uploaded_file = uploaded_file

        if uploaded_file is not None:
            st.success("File uploaded successfully!")
    else:
        # Display existing file info
        st.warning("An uploaded file already exists in the session state.")

        # Option to delete existing file and upload a new one
        delete_existing = st.button("Delete Existing File and Upload New File")
        if delete_existing:
            st.session_state.uploaded_file = None
            st.success("Existing file deleted. Please upload a new file.")
            page_file_upload()


def page_display_info():
    # Display uploaded file information
    if st.session_state.get("uploaded_file") is not None:
        # st.subheader("Uploaded File Information:")
        # st.write(f"File Name: {st.session_state.uploaded_file.name}")
        # st.write(f"File Type: {st.session_state.uploaded_file.type}")
        # st.write(f"File Size: {st.session_state.uploaded_file.size} bytes")
        file_details = {"File Name": st.session_state.uploaded_file.name,
                        "File Type": st.session_state.uploaded_file.type,
                        "File Size": st.session_state.uploaded_file.size}
        st.write(file_details)


def Intro():
    # Introduction
    st.markdown(
        """
        Packet Capture (PCAP) files are a common way to store network traffic data. They contain information about
        the packets exchanged between devices on a network. This data is crucial for network analysis and cybersecurity.
        
        ## Support
        
        [![Buy Me A Coffee](https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png)](https://www.buymeacoffee.com/pareshmakwha)
   
 
        ## What is a PCAP file?

        A PCAP file (Packet Capture) is a binary file that stores network traffic data. It records the details of
        each packet, such as source and destination addresses, protocol, and payload. PCAP files are widely used by
        network administrators, security professionals, and researchers to analyze network behavior.

        ## Importance in Cybersecurity

        PCAP files play a vital role in cybersecurity for several reasons:

        - **Network Traffic Analysis:** Analyzing PCAP files helps detect anomalies, identify patterns, and
          understand network behavior.

        - **Incident Response:** In the event of a security incident, PCAP files can be instrumental in
          reconstructing the sequence of events and identifying the root cause.

        - **Forensic Investigations:** PCAP files provide a detailed record of network activity, aiding in
          forensic investigations to determine the source and impact of security incidents.
          
          
        ## Download Sample File 
        Sample 1 [here](https://github.com/paresh2806/PCAP-Analyzer/blob/master/ftp3.pcap)  \n
    
        Sample 2 [here](https://github.com/paresh2806/PCAP-Analyzer/blob/master/ftp-data.pcap)

        ## Getting Started

        To get started with PCAP analysis, you can use tools like Wireshark or tshark. Additionally, Python
        libraries such as Scapy and PyShark provide programmatic access to PCAP data.

        ```python
        # Example using Scapy
        from scapy.all import rdpcap

        # Load PCAP file
        pcap_file = "example.pcap"
        packets = rdpcap(pcap_file)

        # Analyze packets
        for packet in packets:
            # Perform analysis here
            pass
        ```

        Explore the capabilities of PCAP analysis tools to enhance your understanding of network traffic and
        strengthen cybersecurity practices.

        """
    )




def RawDataView():
    uploaded_file = st.session_state.uploaded_file
    if uploaded_file is not None:
        # Check if the uploaded file is a PCAP file
        if uploaded_file.type == "application/octet-stream":
            # Process the uploaded PCAP file
            pcap_data = rdpcap(os.path.join(uploaded_file.name))
            st.session_state.pcap_data = pcap_data
            # Example: Get all PCAPs
            all_data = get_all_pcap(pcap_data, PD)
            dataframe_data = process_json_data(all_data)
            start_time, end_time, live_time_duration, live_time_duration_str = calculate_live_time(pcap_data)

            # Add live time information to the data frame
            # dataframe_data['Start Time'] = start_time
            # dataframe_data['End Time'] = end_time
            dataframe_data['Live Time Duration'] = live_time_duration_str
            all_columns = list(dataframe_data.columns)
            st.sidebar.header("P1ease Filter Here:")
            # st.sidebar.divider()
            # Filter reset button
            if st.sidebar.button("Reset Filters"):
                st.experimental_rerun()
            # Multiselect for filtering by protocol
            selected_protocols = st.sidebar.multiselect(
                "Select Protocol:",
                options=dataframe_data["Procotol"].unique(), default=None
            )
            # st.sidebar.divider()

            # Sidebar slider for filtering by length
            filter_value_len = st.sidebar.slider(
                "Filter by Numeric Column",
                min_value=min(dataframe_data["len"]),
                max_value=max(dataframe_data["len"]),
                value=(min(dataframe_data["len"]), max(dataframe_data["len"]))
            )
            # st.sidebar.divider()

            # Sidebar text input for filtering by Source
            filter_source = st.sidebar.text_input("Filter by Source:", "")
            # st.sidebar.divider()

            # Sidebar text input for filtering by Destination
            filter_destination = st.sidebar.text_input("Filter by Destination:", "")
            # st.sidebar.divider()

            # Apply filters based on user selection
            if (
                    selected_protocols is None or not selected_protocols) and not filter_value_len and not filter_source and not filter_destination:
                st.write("All PCAPs:")
                Data_to_display_df = dataframe_data.copy()
                st.dataframe(Data_to_display_df, use_container_width=True)

            else:
                # Apply filters based on user input

                # Filter by protocol
                if selected_protocols is not None and selected_protocols:
                    Data_to_display_df = dataframe_data[dataframe_data["Procotol"].isin(selected_protocols)]
                else:
                    Data_to_display_df = dataframe_data

                # Filter by length
                Data_to_display_df = Data_to_display_df[
                    (Data_to_display_df["len"] >= filter_value_len[0]) & (
                            Data_to_display_df["len"] <= filter_value_len[1])
                    ]

                # Filter by Source
                if filter_source:
                    Data_to_display_df = Data_to_display_df[
                        Data_to_display_df["Source"].str.contains(filter_source, case=False, na=False)]

                # Filter by Destination
                if filter_destination:
                    Data_to_display_df = Data_to_display_df[
                        Data_to_display_df["Destination"].str.contains(filter_destination, case=False, na=False)]

                # Display the filtered dataframe
                st.write("Filtered PCAPs:")

                column_check = st.checkbox("Filter with arguments")
                if column_check:
                    # Multiselect for filtering by columns
                    selected_columns = st.multiselect(
                        "Select Columns to Display: ",
                        options=all_columns, default=all_columns
                    )
                    Data_to_display_df = Data_to_display_df[selected_columns]
                # selected_columns = [col for col in Data_to_display_df.columns if st.checkbox(col, value=True )]
                st.checkbox("Use container width", value=True, key="use_container_width")
                st.dataframe(Data_to_display_df, use_container_width=st.session_state.use_container_width)

                st.subheader("Statistics of Selected Data")
                # Time Analysis
                Data_to_display_df['time'] = pd.to_datetime(Data_to_display_df['time'])
                st.subheader("Time Range:")
                st.write("Earliest timestamp:", Data_to_display_df['time'].min())
                st.write("Latest timestamp:", Data_to_display_df['time'].max())
                st.write("Duration:", Data_to_display_df['time'].max() - Data_to_display_df['time'].min())
                ####################################
                col1, col2 = st.columns(2)

                # Column 1: Packet Length Statistics
                with col1:
                    st.subheader("Packet Length Statistics:")
                    st.table(Data_to_display_df['len'].describe())

                    # Source Counts
                    source_counts = Data_to_display_df['Source'].value_counts()
                    st.subheader("Source Counts:")
                    st.table(source_counts)

                # Column 2: Protocol Distribution and Destination Counts
                with col2:
                    # Protocol Distribution
                    protocol_counts = Data_to_display_df['Procotol'].value_counts(normalize=True)
                    st.subheader("Protocol Distribution:")
                    st.table(protocol_counts)

                    # Destination Counts
                    destination_counts = Data_to_display_df['Destination'].value_counts()
                    st.subheader("Destination Counts:")
                    st.table(destination_counts)



                #####################################






        else:
            st.warning("Please upload a valid PCAP file.")



def DataPacketLengthStatistics(data):

    data1 = {'pcap_len': list(data.keys()), 'count': list(data.values())}
    df1 = pd.DataFrame(data1)
    
    # Convert to Bar Chart
    fig = px.bar(df1, x='pcap_len', y='count', color='pcap_len', title="Data Packet Length Statistics")
    fig.update_layout(title_x=0.5)  # Centering the title
    
    # Render the bar chart in Streamlit
    st.plotly_chart(fig)



def CommonProtocolStatistics(data):
    st.write("Common Protocol Statistics")
    data2 = {'protocol_type': list(data.keys()),
             'number_of_packets': list(data.values())}
    df2 = pd.DataFrame(data2)
    # plost.bar_chart(data=df2, bar='protocol_type', value='number_of_packets')

    options = {
        "xAxis": {
            "type": "category",
            "data": df2.protocol_type.tolist(),
        },
        "yAxis": {"type": "value"},
        "series": [{"data": df2.number_of_packets.tolist(), "type": "bar"}],
    }
    st_echarts(options=options, height="500px")

def CommonProtocolStatistics_ploty(data):
    # st.write('Common Protocol Statistics')
    data2 = {'protocol_type': list(data.keys()),
             'number_of_packets': list(data.values())}
    df2 = pd.DataFrame(data2)
    fig = px.bar(df2, x='protocol_type', y='number_of_packets',color="protocol_type",title="Common Protocol Statistics")
    fig.update_layout(title_x=0.5)

    st.plotly_chart(fig)




def MostFrequentProtocolStatistics(data):
    data3 = {'protocol_type': list(data.keys()), 'freq': list(data.values())}
    df3 = pd.DataFrame(data3)
    
    # Convert to Bar Chart
    fig = px.bar(df3, x='protocol_type', y='freq', color='protocol_type', title="Most Frequent Protocol Statistics")
    fig.update_layout(title_x=0.5)  # Centering the title
    
    # Render the bar chart in Streamlit
    st.plotly_chart(fig)



def HTTP_HTTPSAccessStatistics(key,value):
    # st.write("HTTP/HTTPS Access Statistics")
    data4 = {'HTTP/HTTPS key': list(key),
             'HTTP/HTTPS value': list(value)}
    df4 = pd.DataFrame(data4)
    fig = px.bar(df4, x='HTTP/HTTPS key', y='HTTP/HTTPS value',color="HTTP/HTTPS key",title="HTTP/HTTPS Access Statistics")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)



def DNSAccessStatistics(key, value):
    # st.write("DNS Access Statistics")
    data5 = {'dns_key': list(key),
             'dns_value': list(value)}
    df5 = pd.DataFrame(data5)
    fig = px.bar(df5, x='dns_key', y='dns_value', color="dns_key",title="DNS Access Statistics")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)


def TimeFlowChart(data):
    data6 = {'Relative_Time': list(data.keys()), 'Packet_Bytes': list(data.values())}
    df6 = pd.DataFrame(data6)
    fig = px.line(df6, x='Relative_Time', y="Packet_Bytes",title="Time Flow Chart")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)
def DataInOutStatistics(data):
    #st.write("Data In/Out Statistics")
    data7 = {'In/Out': list(data.keys()), 'freq': list(data.values())}
    df7 = pd.DataFrame(data7)

    options = {
        "title": {"text": "Data In/Out Statistics", "subtext": "", "left": "center"},
        "tooltip": {"trigger": "item"},
        "legend": {"orient": "vertical", "left": "left", },
        "series": [
            {
                "name": "Data ",
                "type": "pie",
                "radius": "50%",
                "data": [
                    {"value": count, "name": pcap_len}
                    for pcap_len, count in zip(df7['In/Out'], df7['freq'])
                ],
                "emphasis": {
                    "itemStyle": {
                        "shadowBlur": 10,
                        "shadowOffsetX": 0,
                        "shadowColor": "rgba(0, 0, 0, 0.5)",
                    }
                },
            }
        ],
        "backgroundColor": "rgba(0, 0, 0, 0)",  # Transparent background
    }

    # st.write("Data Packet Length Statistics")
    st.write(df7)
    st_echarts(options=options, height="600px", renderer='svg')

def TotalProtocolPacketFlow(data):
    # st.write("Total Protocol Packet Flow bar chart")
    data8 = {'Protocol': list(data.keys()), 'freq': list(data.values())}
    df8 = pd.DataFrame(data8)

    options = {
        "title": {"text": "Total Protocol PacketFlow", "subtext": "", "left": "center"},
        "tooltip": {"trigger": "item"},
        "legend": {"orient": "vertical", "left": "left", },
        "series": [
            {
                "name": "Protocols",
                "type": "pie",
                "radius": "50%",
                "data": [
                    {"value": count, "name": pcap_len}
                    for pcap_len, count in zip(df8['Protocol'], df8['freq'])
                ],
                "emphasis": {
                    "itemStyle": {
                        "shadowBlur": 10,
                        "shadowOffsetX": 0,
                        "shadowColor": "rgba(0, 0, 0, 0.5)",
                    }
                },
            }
        ],
        "backgroundColor": "rgba(0, 0, 0, 0)",  # Transparent background
    }

    # st.write("Data Packet Length Statistics")
    st_echarts(options=options, height="600px", renderer='svg')

def TotalProtocolPacketFlowbarchart(data):
    # Ensure data is non-empty
    if not data:
        st.warning("No protocol packet flow data available.")
        return
    
    # Prepare the data for plotting
    data9 = {'Protocol': list(data.keys()), 'freq': list(data.values())}
    df9 = pd.DataFrame(data9)
    
    # Check if the dataframe is non-empty
    if df9.empty:
        st.warning("The Protocol Packet Flow data is empty!")
    else:
        # Convert to Bar Chart
        fig = px.bar(df9, x='Protocol', y='freq', color="Protocol", title="Total Protocol Packet Flow")
        fig.update_layout(title_x=0.5)  # Centering the title
        
        # Render the bar chart in Streamlit
        st.plotly_chart(fig)


def InboundIPTrafficDataPacketCountChart(data):
    # st.write("Inbound IP Traffic Data Packet Count Chart")
    data10 = {'Inbound IP': list(data['in_keyp']), 'Number of Data Packets': list(data['in_packet'])}
    df10 = pd.DataFrame(data10)
    fig = px.bar(df10, x='Inbound IP', y='Number of Data Packets', color="Inbound IP",title="Inbound IP Traffic Data Packet Count Chart")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)

def InboundIPTotalTrafficChart(data):
    # st.write("Inbound IP Total Traffic Chart")
    data11 = {'Inbound IP': list(data['in_keyl']), 'Total Data Packet Traffic': list(data['in_len'])}
    df11 = pd.DataFrame(data11)
    fig = px.bar(df11, x='Inbound IP', y='Total Data Packet Traffic', color="Inbound IP",title="Inbound IP Total Traffic Chart")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)

def OutboundIPTrafficDataPacketCountChart(data):  # ip_flow['out_keyp'], ip_flow['out_packet']
    # st.write("Outbound IP Traffic Data Packet Count Chart")
    data12 = {'Outbound IP': list(data['out_keyp']), 'Number of Data Packets': list(data['out_packet'])}
    df12 = pd.DataFrame(data12)
    fig = px.bar(df12, x='Outbound IP', y='Number of Data Packets', color="Outbound IP",title="Outbound IP Traffic Data Packet Count Chart")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)
def OutboundIPTotalTrafficChart(data):  # ip_flow['out_keyl'],ip_flow['out_len']
    st.write("Outbound IP Total Traffic Chart")
    data13 = {'Outbound IP': list(data['out_keyl']), 'Total Data Packet Traffic': list(data['out_len'])}
    df13 = pd.DataFrame(data13)
    fig = px.bar(df13, x='Outbound IP', y='Total Data Packet Traffic', color="Outbound IP",title="Outbound IP Total Traffic Chart")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)


def DrawFoliumMap(data):
    m = folium.Map(location=[data.iloc[0]['Coordinates'][1], data.iloc[0]['Coordinates'][0]],
                   zoom_start=5)

    # Create MarkerCluster layer
    marker_cluster = MarkerCluster().add_to(m)

    # Add markers for each location in the DataFrame
    for index, row in data.iterrows():
        popup_text = f"IP Address: {row['IP_Address']}<br>Data Traffic: {row['Data_Traffic']}"

        folium.Marker(
            location=row['Coordinates'][::-1],
            popup=folium.Popup(popup_text, max_width=300),
            icon=folium.Icon(color='blue'),  # Customize marker color
        ).add_to(marker_cluster)

    # Display the map in Streamlit
    folium_static(m,width=1820 , height=600)


def main(): 
    
    
    # Initialize nmap3
    nmap = nmap3.Nmap()

    # Function to format and display version detection results inside a table
    def format_version_output(raw_data):
        st.markdown("### Nmap Version Detection Results")
        task_results = raw_data.get('task_results', [])
        if task_results:
            task_data = []
            for task in task_results:
                task_name = task.get('task', 'N/A')
                extra_info = task.get('extrainfo', 'N/A')
                task_data.append([task_name, extra_info])

            st.table(task_data)

        runtime = raw_data.get('runtime', {})
        if runtime:
            runtime_data = []
            for key, value in runtime.items():
                runtime_data.append([key, value])

            st.table(runtime_data)

        ip_data = []
        for ip, data in raw_data.items():
            if ip in ["runtime", "stats", "task_results"]:
                continue

            if isinstance(data, dict):
                hostname = data.get('hostname', [])
                if hostname:
                    ip_data.append([f"IP: {ip}", f"Hostname: {hostname[0].get('name', 'N/A')}"])
                    ip_data.append(["Service Version Detection", ""])
                    ports = data.get("ports", [])
                    if ports:
                        for port in ports:
                            service = port.get("service", {})
                            service_name = service.get("name", "N/A")
                            product = service.get("product", "N/A")
                            version = service.get("version", "N/A")
                            protocol = port.get("protocol", "N/A")
                            ip_data.append([f"Port: {port['portid']} ({service_name})", 
                                            f"Product: {product}, Version: {version}, Protocol: {protocol}"])

            st.table(ip_data)

    # Function to format and display OS detection results inside a table
    def format_os_output(raw_data):
        os_data = []
        for ip, data in raw_data.items():
            if ip in ["runtime", "stats"]:
                continue

            if isinstance(data, dict):
                os_detection = data.get("osmatch", [])
                open_ports = data.get("ports", [])
                hostnames = data.get("hostname", [])
                scan_summary = data.get("runtime", {})

                if os_detection or open_ports or hostnames:
                    os_data.append([f"IP Address: {ip}"])
                    if os_detection:
                        os_data.append(["OS Detection", ""])
                        for os in os_detection:
                            os_data.append([f"OS Name: {os.get('name', 'N/A')}", f"Accuracy: {os.get('accuracy', 'N/A')}%"])
                            os_data.append([f"CPE: {os.get('cpe', 'N/A')}", ""])
                    if open_ports:
                        os_data.append(["Open Ports", ""])
                        for port in open_ports:
                            os_data.append([f"Port: {port['portid']} ({port['service']['name']})", f"State: {port['state']}"])

                    if hostnames:
                        os_data.append(["Hostnames", ""])
                        for hostname in hostnames:
                            os_data.append([f"Name: {hostname['name']}", f"Type: {hostname['type']}"])

                    os_data.append(["Scan Summary", ""])
                    scan_time = scan_summary.get("timestr", "N/A")
                    total_hosts = 1 if "task_results" in data else 0
                    elapsed_time = scan_summary.get("elapsed", "N/A")
                    exit_status = "Success" if scan_summary.get("exit", "failure") == "success" else "Failure"
                    os_data.append([f"Scan Time: {scan_time}", f"Total Hosts: {total_hosts}"])
                    os_data.append([f"Elapsed Time: {elapsed_time} seconds", f"Exit Status: {exit_status}"])

        st.table(os_data)

    # Function to run a top ports scan
    def run_top_ports_scan(target):
        results = nmap.scan_top_ports(target)
        ports_data = []
        for ip, data in results.items():
            if ip in ['runtime', 'stats']:
                continue
            if isinstance(data, dict):
                ports_data.append([f"IP: {ip}"])
                ports_data.append([f"State: {data.get('state', {}).get('state', 'N/A')}", ""])
                ports_data.append(["Ports", ""])
                for port in data.get('ports', []):
                    port_info = f"Port: {port['portid']} ({port['service']['name']})"
                    port_state = f"State: {port['state']}"
                    ports_data.append([port_info, port_state])
                ports_data.append(["-" * 40, ""])

            
    # Set the page configuration

    st.set_page_config(page_title="NetX", layout="wide")

    # Sidebar for the option menu
    with st.sidebar:
        selected = option_menu(
            menu_title=None,
            options=["Upload File", "Raw Data & Filtering", "Analysis", "Geoplots", 
                     "IP Analysis","Live Sniffing","Advanced Active Reconnaissance", 
                    "Network Vulnerability scan", "Network Mapping","Real Time Topology Mapping"],
            icons=["file-upload", "file-earmark-text", "bar-chart-line", "globe", "wifi", 
                   "shield-lock", "search", "search", "graph-up"],
            menu_icon="cast",
            default_index=0,
            orientation="vertical"
        )

    # Main content area
    st.title("NetX - Networking Tool")
    st.write("NetX is an Advanced multipurpose tool developed for Network engineers and cybersecurity analysts for analysing live network data and PCAP files")
       
    if selected == "Real Time Topology Mapping":
        import networkx as nx
        import plotly.graph_objects as go
        from scapy.all import sniff, IP
        import threading
        import time

        # Global variable to store communication pairs
        communication_pairs = {}

        # Function to process each packet
        def process_packet(pkt):
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                
                # Create a unique communication pair
                pair = tuple(sorted([src_ip, dst_ip]))
                
                # Update the number of communications between the pair
                if pair in communication_pairs:
                    communication_pairs[pair] += 1
                else:
                    communication_pairs[pair] = 1

        # Function to visualize the network graph using Plotly
        def visualize_network(communication_pairs):
            G = nx.Graph()
            
            # Add edges to the graph based on communication pairs
            for pair, weight in communication_pairs.items():
                G.add_edge(pair[0], pair[1], weight=weight)

            # Create a Plotly figure
            fig = go.Figure()

            pos = nx.spring_layout(G)  # Positions for the nodes
            edge_x = []
            edge_y = []
            
            for edge in G.edges(data=True):
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                edge_x.append(x0)
                edge_x.append(x1)
                edge_x.append(None)  # Separate lines for different edges
                edge_y.append(y0)
                edge_y.append(y1)
                edge_y.append(None)  # Separate lines for different edges

            # Add edges to the figure
            fig.add_trace(go.Scatter(x=edge_x, y=edge_y, mode='lines', line=dict(width=0.5, color='gray'), hoverinfo='none'))

            # Add nodes to the figure
            node_x = []
            node_y = []
            node_text = []
            
            for node in G.nodes():
                x, y = pos[node]
                node_x.append(x)
                node_y.append(y)
                node_text.append(f'IP: {node}<br>Connections: {", ".join(list(G.neighbors(node)))}')

            # Adding nodes with hoverinfo
            fig.add_trace(go.Scatter(
                x=node_x, 
                y=node_y,
                mode='markers+text',
                marker=dict(size=10, color='lightblue', line=dict(width=2, color='DarkSlateGrey')),
                text=node_text,
                textposition="top center",
                hoverinfo='text'
            ))

            # Customize layout for better fitting
            fig.update_layout(
                title='Network Communication Graph',
                title_font_size=20,
                showlegend=False,
                hovermode='closest',
                margin=dict(l=10, r=10, t=50, b=10),  # Adjust margins
                width=1200,  # Set a width for the graph
                height=700,  # Set a height for the graph
                autosize=True  # Allow automatic sizing
            )

            return fig

        # Function to start sniffing in a separate thread
        def start_sniffing():
            sniff(prn=process_packet, store=0)  # Start sniffing packets

        st.title("Real-Time Network Communication Graph")
        
        # Start sniffing in a separate thread
        thread = threading.Thread(target=start_sniffing)
        thread.daemon = True  # Allow thread to exit when main program exits
        thread.start()

        # Placeholder for the Plotly graph
        placeholder = st.empty()

        # Continuously update the graph in Streamlit
        while True:
            if communication_pairs:
                fig = visualize_network(communication_pairs)
                placeholder.plotly_chart(fig, use_container_width=True)  # Use full container width
            
            # Sleep for a short duration to avoid overwhelming the UI
            time.sleep(2.5)

    if selected == "Network Mapping":
        import networkx as nx
        import plotly.graph_objects as go
        from scapy.all import rdpcap  # Ensure rdpcap is imported correctly
        from scapy.all import rdpcap
        # Function to extract network data from the PCAP file using Scapy
        def extract_network_data(pcap_file):
            packets = rdpcap(pcap_file)
            communication_pairs = {}

            for pkt in packets:
                if pkt.haslayer('IP'):
                    src_ip = pkt['IP'].src
                    dst_ip = pkt['IP'].dst
                    
                    # Create a unique communication pair
                    pair = tuple(sorted([src_ip, dst_ip]))
                    
                    # Update the number of communications between the pair
                    if pair in communication_pairs:
                        communication_pairs[pair] += 1
                    else:
                        communication_pairs[pair] = 1

            return communication_pairs

        # Function to visualize the network graph using Plotly
        def visualize_network(communication_pairs):
            G = nx.Graph()
            
            # Add edges to the graph based on communication pairs
            for pair, weight in communication_pairs.items():
                G.add_edge(pair[0], pair[1], weight=weight)

            # Create a Plotly figure
            fig = go.Figure()

            pos = nx.spring_layout(G)  # Positions for the nodes
            edge_x = []
            edge_y = []
            
            for edge in G.edges(data=True):
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                edge_x.append(x0)
                edge_x.append(x1)
                edge_x.append(None)  # Separate lines for different edges
                edge_y.append(y0)
                edge_y.append(y1)
                edge_y.append(None)  # Separate lines for different edges

            # Add edges to the figure
            fig.add_trace(go.Scatter(x=edge_x, y=edge_y, mode='lines', line=dict(width=0.5, color='gray'), hoverinfo='none'))

            # Add nodes to the figure
            node_x = []
            node_y = []
            node_text = []
            
            for node in G.nodes():
                x, y = pos[node]
                node_x.append(x)
                node_y.append(y)
                node_text.append(f'IP: {node}<br>Connections: {", ".join(list(G.neighbors(node)))}')

            # Adding nodes with hoverinfo
            fig.add_trace(go.Scatter(
                x=node_x, 
                y=node_y,
                mode='markers+text',
                marker=dict(size=10, color='lightblue', line=dict(width=2, color='DarkSlateGrey')),
                text=node_text,
                textposition="top center",
                hoverinfo='text'
            ))

            # Customize layout
            fig.update_layout(title='Network Communication Graph',
                            title_font_size=20,
                            showlegend=False,
                            hovermode='closest',
                            margin=dict(l=0, r=0, t=40, b=0))

            return fig

        st.title("Network Communication Graph")
        
        # File upload
        uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap"])
        
        if uploaded_file is not None:
            # Save the uploaded file temporarily
            pcap_file = f"temp_{uploaded_file.name}"
            with open(pcap_file, "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            communication_pairs = extract_network_data(pcap_file)
            fig = visualize_network(communication_pairs)
            
            # Display the Plotly figure in Streamlit
            st.plotly_chart(fig)

    if selected == "Advanced Active Reconnaissance":
            # Title of the app
            st.title("NetX - Scanning Options")

            # Description of the application
            st.markdown("""
            This application allows you to select different TCP scanning methods, host discovery techniques, UDP scanning methods, advanced stealth techniques, OS detection options, version detection, and Zenmap default profiles to maximize the chances of gathering network information.
            """)

            # Input for target
            target_ip = st.text_input("Enter Target IP Address:", "")

            # Define scanning options (removed specific options)
            scan_options = {
                "TCP ACK Scan": "-sA",
                "TCP ACK Ping": "-PA",
                "TCP SYN Scan": "-sS",
                "TCP SYN Ping": "-PS",
                "TCP Connect Scan": "-sT",
                "TCP Window Scan": "-sW",
                "TCP Maimon Scan": "-sM",
                "TCP Null Scan": "-sN",
                "TCP FIN Scan": "-sF",
                "TCP XMAS Scan": "-sX"
            }

            # Define host discovery options
            host_discovery_options = {
                "ARP Scan": "-PR",
                "IP Protocol Ping": "-PO",
                "IP Protocol Scan": "-sO",
                "ICMP Echo Scan": "-PE",
                "IPv6 Scan": "-6"
            }

            # Define UDP scanning options
            udp_scan_options = {
                "UDP Scan": "-sU",
                "UDP Ping": "-PU"
            }

            # Define stealth & firewall evasion options (only -sS and --badsum)
            stealth_options = {
                "Stealth": "-sS",
                "Bad Checksum": "--badsum",
                "Timing - T0": "-T0",
                "Timing - T1": "-T1",
                "Timing - T2": "-T2",
                "Timing - T3": "-T3",
                "Timing - T4": "-T4"
            }

            # Define OS and version detection options with descriptions
            os_detection_options = {
                "Operating System Detection": "-O OR -A (with other scans)",
                "Limit OS Detection": "--osscan-limit",
                "Guess OS Detection": "--osscan-guess; --fuzzy",
                "Maximum OS Detection Tries": "--max-os-tries value",
                "Aggressive Scan": "-A"
            }

            # Define version detection options
            version_detection_options = {
                "Enable Light Mode": "--version-light",
                "Enable All": "--version-all",
                "Service Version Trace": "--version-trace"
            }

            # Define Zenmap default profiles
            zenmap_profiles = {
                "Intense Scan": "-T4 -A -v",
                "Intense Scan plus UDP": "-T4 -A -sS -sU",
                "Intense Scan, all TCP ports": "-T4 -A -p 1-65535",
                "Intense Scan, no ping": "-T4 -A -Pn",
                "Ping Scan": "-sn",
                "Quick Scan": "-T4 -F",
                "Quick Scan plus": "-T4 -sV -O --version-light",
                "Quick Traceroute": "-sn --traceroute",
                "Regular Scan": "",
                "Slow Comprehensive Scan": "-sS -sU -PE -PS80,443 -PA3389 -PP -PU40125 -PY --source-port 53 --script 'default or (discovery and safe)'"
            }

            # Multi-select for TCP scan types
            selected_scans = st.multiselect("Select TCP Scan Types:", options=list(scan_options.keys()))

            # Multi-select for host discovery methods
            selected_discovery = st.multiselect("Select Host Discovery Methods:", options=list(host_discovery_options.keys()))

            # Multi-select for UDP scan types
            selected_udp_scans = st.multiselect("Select UDP Scan Types:", options=list(udp_scan_options.keys()))

            # Multi-select for stealth & firewall evasion techniques
            selected_stealth = st.multiselect("Select Stealth & Firewall Evasion Techniques:", options=list(stealth_options.keys()))

            # Multi-select for OS detection options
            selected_os_detection = st.multiselect("Select OS Detection Options:", options=list(os_detection_options.keys()))

            # Multi-select for version detection options
            selected_version_detection = st.multiselect("Select Version Detection Options:", options=list(version_detection_options.keys()))

            # Multi-select for Zenmap default profiles
            selected_profiles = st.multiselect("Select Zenmap Default Profiles:", options=list(zenmap_profiles.keys()))

            # Execute the scan button
            if st.button("Run Scans"):
                if not target_ip:
                    st.error("Please enter a target IP address.")
                else:
                    results = []
                    # Execute selected TCP scans
                    if selected_scans:
                        for scan in selected_scans:
                            command = f"nmap {scan_options[scan]} {target_ip}"
                            st.write(f"Running command: `{command}`")
                            try:
                                # Execute the Nmap command
                                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                                results.append(f"**Results for {scan}:**\n```\n{output.decode()}\n```")
                            except subprocess.CalledProcessError as e:
                                results.append(f"**Error for {scan}:**\n```\n{e.output.decode()}\n```")
                    
                    # Execute selected host discovery methods
                    if selected_discovery:
                        for discovery in selected_discovery:
                            command = f"nmap {host_discovery_options[discovery]} {target_ip}"
                            st.write(f"Running command: `{command}`")
                            try:
                                # Execute the Nmap command
                                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                                results.append(f"**Results for {discovery}:**\n```\n{output.decode()}\n```")
                            except subprocess.CalledProcessError as e:
                                results.append(f"**Error for {discovery}:**\n```\n{e.output.decode()}\n```")

                    # Execute selected UDP scans
                    if selected_udp_scans:
                        for udp_scan in selected_udp_scans:
                            command = f"nmap {udp_scan_options[udp_scan]} {target_ip}"
                            st.write(f"Running command: `{command}`")
                            try:
                                # Execute the Nmap command
                                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                                results.append(f"**Results for {udp_scan}:**\n```\n{output.decode()}\n```")
                            except subprocess.CalledProcessError as e:
                                results.append(f"**Error for {udp_scan}:**\n```\n{e.output.decode()}\n```")

                    # Execute selected stealth & firewall evasion techniques
                    if selected_stealth:
                        for stealth in selected_stealth:
                            command = f"nmap {stealth_options[stealth]} {target_ip}"
                            st.write(f"Running command: `{command}`")
                            try:
                                # Execute the Nmap command
                                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                                results.append(f"**Results for {stealth}:**\n```\n{output.decode()}\n```")
                            except subprocess.CalledProcessError as e:
                                results.append(f"**Error for {stealth}:**\n```\n{e.output.decode()}\n```")
                    
                    # Execute selected OS detection options
                    if selected_os_detection:
                        for os_detection in selected_os_detection:
                            command = f"nmap {os_detection_options[os_detection]} {target_ip}"
                            st.write(f"Running command: `{command}`")
                            try:
                                # Execute the Nmap command
                                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                                results.append(f"**Results for {os_detection}:**\n```\n{output.decode()}\n```")
                            except subprocess.CalledProcessError as e:
                                results.append(f"**Error for {os_detection}:**\n```\n{e.output.decode()}\n```")
                    
                    # Execute selected version detection options
                    if selected_version_detection:
                        for version_detection in selected_version_detection:
                            command = f"nmap {version_detection_options[version_detection]} {target_ip}"
                            st.write(f"Running command: `{command}`")
                            try:
                                # Execute the Nmap command
                                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                                results.append(f"**Results for {version_detection}:**\n```\n{output.decode()}\n```")
                            except subprocess.CalledProcessError as e:
                                results.append(f"**Error for {version_detection}:**\n```\n{e.output.decode()}\n```")

                    # Execute selected Zenmap default profiles
                    if selected_profiles:
                        for profile in selected_profiles:
                            command = f"nmap {zenmap_profiles[profile]} {target_ip}"
                            st.write(f"Running command: `{command}`")
                            try:
                                # Execute the Nmap command
                                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                                results.append(f"**Results for {profile}:**\n```\n{output.decode()}\n```")
                            except subprocess.CalledProcessError as e:
                                results.append(f"**Error for {profile}:**\n```\n{e.output.decode()}\n```")
                    
                    # Display results
                    for result in results:
                        st.markdown(result)

            # Footer
            st.markdown("### Note:")
            st.markdown("Ensure you have proper authorization to scan the network and devices.")


    
    # Recon tab logic
    if selected == "Network Endpoint scan":
        st.header("Endpoint Penetration Testing")

        # IP address input
        ip_address = st.text_input("Enter the IP address or Hostname to scan:")

        # Buttons for different scan types with catchy icons
        col1, col2 = st.columns(2)

        with col1:
            if st.button("🔍 Common Scan"):
                if ip_address:
                    st.write(f"Running scan on: {ip_address}")

                    # Run top ports scan, version detection, and OS detection
                    run_top_ports_scan(ip_address)
                    version_result = nmap.nmap_version_detection(ip_address)
                    os_results = nmap.nmap_os_detection(ip_address)

                    # Format and st.write the results
                    format_version_output(version_result)
                    format_os_output(os_results)
                else:
                    st.write("Please enter a valid IP address.")
    
    if selected == "Network Vulnerability scan":
        st.header("🔍 **Network Vulnerability Testing**")
        
        # IP address input
        ip_address = st.text_input("🌐 Enter the IP Address or Hostname to Scan:")

        # Buttons for different scan types with catchy icons
        col1, col2 = st.columns(2)

        with col1:
            if st.button("🛡️ Start Vulnerability Scan"):
                st.markdown("<h2 style='color: orange;'>Starting Vulnerability Scan...</h2>", unsafe_allow_html=True)

                import nmap
                st.write(f"🔎 **Scanning IP Address:** {ip_address}")
                nm = nmap.PortScanner()

                try:
                    # Perform the scan with vulners script for vulnerabilities
                    nm.scan(ip_address, arguments='-sV --script vulners --script-args mincvss+5.0')

                    # Show general scan information
                    st.markdown("## 📋 General Information about the Scan:")
                    st.write(f"**Host:** {ip_address}")

                    # Accessing Nmap scan time from scanstats() safely
                    scan_time = nm.scanstats().get('timestr', 'N/A')
                    st.write(f"**Scan Time:** {scan_time}")

                    # Accessing Nmap version safely
                    nmap_version = nm.nmap_version()
                    st.write(f"**Nmap Version:** {nmap_version}")

                    # Accessing scan summary safely (handling case if it doesn't exist)
                    scan_summary = nm.scanstats().get('summary', 'No summary available')
                    st.write(f"**Scan Summary:** {scan_summary}")
                    st.write("🛠️" + "-" * 50)

                    # Detailed Information about each open port
                    st.markdown("## 🔓 Open Ports and Services:")
                    for host in nm.all_hosts():
                        st.write(f"**Host:** {host} ({nm[host].hostname()}) - **Status:** {nm[host].state()}")

                        for protocol in nm[host].all_protocols():
                            st.write(f"**Protocol:** {protocol}")
                            lport = nm[host][protocol].keys()
                            for port in lport:
                                st.write(f"**Port:** {port}, **Service:** {nm[host][protocol][port]['name']}")
                                st.write(f"**Product:** {nm[host][protocol][port].get('product', 'N/A')}")
                                st.write(f"**Version:** {nm[host][protocol][port].get('version', 'N/A')}")
                                st.write(f"**State:** {nm[host][protocol][port]['state']}")
                                st.write("🛠️" + "-" * 50)

                    # Vulnerabilities Information
                    st.markdown("## ⚠️ Vulnerabilities Information:")
                    for host in nm.all_hosts():
                        st.write(f"**Scanning Host:** {host}")
                        if 'script' in nm[host]:
                            if 'vulners' in nm[host]['script']:
                                vulns = nm[host]['script']['vulners']
                                for vuln in vulns:
                                    st.write(f"**Vulnerability:** {vuln}")
                                    st.write(f"**CVSS Score:** {vulns[vuln].get('cvss', 'N/A')}")
                                    st.write(f"**Description:** {vulns[vuln].get('description', 'No description available')}")
                                    st.write(f"**References:** {vulns[vuln].get('references', 'N/A')}")

                                    # Adding common mitigation suggestions
                                    if "CVE" in vuln:
                                        cve_id = vuln.split(":")[1]
                                        st.write(f"**Suggested Mitigation for {cve_id}:**")
                                        st.write(f"  - Check for available patches or updates related to {cve_id}")
                                        st.write(f"  - Review the system configuration to minimize exposure")
                                        st.write(f"  - Apply the latest security updates from the vendor")
                                        st.write(f"  - Refer to official CVE details: https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")

                                    st.write("🛠️" + "-" * 50)
                            else:
                                st.write("🚫 **No vulnerabilities detected on this host.**")
                        else:
                            st.write("🚫 **No script data available.**")

                    # Common Security Suggestions for Open Ports
                    st.write("\n" + "🛡️" + "-" * 50 + "\n")
                    st.write("## 🛡️ Security Measures:")
                    for host in nm.all_hosts():
                        if 'hostnames' in nm[host]:
                            st.write(f"\n**Host:** {host} ({nm[host].hostname()}):")
                            if 80 in nm[host]['tcp']:
                                st.write(f"**Port 80 (HTTP)** is open.")
                                st.write(f"- **Suggestion:** Ensure the HTTP service (nginx) is up-to-date.")
                                st.write(f"- **Common CVEs:** CVE-2021-22965, CVE-2019-11043.")
                                st.write(f"- **Mitigation:** Update nginx, review configurations.")
                                st.write(f"- **Disable unused HTTP methods (e.g., TRACE, OPTIONS).**")
                                st.write(f"- **Implement security headers:** X-Content-Type-Options, X-Frame-Options.")
                            if 443 in nm[host]['tcp']:
                                st.write(f"**Port 443 (HTTPS)** is open.")
                                st.write(f"- **Suggestion:** Ensure strong SSL/TLS settings.")
                                st.write(f"- **Common CVEs:** CVE-2021-22965, CVE-2019-11043.")
                                st.write(f"- **Mitigation:** Use SSL Labs' test, configure HSTS, disable weak ciphers.")
                                st.write(f"- **Enable Perfect Forward Secrecy (PFS) in the SSL configuration.**")
                                st.write(f"- **Ensure the use of strong SSL/TLS protocols (TLS 1.2 and TLS 1.3).**")
                            if 22 in nm[host]['tcp']:
                                st.write(f"**Port 22 (SSH)** is open.")
                                st.write(f"- **Suggestion:** Disable root login via SSH.")
                                st.write(f"- **Mitigation:** Use SSH keys for authentication, disable password-based logins.")
                                st.write(f"- **Ensure the latest OpenSSH version is installed.**")

                    # OS and Software Version Specific Suggestions
                    st.write("\n" + "🛡️" + "-" * 50 + "\n")
                    st.markdown("## 🖥️ OS & Version Specific Suggestions:")
                    for host in nm.all_hosts():
                        st.write(f"\n**Host:** {host}")
                        if 'osmatch' in nm[host]:
                            for os_info in nm[host]['osmatch']:
                                st.write(f"**OS:** {os_info.get('osclass', 'Unknown')} **Version:** {os_info.get('osfamily', 'Unknown')}")
                                st.write(f"**Suggested Mitigation for {os_info.get('osfamily', 'Unknown')} OS:**")
                                st.write(f"  - Regularly update the OS with security patches.")
                                st.write(f"  - Disable unnecessary services to reduce the attack surface.")
                                st.write(f"  - Implement security configurations specific to the OS (e.g., AppArmor, SELinux).")

                                # Example specific to Ubuntu or Linux OS
                                if "Ubuntu" in os_info.get('osclass', ''):
                                    st.write(f"  - Ensure that all packages are up-to-date using `sudo apt update && sudo apt upgrade`.")
                                if "Windows" in os_info.get('osclass', ''):
                                    st.write(f"  - Enable Windows Defender and ensure the latest antivirus definitions are in place.")
                                    st.write(f"  - Review the Windows Security Center for best practices.")
                                    st.write(f"  - Enforce group policy to restrict access to critical files.")
                                    st.write(f"  - Enable BitLocker encryption for Windows devices.")
                                    st.write(f"  - Use Windows Sandbox for risky software installations.")
                                if "Red Hat" in os_info.get('osclass', ''):
                                    st.write(f"  - Use `yum` or `dnf` for automated patching and upgrading of packages.")
                                    st.write(f"  - Disable unnecessary services like FTP, Samba, Telnet, etc.")

                    # Large Scale Recommendations for Specific Software
                    st.write("\n" + "🛡️" + "-" * 50 + "\n")
                    st.write("## 📈 Large Scale Recommendations for Specific Software:")
                    for host in nm.all_hosts():
                        if 80 in nm[host]['tcp']:
                            st.write(f"**HTTP Service detected (Port 80)** - **Product:** {nm[host]['tcp'][80].get('product', 'N/A')}")
                            if 'nginx' in nm[host]['tcp'][80].get('product', ''):
                                st.write(f"  - **Update nginx to the latest stable release.**")
                                st.write(f"  - **CVE-2019-11043:** Ensure proper handling of HTTP/2 requests.")
                                st.write(f"  - **CVE-2020-5551:** Ensure proper access control for web services.")
                                st.write(f"  - **Disable HTTP TRACE method.**")
                                st.write(f"  - **Configure `nginx.conf` to secure the web application.**")
                                st.write(f"  - **Set `http_only` flags for session cookies.**")

                    # Firewall Configuration and Best Practices
                    st.write("\n" + "🛡️" + "-" * 50 + "\n")
                    st.write("## 🔒 Firewall Configuration and Best Practices:")
                    for host in nm.all_hosts():
                        if 'tcp' in nm[host]:
                            st.write(f"\n**Host {host} Firewall Configuration Suggestions:**")
                            st.write(f"  - Ensure that only necessary ports are open (e.g., 80, 443, 22).")
                            st.write(f"  - Block all inbound traffic by default and only allow specific IPs.")
                            st.write(f"  - Use Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) like Snort.")
                            st.write(f"  - Enable logging to track suspicious activity.")

                    st.markdown("## 🎉 Scan Completed!")

                except Exception as e:
                    st.write(f"🚫 **Error during scan:** {str(e)}")


                
    def start_sniffing(interface, packet_count):
        from scapy.all import sniff
        global captured_packets  # Declare as global

        # Clear previous captured packets
        captured_packets = []

        # Streamlit container to hold the real-time packet display
        st.write(f"Sniffing {packet_count} packets from {interface}...")
        packet_display = st.empty()

        # Real-time packet list
        def packet_callback(packet):
            captured_packets.append(packet)  # Append to global list

            # Create a list of packet summaries
            packet_summaries = [f"Packet {i+1}: {pkt.summary()}" for i, pkt in enumerate(captured_packets)]

            # Display all captured packets so far
            packet_display.text("\n".join(packet_summaries))

        # Start sniffing with real-time packet updates
        sniff(iface=interface, count=packet_count, prn=packet_callback)

        st.success(f"Captured {len(captured_packets)} packets.")



    if selected == "Live Sniffing":
        st.title("Live Packet Sniffing")

        # User input for network interface and packet count
        interface = st.text_input("Enter the network interface (e.g., wlan0 for Wi-Fi):")
        packet_count = st.number_input("Number of packets to capture:", min_value=1, max_value=10000, value=10)

        # Button to start sniffing
        if st.button("Start Sniffing"):
            if interface:
                start_sniffing(interface, packet_count)
            else:
                st.warning("Please enter a valid network interface.")

    if selected == "IP Analysis":
        st.title("IP Analysis from PCAP and CSV")

        # Allow both PCAP and CSV uploads
        uploaded_file = st.file_uploader("📁 Upload PCAP or CSV File", type=["pcap", "pcapng", "csv"])

        if uploaded_file is not None:
            st.success("File uploaded! Starting analysis...")

            from scapy.all import rdpcap
            import pandas as pd  # To read CSV files
            import requests
            import time

            # AbuseIPDB API setup
            API_KEY = '1f93d5d081f6d5aa1a5fe7f36b8218738e88d1f8b3d357b1efab75f32ae721a5c9938dc63b6b1465'
            ABUSE_IPDB_URL = "https://api.abuseipdb.com/api/v2/check"

            # Function to check IP against AbuseIPDB
            def check_ip_abuse(ip):
                headers = {
                    'Accept': 'application/json',
                    'Key': API_KEY
                }
                params = {
                    'ipAddress': ip,
                    'maxAgeInDays': 90
                }
                response = requests.get(ABUSE_IPDB_URL, headers=headers, params=params)
                if response.status_code == 200:
                    return response.json().get('data', {})
                else:
                    return None

            # Function to parse PCAP file
            def parse_pcap(file):
                packets = rdpcap(file)
                return packets

            # Function to parse CSV file and return list of IPs
            def parse_csv(file):
                df = pd.read_csv(file)  # Load the CSV into a DataFrame
                # Extract the source IPs from the 'Source' column
                if 'Source' in df.columns:
                    return df['Source'].tolist()  # Return the list of source IPs
                else:
                    st.error("CSV must contain a column named 'Source'.")
                    return []

            # Function to analyze packets and yield results
            def analyze_ips(ips):
                seen_ips = set()  # To keep track of unique IPs
                for ip in ips:
                    if ip not in seen_ips:  # Check if IP has already been analyzed
                        seen_ips.add(ip)  # Add to seen IPs
                        src_abuse = check_ip_abuse(ip)
                        yield {
                            'src_ip': ip,
                            'src_abuse': src_abuse,
                        }

            # Determine file type and process accordingly
            if uploaded_file.name.endswith('.pcap') or uploaded_file.name.endswith('.pcapng'):
                packets = parse_pcap(uploaded_file)
                st.write("####  Analyzing PCAP File IPs...")
                ips = [pkt['IP'].src for pkt in packets if pkt.haslayer('IP')]  # Extract source IPs
            elif uploaded_file.name.endswith('.csv'):
                ips = parse_csv(uploaded_file)
                st.write("#### Analyzing CSV File IPs...")
            else:
                st.error("Unsupported file format.")
                ips = []

            # Placeholder for live updates (empty at first)
            st.write("#### IP Analysis Results (Live):")

            # Loop through each IP's analysis and display live
            for packet_result in analyze_ips(ips):
                st.write("─────────────────────────────────────────────")
                st.subheader(f"🌐 IP Address : `{packet_result['src_ip']}`")

                # Check and display abuse data for source IP
                if packet_result['src_abuse']:
                    abuse_score = packet_result['src_abuse'].get('abuseConfidenceScore', 0)
                    
                    # Highlight malicious IPs in a catchy way
                    if abuse_score > 50:
                        st.markdown(
                                        f"""
                                        <div style='
                                            color: white; 
                                            font-weight: bold; 
                                            background: linear-gradient(135deg, #ff4b5c, #ff6b6b); 
                                            padding: 15px; 
                                            border-radius: 10px; 
                                            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); 
                                            font-size: 16px;
                                        '>
                                            ⚠️ <span style='font-size:18px;'>Malicious IP Found!</span> <br>
                                            Abuse Score: {abuse_score}%
                                        </div>
                                        """, unsafe_allow_html=True
                                    )

                    else:
                        st.success("✅ No abuse reports for this IP.")

                    # Display detailed JSON data
                    st.write("**AData for Source IP:**")
                    st.json(packet_result['src_abuse'])  # Display complete JSON response
                else:
                    st.info("No abuse data available for Source IP.")

                # Add an optional delay to simulate live processing (adjust or remove as needed)
                time.sleep(1)

            save_path = st.text_input("Enter the path to save analyzed results", value="analysis_results.txt")
            
            # Save the results
            if st.button("Save Analysis"):
                with open(save_path, "w") as file:
                    for packet_result in analyze_ips(ips):
                        file.write(f"Src IP: {packet_result['src_ip']}, Src Abuse: {packet_result['src_abuse']}\n")
                st.success(f"Saved analysis to {save_path}")



        # File uploader
    if selected == "Upload File":
        page_file_upload()
        page_display_info()

    # Raw Data Visualizer and Filtering
    if selected == "Raw Data & Filtering":
        st.subheader("Raw Data Can be Visualized Here")
        RawDataView()
  

    if selected == "Analysis":
        st.subheader("Dashboard")
        if "pcap_data" not in st.session_state:
            st.session_state.pcap_data = []
        # get analysis of data
        else:
            data_of_pcap = st.session_state.pcap_data
            if data_of_pcap is None:
                art = """NO DATA FOUND"""
                st.code(art)
            else:
                data_len_stats = pcap_len_statistic(data_of_pcap)  # protocol len statistics
                data_protocol_stats = common_proto_statistic(data_of_pcap)  # count the occurrences of common network protocols
                data_count_dict = most_proto_statistic(data_of_pcap,
                                                       PD)  # counts the occurrences of each protocol and returns most common 10 protocols.
                http_key, http_value = https_stats_main(data_of_pcap)  # https Protocol Statistics
                dns_key, dns_value = dns_stats_main(data_of_pcap)  # DNS Protocol Statistics
                # Data Protocol analysis end

                # Traffic analysis start
                time_flow_dict = time_flow(data_of_pcap)
                host_ip = get_host_ip(data_of_pcap)
                data_flow_dict = data_flow(data_of_pcap, host_ip)
                data_ip_dict = data_in_out_ip(data_of_pcap, host_ip)
                proto_flow_dict = proto_flow(data_of_pcap)
                most_flow_dict = most_flow_statistic(data_of_pcap, PD)
                most_flow_dict = sorted(most_flow_dict.items(), key=lambda d: d[1], reverse=True)
                if len(most_flow_dict) > 10:
                    most_flow_dict = most_flow_dict[0:10]
                most_flow_key = list()
                for key, value in most_flow_dict:
                    most_flow_key.append(key)
                # Traffic analysis end

                # ///////////////////////////////////////////
                # ////     Data of Protocol Analysis    /////
                # ///////////////////////////////////////////
                # DataPacketLengthStatistics(data_len_stats)  #Piechart
                # # CommonProtocolStatistics(data_protocol_stats)
                # CommonProtocolStatistics_ploty(data_protocol_stats) #Barchart
                # MostFrequentProtocolStatistics(data_count_dict) #Piechart
                # HTTP_HTTPSAccessStatistics(http_key,http_value)  #Bar CHart axis -90
                # DNSAccessStatistics(dns_key,dns_value) #BarChart axis -90
                # col1, col2 = st.columns([2, 3])
                #
                # # Column 1: DataPacketLengthStatistics - Piechart
                # with col1:
                #     st.subheader("Data Packet Length Statistics")
                #     DataPacketLengthStatistics(data_len_stats)
                #
                #     # MostFrequentProtocolStatistics - Piechart
                #     st.subheader("Most Frequent Protocol Statistics")
                #     MostFrequentProtocolStatistics(data_count_dict)
                #
                # # Column 2: CommonProtocolStatistics_plotly - Barchart
                # with col2:
                #     st.subheader("Common Protocol Statistics")
                #     CommonProtocolStatistics_ploty(data_protocol_stats)
                #
                #     # HTTP_HTTPSAccessStatistics - BarChart axis -90
                #     st.subheader("HTTP/HTTPS Access Statistics")
                #     HTTP_HTTPSAccessStatistics(http_key, http_value)
                #
                #     # DNSAccessStatistics - BarChart axis -90
                #     st.subheader("DNS Access Statistics")
                #     DNSAccessStatistics(dns_key, dns_value)

                st.title(" Data of Protocol Analysis  ")
                # Create a 2x2 column layout
                col1, col2 = st.columns(2)

                # Column 1: Uneven row heights
                with col1:
                    # Row 1
                    with st.expander("Data Packet Length Statistics"):
                        DataPacketLengthStatistics(data_len_stats)

                    # Row 2 (smaller height)
                    with st.expander("Most Frequent Protocol Statistics"):
                        MostFrequentProtocolStatistics(data_count_dict)


                # Column 2: Uneven row heights
                with col2:
                    # Row 1
                    with st.expander("Common Protocol Statistics"):
                        CommonProtocolStatistics_ploty(data_protocol_stats)

                    # Row 2 (larger height)
                    with st.expander("HTTP/HTTPS Access Statistics Details"):
                        HTTP_HTTPSAccessStatistics(http_key, http_value)

                    # Row 3 (smaller height)
                    with st.expander("DNS Access Statistics"):
                        DNSAccessStatistics(dns_key, dns_value)

                # ///////////////////////////////////////////
                # ////     Data of Traffic Analysis     /////
                # ///////////////////////////////////////////
                st.title("Data of Traffic Analysis")
                col3, col4 = st.columns(2)
                with col3:
                    # Row 1
                    with st.expander("Time Flow Chart"):
                        TimeFlowChart(time_flow_dict)

                    # Row 2 (smaller height)
                  
                with col4:


                    # Row 2 (larger height)
                    with st.expander("Total Protocol Packet Flow bar chart"):
                        TotalProtocolPacketFlowbarchart(proto_flow_dict)




                # Inbound /Outbound


                st.title("Inbound /Outbound ")
                col5, col6 = st.columns(2)
                with col5:
                    # Row 1
                    with st.expander("Inbound IP Traffic Data Packet Count Chart"):
                        InboundIPTrafficDataPacketCountChart(data_ip_dict)  #Bar CHart axis -90 #ip_flow['in_keyp'], ip_flow['in_packet']

                    # Row 2 (smaller height)
                    with st.expander("Inbound IP Total Traffic Chart"):
                        InboundIPTotalTrafficChart(data_ip_dict)  #Bar CHart axis -90 #ip_flow['in_keyl'],ip_flow['in_len']

                # Column 2: Uneven row heights
                with col6:
                    # Row 1
                    with st.expander("Outbound IP Traffic Data Packet Count Chart"):
                        OutboundIPTrafficDataPacketCountChart(data_ip_dict)  #Bar CHart axis -90 # ip_flow['out_keyp'], ip_flow['out_packet']

                    # Row 2 (larger height)
                    with st.expander("Outbound IP Total Traffic Chart"):
                        OutboundIPTotalTrafficChart(data_ip_dict)   #Bar CHart axis -90 # ip_flow['out_keyl'],ip_flow['out_len']




    if selected == "Geoplots":
        st.subheader("Geoplot")
        # ///////////////////////////////////////////
        # ////              Data of Geoplot     /////
        # ///////////////////////////////////////////
        if "pcap_data" not in st.session_state:
            st.session_state.pcap_data = []
            st.warning("No valid data for Geoplot.")
        else:
            data_of_pcap = st.session_state.pcap_data
            if data_of_pcap:
                ipmap_result = ipmap(data_of_pcap)
                # Display the map in Streamlit
                DrawFoliumMap(ipmap_result)
            else:
                st.warning("No valid data for Geoplot.")









if __name__ == "__main__":
    main()
