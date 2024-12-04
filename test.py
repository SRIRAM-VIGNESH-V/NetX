from scapy.all import *
import pyx

# Load the packet from the specified PCAP file
packets = rdpcap("C:\\Users\\vsrir\\Desktop\\PCAP-Analyzer-master (4)\\PCAP-Analyzer-master (3)\\PCAP-Analyzer-master\\PCAP-Analyzer-master\\test1.pcap")

# Function to create a graphical dump of packets
def pdf_dump(packets, layer_shift=1):
    # Create a PyX canvas
    c = pyx.canvas.canvas()

    # Draw each packet layer onto the canvas
    for packet in packets:
        # Check if the packet has Ethernet, IP, and UDP layers
        eth = packet.getlayer(Ether)
        ip = packet.getlayer(IP)
        udp = packet.getlayer(UDP)

        # Example of drawing Ethernet layer information
        if eth:
            c.text(0, layer_shift, f"Ethernet: dst={eth.dst}, src={eth.src}, type={eth.type}")
            layer_shift += 0.5  # Move down for next line

        # Draw IP layer information
        if ip:
            c.text(0, layer_shift, f"IP: version={ip.version}, ihl={ip.ihl}, src={ip.src}, dst={ip.dst}")
            layer_shift += 0.5  # Move down for next line

        # Draw UDP layer information
        if udp:
            c.text(0, layer_shift, f"UDP: sport={udp.sport}, dport={udp.dport}, len={udp.len}")
            layer_shift += 0.5  # Move down for next line

        layer_shift += 1  # Move down for the next packet

    # Save the canvas as PDF
    c.writePDFfile("packets_dump")

# Call the function with the loaded packets
pdf_dump(packets)
